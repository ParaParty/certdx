// Package aliesa updates an ESA site certificate with renewed material.
package aliesa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	esa "github.com/alibabacloud-go/esa-20240910/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

const (
	defaultRegionID     = "cn-hangzhou"
	pageSize            = int64(100)
	confirmTimeout      = 2 * time.Minute
	confirmEvery        = 3 * time.Second
	transientRetryCount = 3
)

var transientBackoff = 2 * time.Second

// siteLocks holds one lock per ESA site. Quota recovery and retention work
// from a listing of the whole site, so concurrent actions on one site would
// otherwise pick the same certificates to delete.
var siteLocks sync.Map // int64 site ID -> chan struct{}

func lockSite(ctx context.Context, siteID int64) (unlock func(), err error) {
	value, _ := siteLocks.LoadOrStore(siteID, make(chan struct{}, 1))
	lock := value.(chan struct{})
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type esaAPI interface {
	ListCertificatesWithContext(context.Context, *esa.ListCertificatesRequest, *dara.RuntimeOptions) (*esa.ListCertificatesResponse, error)
	GetCertificateWithContext(context.Context, *esa.GetCertificateRequest, *dara.RuntimeOptions) (*esa.GetCertificateResponse, error)
	SetCertificateWithContext(context.Context, *esa.SetCertificateRequest, *dara.RuntimeOptions) (*esa.SetCertificateResponse, error)
	DeleteCertificateWithContext(context.Context, *esa.DeleteCertificateRequest, *dara.RuntimeOptions) (*esa.DeleteCertificateResponse, error)
}

type Action struct {
	cfg    *config.AliESAAction
	client esaAPI
}

func New(cfg *config.AliESAAction, profile *config.AliESAProfile) (*Action, error) {
	regionID := profile.RegionID
	if regionID == "" {
		regionID = defaultRegionID
	}
	endpoint := profile.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("esa.%s.aliyuncs.com", regionID)
	}
	sdkCfg := new(openapi.Config).
		SetAccessKeyId(profile.AccessKeyID).
		SetAccessKeySecret(profile.AccessKeySecret).
		SetRegionId(regionID).
		SetEndpoint(endpoint).
		SetConnectTimeout(10_000).
		SetReadTimeout(30_000)
	if profile.SecurityToken != "" {
		sdkCfg.SetSecurityToken(profile.SecurityToken)
	}
	api, err := esa.NewClient(sdkCfg)
	if err != nil {
		return nil, fmt.Errorf("create Ali ESA client: %w", err)
	}
	return &Action{cfg: cfg, client: api}, nil
}

func (a *Action) Type() string { return config.UPDATE_ACTION_ALI_ESA }

func (a *Action) Update(ctx context.Context, fullchain, key []byte, cert *config.ClientCertificate) error {
	leaf, err := parseMaterial(fullchain, key)
	if err != nil {
		return fmt.Errorf("invalid renewed certificate: %w", err)
	}
	if !slices.Equal(domain.Canonical(leaf.DNSNames), domain.Canonical(cert.Domains)) {
		return fmt.Errorf("renewed certificate SANs do not match certificate %q domains", cert.Name)
	}
	if !leaf.NotAfter.After(time.Now()) {
		return fmt.Errorf("renewed certificate for %q has expired", cert.Name)
	}

	unlock, err := lockSite(ctx, a.cfg.SiteID)
	if err != nil {
		return err
	}
	defer unlock()

	entries, err := a.listCertificates(ctx)
	if err != nil {
		return fmt.Errorf("list ESA site certificates: %w", err)
	}

	stored, err := a.findCertificate(ctx, entries, leaf)
	if err != nil {
		return err
	}
	if stored != nil {
		if err := a.confirm(ctx, *stored.Id, leaf); err != nil {
			return err
		}
		return a.cleanup(ctx, *stored.Id)
	}

	req := new(esa.SetCertificateRequest).
		SetSiteId(a.cfg.SiteID).
		SetType("upload").
		SetName(fmt.Sprintf("certdx-%d-%s", a.cfg.SiteID, fingerprint(leaf)[:12])).
		SetCertificate(strings.TrimSpace(string(fullchain))).
		SetPrivateKey(strings.TrimSpace(string(key)))
	var resp *esa.SetCertificateResponse
	var retired []string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp = nil
		err = callESAAPI(ctx, "SetCertificate", func() error {
			var callErr error
			resp, callErr = a.client.SetCertificateWithContext(ctx, req, apiOptions())
			return callErr
		})
		if err == nil {
			break
		}
		if isCertificateDuplicatedError(err) {
			var listErr error
			var findErr error
			entries, listErr = a.listCertificates(ctx)
			if listErr != nil {
				return fmt.Errorf("SetCertificate at ESA site %d: duplicate upload lookup: %w", a.cfg.SiteID, listErr)
			}
			stored, findErr = a.findCertificate(ctx, entries, leaf)
			if findErr != nil {
				return fmt.Errorf("SetCertificate at ESA site %d: duplicate upload lookup: %w", a.cfg.SiteID, findErr)
			}
			if stored == nil || stored.Id == nil || *stored.Id == "" {
				return fmt.Errorf("SetCertificate at ESA site %d reported a duplicate, but the uploaded certificate was not found", a.cfg.SiteID)
			}
			resp = &esa.SetCertificateResponse{Body: &esa.SetCertificateResponseBody{Id: stored.Id}}
			break
		}
		if !isCertificateQuotaError(err) {
			return fmt.Errorf("SetCertificate at ESA site %d: %w", a.cfg.SiteID, err)
		}
		deleted, deleteErr := a.deleteOldest(ctx, entries, 1, "")
		if deleteErr != nil {
			return errors.Join(fmt.Errorf("SetCertificate at ESA site %d: %w", a.cfg.SiteID, err),
				fmt.Errorf("cannot free ESA upload slot: %w", deleteErr))
		}
		retired = append(retired, deleted...)
		// Another host may have changed the site meanwhile, so choose the next
		// candidate from a fresh listing. Dropping what was already retired
		// keeps the loop finite if the listing lags behind the deletes.
		entries, err = a.listCertificates(ctx)
		if err != nil {
			return fmt.Errorf("list ESA site certificates after freeing an upload slot: %w", err)
		}
		entries = slices.DeleteFunc(entries, func(entry *esa.ListCertificatesResponseBodyResult) bool {
			return entry != nil && slices.Contains(retired, stringValue(entry.Id))
		})
	}
	if resp == nil || resp.Body == nil || resp.Body.Id == nil || *resp.Body.Id == "" {
		return fmt.Errorf("SetCertificate at ESA site %d returned no certificate ID", a.cfg.SiteID)
	}
	logging.Info("Ali ESA site %d accepted certificate %s for %q", a.cfg.SiteID, *resp.Body.Id, cert.Name)
	if err := a.confirm(ctx, *resp.Body.Id, leaf); err != nil {
		return err
	}
	return a.cleanup(ctx, *resp.Body.Id)
}

func isCertificateQuotaError(err error) bool {
	code := esaErrorCode(err)
	return code == "CertQuotaCheckFailed" || code == "QuotaExceeded"
}

func isCertificateNotFoundError(err error) bool {
	return esaErrorCode(err) == "Certificate.NotFound"
}

func isCertificateDuplicatedError(err error) bool {
	return esaErrorCode(err) == "Certificate.Duplicated"
}

func esaErrorCode(err error) string {
	var apiErr dara.BaseError
	if errors.As(err, &apiErr) && apiErr.GetCode() != nil {
		return *apiErr.GetCode()
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) && sdkErr.Code != nil {
		return *sdkErr.Code
	}
	return ""
}

func isTransientESAError(err error) bool {
	switch esaErrorCode(err) {
	case "LockFailed", "InternalException":
		return true
	default:
		return false
	}
}

func callESAAPI(ctx context.Context, what string, work func() error) error {
	for attempt := 0; ; attempt++ {
		err := work()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !isTransientESAError(err) || attempt >= transientRetryCount {
			return err
		}

		wait := min(transientBackoff<<attempt, retry.Interval)
		logging.Warn("%s failed transiently, retry %d/%d in %s: %s", what, attempt+1, transientRetryCount, wait, err)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (a *Action) cleanup(ctx context.Context, currentID string) error {
	entries, err := a.listCertificates(ctx)
	if err != nil {
		logging.Warn("Ali ESA site %d certificate cleanup skipped after confirmation: %s", a.cfg.SiteID, err)
		return nil
	}
	seen := false
	managed := 0
	for _, entry := range entries {
		if entry != nil && stringValue(entry.Id) == currentID {
			seen = true
		}
		if a.isManaged(entry) {
			managed++
		}
	}
	if !seen {
		logging.Warn("Ali ESA certificate %s is not visible in site %d list after confirmation; cleanup skipped", currentID, a.cfg.SiteID)
		return nil
	}
	if _, err := a.deleteOldestBestEffort(ctx, entries, managed-a.cfg.CertificateRetainCount(), currentID); err != nil {
		logging.Warn("Ali ESA site %d certificate cleanup skipped after confirmation: %s", a.cfg.SiteID, err)
	}
	return nil
}

func (a *Action) isManaged(entry *esa.ListCertificatesResponseBodyResult) bool {
	return entry != nil && stringValue(entry.Type) == "upload" &&
		strings.HasPrefix(stringValue(entry.Name), fmt.Sprintf("certdx-%d-", a.cfg.SiteID))
}

func (a *Action) deleteOldest(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	count int, protectedID string) ([]string, error) {
	return a.deleteOldestWithPolicy(ctx, entries, count, protectedID, false)
}

func (a *Action) deleteOldestBestEffort(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	count int, protectedID string) ([]string, error) {
	return a.deleteOldestWithPolicy(ctx, entries, count, protectedID, true)
}

func (a *Action) deleteOldestWithPolicy(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	count int, protectedID string, partial bool) ([]string, error) {
	if count <= 0 {
		return nil, nil
	}
	type candidate struct {
		id      string
		group   string
		created time.Time
		status  string
	}
	var managed []candidate
	for _, entry := range entries {
		if !a.isManaged(entry) {
			continue
		}
		if stringValue(entry.Id) == "" || stringValue(entry.CreateTime) == "" {
			return nil, fmt.Errorf("managed certificate %q has no ID or creation time", stringValue(entry.Name))
		}
		created, err := time.Parse("2006-01-02 15:04:05", *entry.CreateTime)
		if err != nil {
			return nil, fmt.Errorf("managed certificate %s has invalid creation time %q: %w", *entry.Id, *entry.CreateTime, err)
		}
		group := "id:" + *entry.Id
		if stringValue(entry.SAN) != "" {
			group = strings.Join(domain.Canonical(strings.Split(*entry.SAN, ",")), "\x00")
		}
		managed = append(managed, candidate{
			id:      *entry.Id,
			group:   group,
			created: created,
			status:  stringValue(entry.Status),
		})
	}
	sort.Slice(managed, func(i, j int) bool {
		if managed[i].created.Equal(managed[j].created) {
			return managed[i].id < managed[j].id
		}
		return managed[i].created.Before(managed[j].created)
	})
	// Each SAN group keeps its newest healthy upload, plus any newer upload
	// whose status is unknown or still in progress, since another action may
	// be waiting to confirm it. Uploads in a terminal status can never serve,
	// so they get no protection even when they are the group's only version.
	latestHealthy := make(map[string]string)
	latestInProgress := make(map[string]string)
	for _, cert := range managed {
		switch {
		case isHealthyCertificateStatus(cert.status):
			latestHealthy[cert.group] = cert.id
			delete(latestInProgress, cert.group)
		case !isTerminalCertificateStatus(cert.status):
			latestInProgress[cert.group] = cert.id
		}
	}
	// Retire dead uploads before usable rollback versions.
	var terminal, rollback []candidate
	for _, cert := range managed {
		switch {
		case cert.id == protectedID || cert.id == latestHealthy[cert.group] || cert.id == latestInProgress[cert.group]:
		case isTerminalCertificateStatus(cert.status):
			terminal = append(terminal, cert)
		default:
			rollback = append(rollback, cert)
		}
	}
	candidates := append(terminal, rollback...)
	if len(candidates) < count {
		if !partial {
			return nil, fmt.Errorf("need to delete %d certdx certificates, but only %d old versions can be retired safely", count, len(candidates))
		}
		logging.Warn("Ali ESA site %d has %d certdx uploads above retainCount, but only %d old versions can be retired safely; keeping the protected latest upload for each SAN set",
			a.cfg.SiteID, count, len(candidates))
		count = len(candidates)
	}
	var deleted []string
	for _, old := range candidates[:count] {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		_, err := a.client.DeleteCertificateWithContext(ctx,
			new(esa.DeleteCertificateRequest).SetSiteId(a.cfg.SiteID).SetId(old.id), apiOptions())
		if err != nil && !isCertificateNotFoundError(err) {
			return deleted, fmt.Errorf("DeleteCertificate %s: %w", old.id, err)
		}
		deleted = append(deleted, old.id)
		if err != nil {
			logging.Info("Ali ESA site %d certificate %s was already deleted", a.cfg.SiteID, old.id)
			continue
		}
		logging.Info("Ali ESA site %d deleted old certdx certificate %s", a.cfg.SiteID, old.id)
	}
	return deleted, nil
}

func isHealthyCertificateStatus(status string) bool {
	return status == "OK" || status == "Expiring"
}

func isTerminalCertificateStatus(status string) bool {
	return status == "Expired" || status == "ApplyFailed" || status == "Canceled"
}

func (a *Action) listCertificates(ctx context.Context) ([]*esa.ListCertificatesResponseBodyResult, error) {
	var entries []*esa.ListCertificatesResponseBodyResult
	for page := int64(1); ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := new(esa.ListCertificatesRequest).
			SetSiteId(a.cfg.SiteID).
			SetPageNumber(page).
			SetPageSize(pageSize)
		resp, err := a.client.ListCertificatesWithContext(ctx, req, apiOptions())
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			return nil, fmt.Errorf("ListCertificates returned no body")
		}
		result := resp.Body.Result
		entries = append(entries, result...)
		if len(result) == 0 {
			return entries, nil
		}
		if resp.Body.TotalCount != nil && int64(len(entries)) >= *resp.Body.TotalCount {
			return entries, nil
		}
		responsePageSize := pageSize
		if resp.Body.PageSize != nil && *resp.Body.PageSize > 0 {
			responsePageSize = *resp.Body.PageSize
		}
		if resp.Body.TotalCount == nil && int64(len(result)) < responsePageSize {
			return entries, nil
		}
	}
}

func (a *Action) findCertificate(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	leaf *x509.Certificate) (*esa.ListCertificatesResponseBodyResult, error) {
	wantFingerprint := fingerprint(leaf)
	var matching []*esa.ListCertificatesResponseBodyResult
	for _, entry := range entries {
		if entry == nil || entry.Id == nil || *entry.Id == "" ||
			entry.Type == nil || *entry.Type != "upload" || entry.SAN == nil ||
			!slices.Equal(domain.Canonical(strings.Split(*entry.SAN, ",")), domain.Canonical(leaf.DNSNames)) {
			continue
		}
		if normalizeFingerprint(entry.FingerprintSha256) == wantFingerprint {
			return entry, nil
		}
		matching = append(matching, entry)
	}
	var firstErr error
	for _, entry := range matching {
		current, getErr := a.getCertificate(ctx, *entry.Id)
		if isCertificateNotFoundError(getErr) {
			// Deleted since the listing, so it cannot be newer than the renewal.
			continue
		}
		if getErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read matching ESA certificate %s: %w", *entry.Id, getErr)
			}
			continue
		}
		if current.Certificate == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ESA certificate %s has no public certificate", *entry.Id)
			}
			continue
		}
		currentLeaf, parseErr := parseLeaf([]byte(*current.Certificate))
		if parseErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("parse ESA certificate %s: %w", *entry.Id, parseErr)
			}
			continue
		}
		if bytes.Equal(currentLeaf.Raw, leaf.Raw) {
			return entry, nil
		}
		if !currentLeaf.NotAfter.Before(leaf.NotAfter) && firstErr == nil {
			firstErr = fmt.Errorf("ESA certificate %s expires no earlier than the renewed certificate", *entry.Id)
		}
	}
	return nil, firstErr
}

func (a *Action) getCertificate(ctx context.Context, id string) (*esa.GetCertificateResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := new(esa.GetCertificateRequest).SetSiteId(a.cfg.SiteID).SetId(id)
	resp, err := a.client.GetCertificateWithContext(ctx, req, apiOptions())
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("GetCertificate %s returned no body", id)
	}
	return resp.Body, nil
}

func (a *Action) confirm(ctx context.Context, id string, leaf *x509.Certificate) error {
	deadline := time.NewTimer(confirmTimeout)
	defer deadline.Stop()
	for {
		body, err := a.getCertificate(ctx, id)
		if err != nil {
			return fmt.Errorf("confirm ESA certificate %s: %w", id, err)
		}
		if body.Result != nil && normalizeFingerprint(body.Result.FingerprintSha256) == fingerprint(leaf) {
			status := stringValue(body.Result.Status)
			if status == "" {
				status = stringValue(body.Status)
			}
			if isHealthyCertificateStatus(status) {
				logging.Info("Ali ESA certificate %s is registered and valid at site %d", id, a.cfg.SiteID)
				return nil
			}
			if isTerminalCertificateStatus(status) {
				return retry.Permanent(fmt.Errorf("ESA certificate %s reached status %s", id, status))
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return retry.Permanent(fmt.Errorf("timed out confirming ESA certificate %s after %s", id, confirmTimeout))
		case <-time.After(confirmEvery):
		}
	}
}

func apiOptions() *dara.RuntimeOptions {
	return &dara.RuntimeOptions{ConnectTimeout: dara.Int(10_000), ReadTimeout: dara.Int(30_000)}
}

func parseMaterial(fullchain, key []byte) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(fullchain, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("missing PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func normalizeFingerprint(value *string) string {
	return strings.ToLower(strings.ReplaceAll(stringValue(value), ":", ""))
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
