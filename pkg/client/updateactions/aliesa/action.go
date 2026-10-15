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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	esa "github.com/alibabacloud-go/esa-20240910/v2/client"
	"github.com/alibabacloud-go/tea/dara"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

const (
	defaultRegionID = "cn-hangzhou"
	pageSize        = int64(100)
	uploadQuota     = 5
	confirmTimeout  = 2 * time.Minute
	confirmEvery    = 3 * time.Second
)

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

	uploaded := 0
	for _, entry := range entries {
		if entry != nil && stringValue(entry.Type) == "upload" {
			uploaded++
		}
	}
	if uploaded >= uploadQuota {
		if err := a.deleteOldest(ctx, entries, uploaded-uploadQuota+1, ""); err != nil {
			return fmt.Errorf("free ESA upload slot at site %d: %w", a.cfg.SiteID, err)
		}
	}

	req := new(esa.SetCertificateRequest).
		SetSiteId(a.cfg.SiteID).
		SetType("upload").
		SetName(fmt.Sprintf("certdx-%d-%s", a.cfg.SiteID, fingerprint(leaf)[:12])).
		SetCertificate(strings.TrimSpace(string(fullchain))).
		SetPrivateKey(strings.TrimSpace(string(key)))
	if err := ctx.Err(); err != nil {
		return err
	}
	resp, err := a.client.SetCertificateWithContext(ctx, req, apiOptions())
	if err != nil {
		return fmt.Errorf("SetCertificate at ESA site %d: %w", a.cfg.SiteID, err)
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

func (a *Action) cleanup(ctx context.Context, currentID string) error {
	entries, err := a.listCertificates(ctx)
	if err != nil {
		return fmt.Errorf("list ESA certificates for cleanup: %w", err)
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
		return fmt.Errorf("ESA certificate %s is not visible in site %d list after confirmation", currentID, a.cfg.SiteID)
	}
	if err := a.deleteOldest(ctx, entries, managed-a.cfg.CertificateRetainCount(), currentID); err != nil {
		return fmt.Errorf("retain ESA certificates at site %d: %w", a.cfg.SiteID, err)
	}
	return nil
}

func (a *Action) isManaged(entry *esa.ListCertificatesResponseBodyResult) bool {
	return entry != nil && stringValue(entry.Type) == "upload" &&
		strings.HasPrefix(stringValue(entry.Name), fmt.Sprintf("certdx-%d-", a.cfg.SiteID))
}

func (a *Action) deleteOldest(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	count int, protectedID string) error {
	if count <= 0 {
		return nil
	}
	type candidate struct {
		id      string
		group   string
		created time.Time
	}
	var managed []candidate
	for _, entry := range entries {
		if !a.isManaged(entry) {
			continue
		}
		if stringValue(entry.Id) == "" || stringValue(entry.CreateTime) == "" {
			return fmt.Errorf("managed certificate %q has no ID or creation time", stringValue(entry.Name))
		}
		created, err := time.Parse("2006-01-02 15:04:05", *entry.CreateTime)
		if err != nil {
			return fmt.Errorf("managed certificate %s has invalid creation time %q: %w", *entry.Id, *entry.CreateTime, err)
		}
		group := "id:" + *entry.Id
		if stringValue(entry.SAN) != "" {
			group = strings.Join(domain.Canonical(strings.Split(*entry.SAN, ",")), "\x00")
		}
		managed = append(managed, candidate{id: *entry.Id, group: group, created: created})
	}
	sort.Slice(managed, func(i, j int) bool {
		if managed[i].created.Equal(managed[j].created) {
			return managed[i].id < managed[j].id
		}
		return managed[i].created.Before(managed[j].created)
	})
	latest := make(map[string]string)
	for _, cert := range managed {
		latest[cert.group] = cert.id
	}
	var candidates []candidate
	for _, cert := range managed {
		if cert.id != protectedID && cert.id != latest[cert.group] {
			candidates = append(candidates, cert)
		}
	}
	if len(candidates) < count {
		return fmt.Errorf("need to delete %d certdx certificates, but only %d old versions can be retired safely", count, len(candidates))
	}
	for _, old := range candidates[:count] {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := a.client.DeleteCertificateWithContext(ctx,
			new(esa.DeleteCertificateRequest).SetSiteId(a.cfg.SiteID).SetId(old.id), apiOptions())
		if err != nil {
			return fmt.Errorf("DeleteCertificate %s: %w", old.id, err)
		}
		logging.Info("Ali ESA site %d deleted old certdx certificate %s", a.cfg.SiteID, old.id)
	}
	return nil
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
		entries = append(entries, resp.Body.Result...)
		if int64(len(resp.Body.Result)) < pageSize ||
			(resp.Body.TotalCount != nil && page*pageSize >= *resp.Body.TotalCount) {
			return entries, nil
		}
	}
}

func (a *Action) findCertificate(ctx context.Context, entries []*esa.ListCertificatesResponseBodyResult,
	leaf *x509.Certificate) (stored *esa.ListCertificatesResponseBodyResult, err error) {
	wantFingerprint := fingerprint(leaf)
	for _, entry := range entries {
		if entry == nil || entry.Id == nil || *entry.Id == "" ||
			entry.Type == nil || *entry.Type != "upload" || entry.SAN == nil ||
			!slices.Equal(domain.Canonical(strings.Split(*entry.SAN, ",")), domain.Canonical(leaf.DNSNames)) {
			continue
		}
		if normalizeFingerprint(entry.FingerprintSha256) == wantFingerprint {
			stored = entry
			continue
		}
		current, getErr := a.getCertificate(ctx, *entry.Id)
		if getErr != nil {
			return nil, fmt.Errorf("read matching ESA certificate %s: %w", *entry.Id, getErr)
		}
		if current.Certificate == nil {
			return nil, fmt.Errorf("ESA certificate %s has no public certificate", *entry.Id)
		}
		currentLeaf, parseErr := parseLeaf([]byte(*current.Certificate))
		if parseErr != nil {
			return nil, fmt.Errorf("parse ESA certificate %s: %w", *entry.Id, parseErr)
		}
		if bytes.Equal(currentLeaf.Raw, leaf.Raw) {
			stored = entry
			continue
		}
		if !currentLeaf.NotAfter.Before(leaf.NotAfter) {
			return nil, fmt.Errorf("ESA certificate %s expires no earlier than the renewed certificate", *entry.Id)
		}
	}
	return stored, nil
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
			if status == "OK" || status == "Expiring" {
				logging.Info("Ali ESA certificate %s is registered and valid at site %d", id, a.cfg.SiteID)
				return nil
			}
			if status == "Expired" || status == "ApplyFailed" || status == "Canceled" {
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
