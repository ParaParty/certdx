// Package tencentcloud is the "tencentCloud" update action: it re-binds
// Tencent Cloud resources from the certificate they currently serve to the
// newly issued one.
package tencentcloud

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	txprofile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

const defaultEndpoint = "ssl.tencentcloudapi.com"

// reqTimeout is the per-request timeout handed to the SDK, in seconds.
const reqTimeout = 60

const (
	// transientRetryCount bounds the retries of a single API call that
	// failed with a recognizably transient code (see isTransientTxcError).
	transientRetryCount = 3

	// sameExpiryTolerance is how far apart a CertEndTime and the renewed
	// certificate's NotAfter may be and still be treated as the same
	// instant. Both have one-second precision and CertEndTime is parsed in
	// its documented GMT+8 zone, so this only absorbs rounding. Matching
	// expiry alone never proves identity: a candidate within it is
	// verified with DescribeCertificateDetail (see sameCertificate).
	sameExpiryTolerance = 2 * time.Second
)

// Variables rather than constants so tests do not have to sleep through
// them.
var (
	// deployConfirmTimeout bounds the poll for one UpdateCertificateInstance
	// deploy record. The action runs inside the long-lived client daemon,
	// whose context never expires on its own, so this is what keeps a deploy
	// that never settles from blocking later deliveries for the certificate.
	deployConfirmTimeout = 5 * time.Minute

	// deployRecordAppearTimeout bounds the sub-case where the record detail
	// keeps coming back empty: with nothing to confirm there is no point
	// burning the whole deployConfirmTimeout before saying so.
	deployRecordAppearTimeout = 90 * time.Second

	// deployPollInterval is the gap between deploy record polls.
	deployPollInterval = 10 * time.Second

	// transientBackoff is the first backoff after a transient failure. It
	// doubles per attempt, capped at retry.Interval. Throttling and
	// InternalError come back in well under retry.Do's one-second
	// fast-fail floor, so without this local loop they would never be
	// retried at all.
	transientBackoff = 2 * time.Second
)

// sslAPI is the part of the Tencent Cloud SSL client the action uses.
// *txssl.Client implements it; tests substitute a fake.
type sslAPI interface {
	DescribeCertificatesWithContext(ctx context.Context, req *txssl.DescribeCertificatesRequest) (*txssl.DescribeCertificatesResponse, error)
	UpdateCertificateInstanceWithContext(ctx context.Context, req *txssl.UpdateCertificateInstanceRequest) (*txssl.UpdateCertificateInstanceResponse, error)
	DescribeHostUpdateRecordDetailWithContext(ctx context.Context, req *txssl.DescribeHostUpdateRecordDetailRequest) (*txssl.DescribeHostUpdateRecordDetailResponse, error)
	DescribeCertificateDetailWithContext(ctx context.Context, req *txssl.DescribeCertificateDetailRequest) (*txssl.DescribeCertificateDetailResponse, error)
}

type Action struct {
	cfg    *config.TencentCloudAction
	client sslAPI
}

func New(cfg *config.TencentCloudAction, profile *config.TencentCloudProfile) (*Action, error) {
	endpoint := profile.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	cpf := txprofile.NewClientProfile()
	cpf.HttpProfile.Endpoint = endpoint
	cpf.HttpProfile.ReqTimeout = reqTimeout

	c, err := txssl.NewClient(txcommon.NewCredential(profile.SecretID, profile.SecretKey), "", cpf)
	if err != nil {
		return nil, fmt.Errorf("create tencent cloud client: %w", err)
	}

	return &Action{cfg: cfg, client: c}, nil
}

func (a *Action) Type() string {
	return config.UPDATE_ACTION_TENCENT_CLOUD
}

// Update finds the uploaded certificate currently covering the same domain
// set and re-points the configured resources at the new material, then waits
// for Tencent Cloud's deploy record to confirm the resources moved.
//
// Discovery runs on every update rather than once at start-up, because the
// certificate the resources are bound to changes each time this succeeds.
//
// Errors that are final but slow to arrive (a deploy record reporting failed
// resources, a deploy that never settles) are marked retry.Permanent, so the
// action runner does not replay the whole upload and deploy for them.
func (a *Action) Update(ctx context.Context, fullchain, key []byte, c *config.ClientCertificate) error {
	leaf, err := parseLeaf(fullchain)
	if err != nil {
		return fmt.Errorf("parse renewed certificate: %w", err)
	}

	certificates, err := a.fetchCertificates(ctx)
	if err != nil {
		return fmt.Errorf("fetch certificates: %w", err)
	}

	old, stored, err := a.pickCertificates(ctx, certificates, c.Domains, leaf)
	if err != nil {
		return err
	}
	if old == nil {
		if stored != nil {
			logging.Info("Tencent Cloud already holds the renewed certificate %s for domains %v and no older one, nothing to replace",
				*stored.CertificateId, c.Domains)
			return nil
		}
		logging.Warn("No uploaded Tencent Cloud certificate matches domains %v, nothing to replace", c.Domains)
		return nil
	}

	return a.replaceCertificate(ctx, c.Name, old, stored, fullchain, key)
}

// replaceCertificate uploads the renewed material in place of old and waits
// for the deploy to be confirmed. When Tencent Cloud already stores the
// material (an earlier delivery uploaded it but did not finish re-binding),
// the resources are re-bound to that stored certificate instead of the call
// being reported as a no-op success.
func (a *Action) replaceCertificate(ctx context.Context, certName string, old, stored *txssl.Certificates,
	fullchain, key []byte) error {
	oldID := *old.CertificateId

	req := txssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = txcommon.StringPtr(oldID)
	req.CertificatePublicKey = txcommon.StringPtr(strings.TrimSpace(string(fullchain)))
	req.CertificatePrivateKey = txcommon.StringPtr(strings.TrimSpace(string(key)))
	req.ResourceTypes, req.ResourceTypesRegions = toResourceTypesAndRegions(a.cfg)
	req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)
	req.Repeatable = txcommon.BoolPtr(false)

	deployRecordID, err := a.updateCertificateInstance(ctx, req)
	switch {
	case err == nil:
		return a.waitDeployRecord(ctx, certName, deployRecordID)
	case txcErrorCode(err) == codeCertificateExists:
		logging.Warn("Certificate for %q is already uploaded (%s), rebinding resources of cert id %s to the stored certificate",
			certName, err, oldID)
		return a.rebindStoredCertificate(ctx, certName, oldID, stored)
	case isNothingBoundError(err):
		logging.Info("No %v resource is bound to cert id %s, nothing to re-point (%s)", a.cfg.ResourceTypes, oldID, err)
		return nil
	default:
		return err
	}
}

// rebindStoredCertificate re-points the resources of oldID at the
// certificate Tencent Cloud already stores for the renewed material, and
// waits for the deploy record so the rebind is confirmed rather than assumed.
func (a *Action) rebindStoredCertificate(ctx context.Context, certName, oldID string, stored *txssl.Certificates) error {
	if stored == nil {
		return fmt.Errorf("tencent cloud reports the certificate for %q as uploaded, "+
			"but no stored certificate with the same domains holds it", certName)
	}
	storedID := *stored.CertificateId

	req := txssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = txcommon.StringPtr(oldID)
	req.CertificateId = txcommon.StringPtr(storedID)
	req.ResourceTypes, req.ResourceTypesRegions = toResourceTypesAndRegions(a.cfg)
	req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)

	deployRecordID, err := a.updateCertificateInstance(ctx, req)
	if err != nil {
		if isNothingBoundError(err) {
			// The usual case after a daemon restart: an earlier run already
			// moved every resource off the old certificate.
			logging.Info("No %v resource is still bound to cert id %s, nothing to re-point to %s (%s)",
				a.cfg.ResourceTypes, oldID, storedID, err)
			return nil
		}
		return fmt.Errorf("rebind to %s: %w", storedID, err)
	}
	logging.Info("Rebinding resources of cert id %s to already uploaded cert id %s", oldID, storedID)

	return a.waitDeployRecord(ctx, certName, deployRecordID)
}

// updateCertificateInstance issues UpdateCertificateInstance and returns the
// id of the deploy record it created. The call is asynchronous: a zero
// DeployRecordId means the task is still being created and, per the SDK
// contract, the request must be repeated.
func (a *Action) updateCertificateInstance(ctx context.Context, req *txssl.UpdateCertificateInstanceRequest) (uint64, error) {
	var deployRecordID uint64
	err := callTxcAPI(ctx, "UpdateCertificateInstance", func() error {
		resp, err := a.client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return err
		}
		logging.Debug("UpdateCertificateInstance requestId=%s", stringOrEmpty(resp.Response.RequestId))

		if resp.Response.DeployRecordId == nil || *resp.Response.DeployRecordId == 0 {
			return fmt.Errorf("%w: deploy task not created yet", errTxcRetryable)
		}
		deployRecordID = *resp.Response.DeployRecordId
		return nil
	})
	return deployRecordID, err
}

// waitDeployRecord polls the host-update record of an
// UpdateCertificateInstance task until every resource has been re-bound. A
// created task is not a replaced certificate: without this poll a failed
// deploy would leave the resources on the old certificate while the action
// reported success.
//
// Everything it can prove — resources failed, the record never listed a
// resource, the deploy never settled — is returned as retry.Permanent, so
// the action runner reports it instead of replaying the upload. A missing
// CAM permission for the (read-only) confirmation call downgrades to a
// warning rather than failing a deploy that Tencent Cloud accepted.
func (a *Action) waitDeployRecord(ctx context.Context, certName string, deployRecordID uint64) error {
	id := strconv.FormatUint(deployRecordID, 10)
	start := time.Now()
	deadline := start.Add(deployConfirmTimeout)
	sawResources := false

	for {
		req := txssl.NewDescribeHostUpdateRecordDetailRequest()
		req.DeployRecordId = txcommon.StringPtr(id)

		resp, err := a.client.DescribeHostUpdateRecordDetailWithContext(ctx, req)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				return fmt.Errorf("wait deploy record %s for cert %q: %w", id, certName, ctx.Err())
			case isTxcPermissionError(err):
				// The deploy itself was accepted; only the read-only
				// confirmation is forbidden. Accounts whose CAM policy
				// predates this poll must not start failing over it.
				logging.Warn("Not allowed to read deploy record %s for cert %q (%s); "+
					"grant ssl:DescribeHostUpdateRecordDetail to have the update confirmed instead of assumed", id, certName, err)
				return nil
			case !isTransientTxcError(err):
				return retry.Permanent(fmt.Errorf("DescribeHostUpdateRecordDetail %s: %w", id, err))
			default:
				logging.Warn("DescribeHostUpdateRecordDetail %s errored transiently: %s", id, err)
			}
		} else {
			detail := resp.Response
			failed := int64OrZero(detail.FailedTotalCount)
			pending := int64OrZero(detail.RunningTotalCount) + int64OrZero(detail.PendingTotalCount)
			sawResources = sawResources || deployRecordListsResources(detail)

			if pending == 0 && sawResources {
				if failed > 0 {
					// Confirmed and final: re-uploading the certificate and
					// re-deploying cannot turn these failures into successes.
					return retry.Permanent(fmt.Errorf("deploy record %s for cert %q: %d resource(s) failed to update",
						id, certName, failed))
				}
				logging.Info("Deploy record %s for cert %q confirmed, %d resource(s) updated",
					id, certName, int64OrZero(detail.SuccessTotalCount))
				return nil
			}
			if !sawResources && time.Since(start) >= deployRecordAppearTimeout {
				return retry.Permanent(fmt.Errorf("could not confirm deploy record %s for cert %q: "+
					"no resource listed after %s", id, certName, deployRecordAppearTimeout))
			}
			logging.Debug("Deploy record %s for cert %q still running, pending=%d failed=%d", id, certName, pending, failed)
		}

		if time.Now().After(deadline) {
			// A replay would only repeat the upload and wait again.
			return retry.Permanent(fmt.Errorf("timeout confirming deploy record %s for cert %q after %s",
				id, certName, deployConfirmTimeout))
		}

		select {
		case <-time.After(deployPollInterval):
		case <-ctx.Done():
			return fmt.Errorf("wait deploy record %s for cert %q: %w", id, certName, ctx.Err())
		}
	}
}

// fetchCertificates lists every uploaded, issued server certificate in the
// account.
func (a *Action) fetchCertificates(ctx context.Context) ([]*txssl.Certificates, error) {
	const pageSize uint64 = 100
	offset := uint64(0)

	fetchedCertificates := make([]*txssl.Certificates, 0)

	for {
		req := txssl.NewDescribeCertificatesRequest()
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.Offset = txcommon.Uint64Ptr(offset)
		req.Limit = txcommon.Uint64Ptr(pageSize)

		var page []*txssl.Certificates
		err := callTxcAPI(ctx, "DescribeCertificates", func() error {
			resp, err := a.client.DescribeCertificatesWithContext(ctx, req)
			if err != nil {
				return err
			}
			logging.Debug("DescribeCertificates requestId=%s", stringOrEmpty(resp.Response.RequestId))
			page = resp.Response.Certificates
			return nil
		})
		if err != nil {
			return nil, err
		}

		fetchedCertificates = append(fetchedCertificates, page...)
		if len(page) == 0 {
			break
		}

		offset += pageSize
	}

	return fetchedCertificates, nil
}

// pickCertificates sorts the uploaded certificates whose SANs equal domains
// against leaf, the renewed certificate:
//
//   - stored is the renewed certificate itself, already uploaded by an
//     earlier delivery. Only a certificate whose CertEndTime matches the
//     leaf's NotAfter to the second is a candidate, and it is confirmed by
//     content (sameCertificate): a same-SAN reissue can share, or come
//     within hours of, the renewed certificate's expiry.
//   - old is the newest other certificate expiring no later than the
//     renewed one: the certificate the resources serve now and the one to
//     replace.
//
// Certificates expiring after the renewed one are neither: replacing them
// would move resources to a shorter-lived certificate. A certificate whose
// expiry cannot be parsed is skipped, as nothing about it can be proven.
func (a *Action) pickCertificates(ctx context.Context, certificates []*txssl.Certificates, domains []string,
	leaf *x509.Certificate) (old, stored *txssl.Certificates, err error) {
	var oldEnd time.Time
	for _, cert := range certificates {
		if cert == nil || cert.CertificateId == nil {
			continue
		}
		if !isSameStrSetRejectNilItem(cert.CertSANs, domains) {
			continue
		}

		end, ok := parseTxcTime(cert.CertEndTime)
		if !ok {
			logging.Warn("Skipping Tencent Cloud certificate %s: unparsable CertEndTime %q",
				*cert.CertificateId, stringOrEmpty(cert.CertEndTime))
			continue
		}

		if end.After(leaf.NotAfter.Add(sameExpiryTolerance)) {
			logging.Info("Ignoring Tencent Cloud certificate %s: it expires at %s, after the renewed certificate",
				*cert.CertificateId, end.Format(time.RFC3339))
			continue
		}

		if !end.Before(leaf.NotAfter.Add(-sameExpiryTolerance)) {
			same, err := a.sameCertificate(ctx, *cert.CertificateId, leaf)
			if err != nil {
				return nil, nil, fmt.Errorf("check whether certificate %s is the renewed certificate: %w",
					*cert.CertificateId, err)
			}
			if same {
				stored = cert
				continue
			}
			// A different certificate expiring with the renewed one, such
			// as a reissue: it is a candidate for replacement like any
			// other.
		}

		// Several certificates can cover the same domains once this action
		// has run before; the newest one is what the resources now serve.
		if old == nil || end.After(oldEnd) {
			old, oldEnd = cert, end
		}
	}
	return old, stored, nil
}

// sameCertificate reports whether the uploaded certificate id holds leaf,
// by comparing the stored public certificate or, failing that, its SHA-1
// fingerprint.
func (a *Action) sameCertificate(ctx context.Context, id string, leaf *x509.Certificate) (bool, error) {
	req := txssl.NewDescribeCertificateDetailRequest()
	req.CertificateId = txcommon.StringPtr(id)

	var detail *txssl.DescribeCertificateDetailResponseParams
	err := callTxcAPI(ctx, "DescribeCertificateDetail", func() error {
		resp, err := a.client.DescribeCertificateDetailWithContext(ctx, req)
		if err != nil {
			return err
		}
		detail = resp.Response
		return nil
	})
	if err != nil {
		return false, err
	}

	if detail.CertificatePublicKey != nil && strings.TrimSpace(*detail.CertificatePublicKey) != "" {
		stored, err := parseLeaf([]byte(*detail.CertificatePublicKey))
		if err != nil {
			return false, fmt.Errorf("parse stored public certificate: %w", err)
		}
		return bytes.Equal(stored.Raw, leaf.Raw), nil
	}
	if detail.CertFingerprint != nil && *detail.CertFingerprint != "" {
		return normalizeFingerprint(*detail.CertFingerprint) == sha1Fingerprint(leaf), nil
	}
	return false, fmt.Errorf("certificate detail carries neither the public certificate nor its fingerprint")
}

// callTxcAPI runs one Tencent Cloud SDK call, retrying it with exponential
// backoff while it fails with a transient error. Any other error is returned
// as is, straight away.
func callTxcAPI(ctx context.Context, what string, work func() error) error {
	for attempt := 0; ; attempt++ {
		err := work()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%s: %w", what, ctx.Err())
		}
		if !isTransientTxcError(err) || attempt >= transientRetryCount {
			return fmt.Errorf("%s: %w", what, err)
		}

		wait := min(transientBackoff<<attempt, retry.Interval)
		logging.Warn("%s failed transiently, retry %d/%d in %s: %s", what, attempt+1, transientRetryCount, wait, err)

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", what, ctx.Err())
		}
	}
}

func toResourceTypesAndRegions(cfg *config.TencentCloudAction) ([]*string, []*txssl.ResourceTypeRegions) {
	resourceTypesRegions := make([]*txssl.ResourceTypeRegions, 0, len(cfg.ResourceTypesRegions))
	for _, it := range cfg.ResourceTypesRegions {
		resourceTypesRegions = append(resourceTypesRegions, &txssl.ResourceTypeRegions{
			ResourceType: txcommon.StringPtr(it.ResourceType),
			Regions:      txcommon.StringPtrs(it.Regions),
		})
	}
	return txcommon.StringPtrs(cfg.ResourceTypes), resourceTypesRegions
}
