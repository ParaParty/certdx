package txcCertificateUpdater

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	txprofile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"pkg.para.party/certdx/pkg/cli"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"

	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// updateRetryCount bounds the per-cert UpdateCertificateInstance retries.
const updateRetryCount = 3

// describeRetryCount bounds DescribeCertificates pagination retries.
const describeRetryCount = 3

const (
	// waitDeadline bounds a whole updater run — an unreachable or
	// rejecting Tencent Cloud endpoint must surface as a nonzero exit
	// for cron alerting instead of hanging forever.
	waitDeadline = 10 * time.Minute

	// deployConfirmTimeout bounds the poll for one UpdateCertificateInstance
	// deploy record; deployPollInterval is the gap between polls.
	deployConfirmTimeout = 5 * time.Minute
	deployPollInterval   = 10 * time.Second

	// deployRecordAppearTimeout bounds the sub-case where the record
	// detail keeps coming back empty: with nothing to confirm there is
	// no point burning the whole deployConfirmTimeout before saying so.
	deployRecordAppearTimeout = 90 * time.Second

	// txcFastFailThreshold mirrors retry.Do's fast-fail floor: a failure
	// arriving faster than this is deterministic unless it is one of the
	// recognizably transient SDK codes.
	txcFastFailThreshold = time.Second

	// txcTransientBackoff is the first backoff for a transient SDK
	// failure (throttling, InternalError, network/5xx). It doubles per
	// attempt, capped at retry.Interval.
	txcTransientBackoff = 2 * time.Second
)

type TencentCloudCertificateUpdater struct {
	cmd *txcCertsUpdateCmd

	cfg    *TencentCloudConfig
	client *txssl.Client

	wg           sync.WaitGroup
	taskErrMu    sync.Mutex
	taskErr      []error
	certDXDaemon *client.CertDXClientDaemon

	// oldCertEnd maps an expiring certificate id to its parsed
	// CertEndTime. It is the per-task companion of
	// ClientCertification.oldCertificateId — the rebind path needs the
	// expiry of the certificate it is replacing to reject a stale
	// replacement. Written once in GetCertificateToUpdate, read-only
	// afterwards.
	oldCertEnd map[string]time.Time

	// ctx is captured from InvokeCertificateUpdate so the per-cert
	// retry callbacks (closures the certdx daemon invokes on update)
	// and the paged DescribeCertificates retries can share a single
	// cancellation source. The updater is one-shot, so a struct-level
	// ctx is simpler than threading it through every closure.
	ctx context.Context
}

func MakeTencentCloudCertificateUpdater(updaterCmd *txcCertsUpdateCmd) *TencentCloudCertificateUpdater {
	return &TencentCloudCertificateUpdater{
		cmd:        updaterCmd,
		cfg:        &TencentCloudConfig{},
		oldCertEnd: make(map[string]time.Time),
	}
}

// findReplacementCertificate returns the certificate that already
// supersedes cert: same SAN set, a strictly later CertEndTime, and not
// itself in the expiring set. Matching on the SAN set alone was wrong —
// the activating list also contains the expiring certs, so two same-SAN
// expiring certs used to suppress each other and neither was renewed.
// Anything we cannot prove is a valid replacement (unparsable expiry, a
// same-SAN peer that is also expiring) returns nil so cert still renews.
func findReplacementCertificate(activatingCertificates []*txssl.Certificates, cert *txssl.Certificates,
	expiringIds map[string]struct{}) (*txssl.Certificates, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	certEnd, ok := parseTxcTime(cert.CertEndTime)
	if !ok {
		logging.Warn("Certificate has no parsable CertEndTime, treating it as not replaced")
		return nil, nil
	}

	var (
		newest    *txssl.Certificates
		newestEnd time.Time
	)
	for _, ac := range activatingCertificates {
		if ac == nil || ac.CertificateId == nil {
			logging.Warn("Skipping certificate without id while looking for a replacement")
			continue
		}
		if cert.CertificateId != nil && *ac.CertificateId == *cert.CertificateId {
			continue
		}
		if _, expiring := expiringIds[*ac.CertificateId]; expiring {
			continue
		}
		if !isSameStrSetRejectNilItemPtrArrPtrArr(ac.CertSANs, cert.CertSANs) {
			continue
		}
		acEnd, ok := parseTxcTime(ac.CertEndTime)
		if !ok || !acEnd.After(certEnd) {
			continue
		}
		if newest == nil || acEnd.After(newestEnd) {
			newest, newestEnd = ac, acEnd
		}
	}
	return newest, nil
}

func (r *TencentCloudCertificateUpdater) GetCertificateToUpdate() error {
	logging.Info("Retrieving expiring certificates")
	expiringCertificates, err := r.FetchTencentCloudCertificate(func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(1)               // 临期证书
	})
	if err != nil {
		return fmt.Errorf("fetch expiring certificates: %w", err)
	}

	logging.Info("Retrieving expiring and normal certificates")
	activatingCertificates, err := r.FetchTencentCloudCertificate(func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(0)               // 临期证书和非临期证书
	})
	if err != nil {
		return fmt.Errorf("fetch activating certificates: %w", err)
	}

	// The activating list is a superset of the expiring one; a same-SAN
	// peer that is itself expiring is not a replacement.
	expiringIds := make(map[string]struct{}, len(expiringCertificates))
	for _, expiringCert := range expiringCertificates {
		if expiringCert == nil || expiringCert.CertificateId == nil {
			continue
		}
		expiringIds[*expiringCert.CertificateId] = struct{}{}
	}

	matchedCerts := make([]ClientCertification, 0)
	if r.oldCertEnd == nil {
		r.oldCertEnd = make(map[string]time.Time)
	}

	for _, expiringCert := range expiringCertificates {
		if expiringCert == nil || expiringCert.CertificateId == nil {
			logging.Error("Unexpected nil certificate id")
			continue
		}
		activatingCertificate, err := findReplacementCertificate(activatingCertificates, expiringCert, expiringIds)
		if err != nil {
			logging.Error("Failed to check activating certificate: %s", err)
			continue
		}
		if activatingCertificate != nil {
			logging.Info("A newer certificate exists, old cert id: %v, new cert id: %v", *expiringCert.CertificateId, *activatingCertificate.CertificateId)
			continue
		}

		fetchedCertSANs := expiringCert.CertSANs

		for _, cert := range r.cfg.Certifications {
			if isSameStrSetRejectNilItem(fetchedCertSANs, cert.Domains) {
				cert.oldCertificateId = *expiringCert.CertificateId
				cert.certDxKey = domain.AsKey(cert.Domains)
				// Remember when the certificate being replaced expires:
				// the rebind path must not settle for a stored
				// certificate that expires no later than this one.
				if end, ok := parseTxcTime(expiringCert.CertEndTime); ok {
					r.oldCertEnd[cert.oldCertificateId] = end
				}
				matchedCerts = append(matchedCerts, cert)
			}
		}
	}

	logMissingCerts(r.cfg.Certifications, matchedCerts)
	r.cfg.Certifications = matchedCerts

	return nil
}

// AddReplaceTask registers a per-cert callback with the certdx daemon.
// The WaitGroup counter is incremented only after AddCertToWatchOpt
// succeeds — a registration failure leaves the wait group untouched
// rather than leaking a permanent +1 that would hang WaitReplaceTask
// at its deadline.
func (r *TencentCloudCertificateUpdater) AddReplaceTask() error {
	for _, c := range r.cfg.Certifications {
		taskCert := c // capture by value for the closure

		if err := r.certDXDaemon.AddCertToWatchOpt(taskCert.Name, taskCert.Domains, []client.WatchingCertsOption{
			client.WithCertificateHandlerOption(r.makeReplaceHandler(taskCert)),
		}); err != nil {
			return fmt.Errorf("watch cert %q: %w", taskCert.Name, err)
		}
		r.wg.Add(1)
	}
	return nil
}

// makeReplaceHandler returns the per-cert callback the certdx daemon
// fires on each cert update. It posts the new cert to Tencent Cloud
// SSL with retries (cancellable via r.ctx), waits for the resulting
// deploy record to be confirmed, and signals the outer WaitGroup
// whether the replacement succeeded or not.
func (r *TencentCloudCertificateUpdater) makeReplaceHandler(taskCert ClientCertification) client.CertificateUpdateHandler {
	return func(fullchain, key []byte, _ *config.ClientCertification) {
		defer r.wg.Done()

		req := txssl.NewUpdateCertificateInstanceRequest()
		req.OldCertificateId = &taskCert.oldCertificateId
		req.CertificatePublicKey = txcommon.StringPtr(strings.TrimSpace(string(fullchain)))
		req.CertificatePrivateKey = txcommon.StringPtr(strings.TrimSpace(string(key)))
		req.ResourceTypes, req.ResourceTypesRegions = taskCert.ToResourceTypesAndResourceTypesRegions()
		req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)
		req.Repeatable = txcommon.BoolPtr(false)

		err := r.callTxcAPI(updateRetryCount, "UpdateCertificateInstance", func() error {
			resp, err := r.client.UpdateCertificateInstanceWithContext(r.ctx, req)
			if err != nil {
				var sdkErr *txerr.TencentCloudSDKError
				if errors.As(err, &sdkErr) && sdkErr.Code == "FailedOperation.CertificateExists" {
					// The certificate is already in the Tencent Cloud
					// store from an earlier partial run, but nothing was
					// re-bound: the resources still point at the expiring
					// cert. Rebind them against the stored certificate
					// instead of reporting a no-op as success.
					logging.Warn("Certificate already uploaded (code=%s message=%s requestId=%s), rebinding resources to the stored certificate",
						sdkErr.Code, sdkErr.Message, sdkErr.RequestId)
					return r.rebindExistingCertificate(taskCert)
				}
				return fmt.Errorf("UpdateCertificateInstance: %w", err)
			}
			logging.Debug("UpdateCertificateInstance requestId=%s", *resp.Response.RequestId)
			return r.waitDeployRecord(taskCert.Name, resp.Response.DeployRecordId)
		})

		if err != nil {
			r.taskErrMu.Lock()
			r.taskErr = append(r.taskErr, fmt.Errorf("replace cert %q: %w", taskCert.Name, err))
			r.taskErrMu.Unlock()
		}
	}
}

// rebindExistingCertificate handles FailedOperation.CertificateExists:
// it looks up the certificate Tencent Cloud already stores for the same
// domains and re-issues UpdateCertificateInstance against that id, then
// waits for the deploy record so the rebind is confirmed rather than
// assumed.
func (r *TencentCloudCertificateUpdater) rebindExistingCertificate(taskCert ClientCertification) error {
	newCertificateId, err := r.findUploadedCertificate(taskCert)
	if err != nil {
		return fmt.Errorf("locate already uploaded certificate: %w", err)
	}
	logging.Info("Rebinding resources of cert id %s to already uploaded cert id %s", taskCert.oldCertificateId, newCertificateId)

	req := txssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = txcommon.StringPtr(taskCert.oldCertificateId)
	req.CertificateId = txcommon.StringPtr(newCertificateId)
	req.ResourceTypes, req.ResourceTypesRegions = taskCert.ToResourceTypesAndResourceTypesRegions()
	req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)

	resp, err := r.client.UpdateCertificateInstanceWithContext(r.ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateCertificateInstance (rebind to %s): %w", newCertificateId, err)
	}
	logging.Debug("UpdateCertificateInstance (rebind) requestId=%s", *resp.Response.RequestId)

	return r.waitDeployRecord(taskCert.Name, resp.Response.DeployRecordId)
}

// findUploadedCertificate returns the id of the newest certificate
// Tencent Cloud holds for taskCert's domains, excluding the expiring one
// being replaced and anything that does not outlive it. The lookup runs
// with FilterExpiring=0, so expiring certificates are in the result set
// too — without the expiry guard a rebind could point every resource at
// a staler certificate and then confirm that as a success.
func (r *TencentCloudCertificateUpdater) findUploadedCertificate(taskCert ClientCertification) (string, error) {
	certificates, err := r.FetchTencentCloudCertificate(func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(0)               // 临期证书和非临期证书
	})
	if err != nil {
		return "", err
	}

	oldEnd := r.oldCertEndTime(taskCert.oldCertificateId)
	if oldEnd.IsZero() {
		logging.Warn("Expiry of cert id %s is unknown, cannot check the stored certificate is newer than it",
			taskCert.oldCertificateId)
	}
	return pickNewerUploadedCertificate(certificates, taskCert.Domains, taskCert.oldCertificateId, oldEnd)
}

// oldCertEndTime returns the parsed CertEndTime of the expiring
// certificate with the given id, or the zero time when it was never
// recorded (unparsable timestamp, or a task built outside
// GetCertificateToUpdate). The map is filled before any handler runs and
// only read afterwards, so it needs no lock.
func (r *TencentCloudCertificateUpdater) oldCertEndTime(certificateId string) time.Time {
	return r.oldCertEnd[certificateId]
}

// waitDeployRecord polls the host-update record of an
// UpdateCertificateInstance task until every resource has been
// re-bound. A created task is not a replaced certificate: without this
// poll a failed deploy would leave the resources on the expiring cert
// while the run reported success.
//
// Anything it can prove — resources failed, the record never listed a
// resource, the deploy never settled — comes back wrapped in
// [errTxcTerminal] so callTxcAPI reports it instead of replaying the
// upload. "No record yet" is the one retryable outcome, and a missing
// CAM permission for the (read-only) confirmation call downgrades to a
// warning rather than failing a deploy that Tencent Cloud accepted.
func (r *TencentCloudCertificateUpdater) waitDeployRecord(certName string, deployRecordId *uint64) error {
	if deployRecordId == nil || *deployRecordId == 0 {
		// DeployRecordId == 0 means the task has not been created yet;
		// the SDK contract is to repeat the request.
		return fmt.Errorf("%w: deploy task for cert %q not created yet", errTxcRetryable, certName)
	}

	id := strconv.FormatUint(*deployRecordId, 10)
	start := time.Now()
	deadline := start.Add(deployConfirmTimeout)
	sawResources := false

	for {
		req := txssl.NewDescribeHostUpdateRecordDetailRequest()
		req.DeployRecordId = txcommon.StringPtr(id)

		resp, err := r.client.DescribeHostUpdateRecordDetailWithContext(r.ctx, req)
		if err != nil {
			switch {
			case isTxcPermissionError(err):
				// The deploy itself was accepted; only the read-only
				// confirmation is forbidden. Accounts whose CAM policy
				// predates this poll must not start failing their runs
				// over it — warn loudly and stop confirming.
				logging.Warn("Not allowed to read deploy record %s for cert %q (%s); "+
					"grant ssl:DescribeHostUpdateRecordDetail to have the update confirmed instead of assumed", id, certName, err)
				return nil
			case !isTransientTxcError(err):
				return fmt.Errorf("DescribeHostUpdateRecordDetail %s: %w", id, err)
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
					// Confirmed and final: re-uploading the certificate
					// and re-deploying cannot turn these failures into
					// successes, so this must not be retried.
					return fmt.Errorf("%w: deploy record %s for cert %q: %d resource(s) failed to update",
						errTxcTerminal, id, certName, failed)
				}
				logging.Info("Deploy record %s for cert %q confirmed, %d resource(s) updated",
					id, certName, int64OrZero(detail.SuccessTotalCount))
				return nil
			}
			if !sawResources && time.Since(start) >= deployRecordAppearTimeout {
				return fmt.Errorf("%w: could not confirm deploy record %s for cert %q: "+
					"no resource listed after %s", errTxcTerminal, id, certName, deployRecordAppearTimeout)
			}
			logging.Debug("Deploy record %s for cert %q still running, pending=%d failed=%d", id, certName, pending, failed)
		}

		if time.Now().After(deadline) {
			if !sawResources {
				return fmt.Errorf("%w: could not confirm deploy record %s for cert %q: "+
					"no resource listed after %s", errTxcTerminal, id, certName, deployConfirmTimeout)
			}
			// Still pending after the confirmation window: a retry would
			// only repeat the upload and wait again, and the whole run is
			// bounded by waitDeadline anyway.
			return fmt.Errorf("%w: timeout confirming deploy record %s for cert %q after %s",
				errTxcTerminal, id, certName, deployConfirmTimeout)
		}

		select {
		case <-time.After(deployPollInterval):
		case <-r.ctx.Done():
			return fmt.Errorf("wait deploy record %s for cert %q: %w", id, certName, r.ctx.Err())
		}
	}
}

// callTxcAPI runs a Tencent Cloud SDK call with bounded retries. It
// keeps retry.Do's fast-fail rule for deterministic failures but adds a
// backoff path for recognizably transient ones (throttling,
// InternalError, network/5xx) — those return in well under a second, so
// retry.Do alone would give up before the retry budget ever engaged.
func (r *TencentCloudCertificateUpdater) callTxcAPI(retryCount int, what string, work func() error) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}

	var err error
	for attempt := 0; ; attempt++ {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		// A terminal verdict is never retried, however long it took to
		// arrive. Deploy-record confirmation polls for minutes, so the
		// elapsed-time heuristic below would classify its "these
		// resources failed" answer as retryable and replay the whole
		// upload + deploy until the run budget was gone.
		if isTerminalTxcError(err) {
			return fmt.Errorf("%s failed terminally, not retrying. error is: %w", what, err)
		}

		transient := isTransientTxcError(err)
		if !transient && time.Since(begin) < txcFastFailThreshold {
			return fmt.Errorf("%s errored too fast, give up retry. last error is: %w", what, err)
		}

		if attempt >= retryCount {
			break
		}

		wait := retry.Interval
		if transient {
			wait = txcTransientBackoff << attempt
			if wait > retry.Interval {
				wait = retry.Interval
			}
		}
		logging.Warn("%s retry %d/%d in %s, errored: %s", what, attempt+1, retryCount, wait, err)

		select {
		case <-time.After(wait):
		case <-r.ctx.Done():
			return fmt.Errorf("%s retry cancelled: %w", what, r.ctx.Err())
		}
	}

	return fmt.Errorf("%s errored too many times, give up retry. last error is: %w", what, err)
}

// WaitReplaceTask blocks until every registered handler has completed
// or ctx fires. Cancellation is driven by the caller's ctx, which the
// entrypoint bounds with [waitDeadline] and wires to SIGINT/SIGTERM, so
// an unreachable server ends the run instead of hanging it.
func (r *TencentCloudCertificateUpdater) WaitReplaceTask(ctx context.Context) error {
	wgDone := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(wgDone)
	}()

	select {
	case <-ctx.Done():
		// Report what already failed alongside the deadline; a bare
		// "context deadline exceeded" hides which certificate or
		// resource actually went wrong.
		errs := append([]error{fmt.Errorf("wait for certificate replacement: %w", ctx.Err())}, r.collectTaskErr()...)
		return errors.Join(errs...)
	case <-wgDone:
		if errs := r.collectTaskErr(); len(errs) != 0 {
			return errors.Join(errs...)
		}
		logging.Info("Certificates replaced successfully")
		return nil
	}
}

// collectTaskErr snapshots the errors recorded by the per-cert handlers.
// Handlers may still be running when the deadline branch reads them, so
// the copy is taken under the mutex.
func (r *TencentCloudCertificateUpdater) collectTaskErr() []error {
	r.taskErrMu.Lock()
	defer r.taskErrMu.Unlock()
	return append([]error(nil), r.taskErr...)
}

func (r *TencentCloudCertificateUpdater) FetchTencentCloudCertificate(opt func(request *txssl.DescribeCertificatesRequest)) ([]*txssl.Certificates, error) {
	const pageSize uint64 = 100
	offset := uint64(0)

	fetchedCertificates := make([]*txssl.Certificates, 0)

	for {
		req := txssl.NewDescribeCertificatesRequest()
		opt(req)
		req.Offset = txcommon.Uint64Ptr(offset)
		req.Limit = txcommon.Uint64Ptr(pageSize)

		noMoreResult := false
		err := r.callTxcAPI(describeRetryCount, "DescribeCertificates", func() error {
			resp, err := r.client.DescribeCertificatesWithContext(r.ctx, req)
			if err != nil {
				return fmt.Errorf("DescribeCertificates: %w", err)
			}
			logging.Debug("DescribeCertificates requestId=%s", *resp.Response.RequestId)

			fetchedCertificates = append(fetchedCertificates, resp.Response.Certificates...)
			noMoreResult = len(resp.Response.Certificates) == 0
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}

		offset += pageSize
		if noMoreResult {
			break
		}
	}
	return fetchedCertificates, nil
}

// logMissingCerts emits a warning for each cert that is configured for
// the updater but did not match any expiring certificate fetched from
// Tencent Cloud. The previous nil-returning err signature was dead
// code; the caller had no way to distinguish "all matched" from "some
// missing".
func logMissingCerts(configured, matched []ClientCertification) {
	matchedKeys := make(map[string]struct{}, len(matched))
	for _, cert := range matched {
		key := cert.Name + "|" + strings.Join(cert.Domains, ",")
		matchedKeys[key] = struct{}{}
	}

	for _, cert := range configured {
		key := cert.Name + "|" + strings.Join(cert.Domains, ",")
		if _, found := matchedKeys[key]; !found {
			logging.Warn("Cert in configuration but not in tencent cloud updating tasks: name=%s domains=%v",
				cert.Name, cert.Domains)
		}
	}
}

func (r *TencentCloudCertificateUpdater) InitCertDX() error {
	r.certDXDaemon = client.MakeCertDXClientDaemon()
	if err := r.certDXDaemon.LoadConfigurationAndValidateOpt(*r.cmd.confPath, []config.ValidatingOption{
		config.WithAcceptEmptyCertificateSavePath(true),
		config.WithAcceptEmptyCertificatesList(false),
	}); err != nil {
		return fmt.Errorf("invalid certdx config: %w", err)
	}
	logging.Debug("Reconnect duration is: %s", r.certDXDaemon.Config.Common.ReconnectDuration)
	return nil
}

// InitTencentCloud parses the same TOML file once into the Tencent
// Cloud-specific schema and constructs the SDK client. The certdx-
// schema parse happened in InitCertDX; the file is opened once per
// schema rather than read+parsed twice into the same struct.
func (r *TencentCloudCertificateUpdater) InitTencentCloud() error {
	if err := cli.LoadTOML(*r.cmd.confPath, r.cfg); err != nil {
		return err
	}

	credential := txcommon.NewCredential(r.cfg.Authorization.SecretID, r.cfg.Authorization.SecretKey)

	cpf := txprofile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 60

	c, err := txssl.NewClient(credential, "", cpf)
	if err != nil {
		return fmt.Errorf("create tencent cloud client: %w", err)
	}
	r.client = c
	return nil
}

func (r *TencentCloudCertificateUpdater) InitCertificateUpdater() error {
	if err := r.InitCertDX(); err != nil {
		return fmt.Errorf("init certdx: %w", err)
	}
	if err := r.InitTencentCloud(); err != nil {
		return fmt.Errorf("init tencent cloud: %w", err)
	}
	return nil
}

// InvokeCertificateUpdate captures ctx on the updater and drives a
// one-shot replace pass: pull expiring certs, register per-cert
// replace handlers, start the certdx daemon, then wait for every
// handler to complete (or ctx to fire).
func (r *TencentCloudCertificateUpdater) InvokeCertificateUpdate(ctx context.Context) error {
	r.ctx = ctx

	if err := r.GetCertificateToUpdate(); err != nil {
		return fmt.Errorf("get certificates to update: %w", err)
	}
	if err := r.AddReplaceTask(); err != nil {
		return fmt.Errorf("add replace task: %w", err)
	}

	switch r.certDXDaemon.Config.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		go r.certDXDaemon.HttpMain()
	case config.CLIENT_MODE_GRPC:
		go r.certDXDaemon.GRPCMain()
	default:
		return fmt.Errorf("unsupported mode: %s", r.certDXDaemon.Config.Common.Mode)
	}
	defer r.certDXDaemon.Stop()

	return r.WaitReplaceTask(ctx)
}
