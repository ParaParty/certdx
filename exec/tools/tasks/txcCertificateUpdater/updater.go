package txcCertificateUpdater

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

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

type TencentCloudCertificateUpdater struct {
	cmd *txcCertsUpdateCmd

	cfg    *TencentCloudConfig
	client *txssl.Client

	wg           sync.WaitGroup
	taskErrMu    sync.Mutex
	taskErr      []error
	certDXDaemon *client.CertDXClientDaemon

	// ctx is captured from InvokeCertificateUpdate so the per-cert
	// retry callbacks (closures the certdx daemon invokes on update)
	// and the paged DescribeCertificates retries can share a single
	// cancellation source. The updater is one-shot, so a struct-level
	// ctx is simpler than threading it through every closure.
	ctx context.Context
}

func MakeTencentCloudCertificateUpdater(updaterCmd *txcCertsUpdateCmd) *TencentCloudCertificateUpdater {
	return &TencentCloudCertificateUpdater{
		cmd: updaterCmd,
		cfg: &TencentCloudConfig{},
	}
}

func isActivatingCertificateExists(activatingCertificates []*txssl.Certificates, cert *txssl.Certificates) (*txssl.Certificates, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	for _, ac := range activatingCertificates {
		if ac == nil {
			return nil, fmt.Errorf("activatingCertificates contains nil certificate")
		}
		if ac.CertificateId != nil && cert.CertificateId != nil && *ac.CertificateId == *cert.CertificateId {
			continue
		}
		if isSameStrSetRejectNilItemPtrArrPtrArr(ac.CertSANs, cert.CertSANs) {
			return ac, nil
		}
	}
	return nil, nil
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

	matchedCerts := make([]ClientCertification, 0)

	for _, expiringCert := range expiringCertificates {
		if expiringCert.CertificateId == nil {
			logging.Error("Unexpected nil certificate id")
			continue
		}
		activatingCertificate, err := isActivatingCertificateExists(activatingCertificates, expiringCert)
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
// SSL with retries (cancellable via r.ctx) and signals the outer
// WaitGroup whether the call succeeded or not.
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

		err := retry.Do(r.ctx, updateRetryCount, func() error {
			resp, err := r.client.UpdateCertificateInstance(req)
			if err != nil {
				var sdkErr *txerr.TencentCloudSDKError
				if errors.As(err, &sdkErr) && sdkErr.Code == "FailedOperation.CertificateExists" {
					logging.Warn("Certificate already exists, skipping upload (code=%s message=%s requestId=%s)",
						sdkErr.Code, sdkErr.Message, sdkErr.RequestId)
					return nil
				}
				return fmt.Errorf("UpdateCertificateInstance: %w", err)
			}
			logging.Debug("UpdateCertificateInstance requestId=%s", *resp.Response.RequestId)
			return nil
		})

		if err != nil {
			r.taskErrMu.Lock()
			r.taskErr = append(r.taskErr, err)
			r.taskErrMu.Unlock()
		}
	}
}

// WaitReplaceTask blocks until every registered handler has completed
// or ctx fires. Cancellation is driven by the caller's ctx — a Stop
// signal propagates through directly instead of through the previous
// hard-coded one-hour internal timeout.
func (r *TencentCloudCertificateUpdater) WaitReplaceTask(ctx context.Context) error {
	wgDone := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(wgDone)
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for certificate replacement: %w", ctx.Err())
	case <-wgDone:
		r.taskErrMu.Lock()
		defer r.taskErrMu.Unlock()
		if len(r.taskErr) == 0 {
			logging.Info("Certificates replaced successfully")
			return nil
		}
		return errors.Join(r.taskErr...)
	}
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
		err := retry.Do(r.ctx, describeRetryCount, func() error {
			resp, err := r.client.DescribeCertificates(req)
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
