package txcCertificateUpdater

import (
	"context"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	txprofile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"google.golang.org/appengine"
	"io"
	"os"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/utils"
	"strings"
	"sync"
	"time"

	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

type TencentCloudCertificateUpdater struct {
	cmd *txcCertsUpdateCmd

	cfg    *TencentCloudConfig
	client *txssl.Client

	wg           sync.WaitGroup
	taskErr      appengine.MultiError
	taskErrMutex sync.Mutex

	certDXDaemon *client.CertDXClientDaemon
}

func MakeTencentCloudCertificateUpdater(updaterCmd *txcCertsUpdateCmd) *TencentCloudCertificateUpdater {
	return &TencentCloudCertificateUpdater{
		cmd: updaterCmd,

		cfg: &TencentCloudConfig{},
		// client : in tencent cloud init

		wg:           sync.WaitGroup{},
		taskErr:      appengine.MultiError{},
		taskErrMutex: sync.Mutex{},

		// certDXDaemon : in certdx init
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
		if ac.CertificateId == cert.CertificateId {
			continue
		}
		if isSameStrSetRejectNilItemPtrArrPtrArr(ac.CertSANs, cert.CertSANs) {
			return ac, nil
		}
	}
	return nil, nil
}

func (r *TencentCloudCertificateUpdater) GetCertificateToUpdate() error {
	logging.Info("retrieving expiring certificates...")
	expiringCertificates, err := r.FetchTencentCloudCertificate(func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(1)               // 临期证书
	})
	if err != nil {
		logging.Fatal("failed to fetch expiring certificates: %v", err)
	}

	logging.Info("retrieving expiring and normal certificates...")
	activatingCertificates, err := r.FetchTencentCloudCertificate(func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(0)               // 临期证书和非临期证书
	})
	if err != nil {
		logging.Fatal("failed to fetch expiring certificates: %v", err)
	}

	matchedCerts := make([]ClientCertification, 0)

	for _, expiringCert := range expiringCertificates {
		if expiringCert.CertificateId == nil {
			logging.Error("unexpected certificate id: %v", expiringCert.CertificateId)
			continue
		}
		var activatingCertificate *txssl.Certificates
		activatingCertificate, err = isActivatingCertificateExists(activatingCertificates, expiringCert)
		if err != nil {
			logging.Error("failed to check activating certificate: %v", err)
			continue
		}
		if activatingCertificate != nil {
			logging.Info("a newer certificate exists, old cert id: %v, new cert id: %v", *expiringCert.CertificateId, *activatingCertificate.CertificateId)
			continue
		}

		fetchedCertSANs := expiringCert.CertSANs

		for _, cert := range r.cfg.Certifications {
			if isSameStrSetRejectNilItem(fetchedCertSANs, cert.Domains) {
				cert.oldCertificateId = *expiringCert.CertificateId
				cert.certDxKey = utils.DomainsAsKey(cert.Domains)
				matchedCerts = append(matchedCerts, cert)
			}
		}
	}

	err = LogMissingCerts(r.cfg.Certifications, matchedCerts)
	if err != nil {
		r.cfg.Certifications = make([]ClientCertification, 0)
		return err
	}
	r.cfg.Certifications = matchedCerts

	return nil
}

func (r *TencentCloudCertificateUpdater) AddReplaceTask() error {
	for _, c := range r.cfg.Certifications {
		taskCert := c // copy
		r.wg.Add(1)

		err := r.certDXDaemon.AddCertToWatchOpt(taskCert.Name, taskCert.Domains, []client.WatchingCertsOption{
			client.WithCertificateHandlerOption(func(fullchain, key []byte, certDxC *config.ClientCertification) {
				req := txssl.NewUpdateCertificateInstanceRequest()
				req.OldCertificateId = &taskCert.oldCertificateId
				req.CertificatePublicKey = txcommon.StringPtr(strings.TrimSpace(string(fullchain)))
				req.CertificatePrivateKey = txcommon.StringPtr(strings.TrimSpace(string(key)))
				req.ResourceTypes, req.ResourceTypesRegions = taskCert.ToResourceTypesAndResourceTypesRegions()
				req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)

				err := utils.Retry(3, func() error {
					resp, err := r.client.UpdateCertificateInstance(req)
					if err != nil {
						var tencentCloudSDKError *txerr.TencentCloudSDKError
						if errors.As(err, &tencentCloudSDKError) {
							logging.Error("UploadUpdateCertificateInstance, failed: %v, requestId: %v", tencentCloudSDKError, tencentCloudSDKError.RequestId)
						} else {
							logging.Error("UploadUpdateCertificateInstance, failed: %v", err)
						}
						return err
					}

					logging.Debug("UploadUpdateCertificateInstance RequestId: %v", *resp.Response.RequestId)
					return nil
				})

				if err != nil {
					r.taskErrMutex.Lock()
					r.taskErr = append(r.taskErr, err)
					r.taskErrMutex.Unlock()
				}

				r.wg.Done()
			}),
		})
		if err != nil {
			logging.Error("failed to add cert to watch, error: %v", err)
		}
	}

	return nil
}

func (r *TencentCloudCertificateUpdater) WaitReplaceTask() error {
	waitDeadlineCtx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancelFunc()

	wgDone := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(wgDone)
	}()

	select {
	case <-waitDeadlineCtx.Done():
		s := "timeout waiting for certificates to be replaced"
		logging.Error(s)
		return fmt.Errorf(s)
	case <-wgDone:
		if len(r.taskErr) == 0 {
			logging.Info("certificate replaced successfully")
			return nil
		} else {
			logging.Error("certificate replaced failed: %v", r.taskErr)
			return r.taskErr
		}
	}
}
func (r *TencentCloudCertificateUpdater) FetchTencentCloudCertificate(opt func(request *txssl.DescribeCertificatesRequest)) ([]*txssl.Certificates, error) {
	offset := uint64(0)
	pageSize := uint64(100)

	fetchedCertificates := make([]*txssl.Certificates, 0)

	for {
		req := txssl.NewDescribeCertificatesRequest()
		opt(req)
		req.Offset = txcommon.Uint64Ptr(offset)
		req.Limit = txcommon.Uint64Ptr(pageSize)

		noMoreResult := false
		err := utils.Retry(3, func() error {
			resp, err := r.client.DescribeCertificates(req)
			if err != nil {
				var tencentCloudSDKError *txerr.TencentCloudSDKError
				if errors.As(err, &tencentCloudSDKError) {
					logging.Error("DescribeCertificates, failed: %v, requestId: %v", tencentCloudSDKError, tencentCloudSDKError.RequestId)
				} else {
					logging.Error("DescribeCertificates, failed: %v", err)
				}
				return err
			}
			logging.Debug("DescribeCertificates RequestId: %v", *resp.Response.RequestId)

			fetchedCertificates = append(fetchedCertificates, resp.Response.Certificates...)
			noMoreResult = len(resp.Response.Certificates) == 0
			return nil
		})

		if err != nil {
			logging.Error("failed to list all certificates, error: %v", err)
			return nil, err
		}

		offset = offset + pageSize
		if noMoreResult {
			break
		}
	}
	return fetchedCertificates, nil
}

func LogMissingCerts(a, b []ClientCertification) error {
	bKeys := make(map[string]struct{}, len(b))
	for _, cert := range b {
		key := cert.Name + "|" + strings.Join(cert.Domains, ",")
		bKeys[key] = struct{}{}
	}

	for _, cert := range a {
		key := cert.Name + "|" + strings.Join(cert.Domains, ",")
		if _, found := bKeys[key]; !found {
			// Not a fatal error, because of the filtering condition
			logging.Warn("cert only in configuration but not in tencent cloud updating tasks – Name: %s, Domains: %v", cert.Name, cert.Domains)
		}
	}

	return nil
}

func (r *TencentCloudCertificateUpdater) InitCertDX() error {
	r.certDXDaemon = client.MakeCertDXClientDaemon()
	err := r.certDXDaemon.LoadConfigurationAndValidateOpt(*r.cmd.confPath, []config.ValidatingOption{
		config.WithAcceptEmptyCertificateSavePath(true),
		config.WithAcceptEmptyCertificatesList(false),
	})
	if err != nil {
		logging.Fatal("Invalid config: %s", err)
	}
	logging.Debug("Reconnect duration is: %s", r.certDXDaemon.Config.Common.ReconnectDuration)

	return nil
}

func (r *TencentCloudCertificateUpdater) InitTencentCloud() error {
	cfile, err := os.Open(*r.cmd.confPath)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
		return err
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, r.cfg); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshalling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	credential := txcommon.NewCredential(r.cfg.Authorization.SecretID,
		r.cfg.Authorization.SecretKey)

	cpf := txprofile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 60

	r.client, err = txssl.NewClient(credential, "", cpf)
	if err != nil {
		logging.Fatal("Fail to create tencent cloud client, err: %s", err)
	}

	return nil
}

func (r *TencentCloudCertificateUpdater) InitCertificateUpdater() error {
	err := r.InitCertDX()
	if err != nil {
		logging.Error("Failed to initialize certdx: %s", err)
		return err
	}

	err = r.InitTencentCloud()
	if err != nil {
		logging.Error("Failed to initialize tencent cloud: %s", err)
		return err
	}

	return nil
}

func (r *TencentCloudCertificateUpdater) InvokeCertificateUpdate() error {
	err := r.GetCertificateToUpdate()
	if err != nil {
		logging.Fatal("Failed to initialize tencent cloud: %s", err)
	}

	err = r.AddReplaceTask()
	if err != nil {
		logging.Fatal("Failed to initialize tencent cloud: %s", err)
	}

	switch r.certDXDaemon.Config.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		go r.certDXDaemon.HttpMain()
	case config.CLIENT_MODE_GRPC:
		go r.certDXDaemon.GRPCMain()
	default:
		logging.Fatal("Mode: \"%s\" is not supported", r.certDXDaemon.Config.Common.Mode)
	}

	return r.WaitReplaceTask()
}
