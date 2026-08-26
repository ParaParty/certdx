// Package tencentcloud is the "tencentCloud" update action: it re-binds
// Tencent Cloud resources from the certificate they currently serve to the
// newly issued one.
package tencentcloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txprofile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

const defaultEndpoint = "ssl.tencentcloudapi.com"

// reqTimeout is the per-request timeout handed to the SDK, in seconds.
const reqTimeout = 60

// certTimeLayout is how the SSL API formats certificate timestamps.
const certTimeLayout = "2006-01-02 15:04:05"

type Action struct {
	cfg    *config.TencentCloudAction
	client *txssl.Client
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
// set and re-points the configured resources at the new material.
//
// Discovery runs on every update rather than once at start-up, because the
// certificate the resources are bound to changes each time this succeeds.
func (a *Action) Update(ctx context.Context, fullchain, key []byte, c *config.ClientCertificate) error {
	old, err := a.findCertificateToReplace(ctx, c.Domains)
	if err != nil {
		return err
	}
	if old == nil {
		logging.Warn("No uploaded Tencent Cloud certificate matches domains %v, nothing to replace", c.Domains)
		return nil
	}

	return a.replaceCertificate(ctx, *old.CertificateId, fullchain, key)
}

// findCertificateToReplace returns the newest uploaded certificate whose SANs
// equal domains, or nil when the account holds no such certificate.
func (a *Action) findCertificateToReplace(ctx context.Context, domains []string) (*txssl.Certificates, error) {
	certificates, err := a.fetchCertificates(ctx, func(req *txssl.DescribeCertificatesRequest) {
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
	})
	if err != nil {
		return nil, fmt.Errorf("fetch certificates: %w", err)
	}

	var newest *txssl.Certificates
	var newestEnd time.Time

	for _, cert := range certificates {
		if cert == nil || cert.CertificateId == nil {
			continue
		}
		if !isSameStrSetRejectNilItem(cert.CertSANs, domains) {
			continue
		}

		// Several certificates can cover the same domains once this action
		// has run before; the newest one is what the resources now serve.
		end := parseCertTime(cert.CertEndTime)
		if newest == nil || end.After(newestEnd) {
			newest, newestEnd = cert, end
		}
	}

	return newest, nil
}

func (a *Action) replaceCertificate(ctx context.Context, oldCertificateID string, fullchain, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	req := txssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = txcommon.StringPtr(oldCertificateID)
	req.CertificatePublicKey = txcommon.StringPtr(strings.TrimSpace(string(fullchain)))
	req.CertificatePrivateKey = txcommon.StringPtr(strings.TrimSpace(string(key)))
	req.ResourceTypes, req.ResourceTypesRegions = toResourceTypesAndRegions(a.cfg)
	req.ExpiringNotificationSwitch = txcommon.Uint64Ptr(1)
	req.Repeatable = txcommon.BoolPtr(false)

	resp, err := a.client.UpdateCertificateInstance(req)
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
}

func (a *Action) fetchCertificates(ctx context.Context, opt func(request *txssl.DescribeCertificatesRequest)) ([]*txssl.Certificates, error) {
	const pageSize uint64 = 100
	offset := uint64(0)

	fetchedCertificates := make([]*txssl.Certificates, 0)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		req := txssl.NewDescribeCertificatesRequest()
		opt(req)
		req.Offset = txcommon.Uint64Ptr(offset)
		req.Limit = txcommon.Uint64Ptr(pageSize)

		resp, err := a.client.DescribeCertificates(req)
		if err != nil {
			return nil, fmt.Errorf("DescribeCertificates: %w", err)
		}
		logging.Debug("DescribeCertificates requestId=%s", *resp.Response.RequestId)

		fetchedCertificates = append(fetchedCertificates, resp.Response.Certificates...)
		if len(resp.Response.Certificates) == 0 {
			break
		}

		offset += pageSize
	}

	return fetchedCertificates, nil
}

func parseCertTime(value *string) time.Time {
	if value == nil {
		return time.Time{}
	}
	parsed, err := time.Parse(certTimeLayout, *value)
	if err != nil {
		return time.Time{}
	}
	return parsed
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
