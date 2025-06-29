package txcReplaceCertificate

import (
	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
	"io"
	"os"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/types"
	"pkg.para.party/certdx/pkg/utils"

	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	//txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txprofile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

type ClientCertification struct {
	Name    string
	Domains []string

	oldCertificateId []string
	key              types.DomainKey
}

type TencentCloudConfig struct {
	Authorization struct {
		SecretID  string `toml:"secretID" json:"secret_id,omitempty"`
		SecretKey string `toml:"secretKey" json:"secret_key,omitempty"`
	} `toml:"Authorization" json:"authorization,omitempty"`

	certifications []ClientCertification
}

type TencentCloudCertificateReplace struct {
	cfg    *TencentCloudConfig
	client *txssl.Client
}

func (r *TencentCloudCertificateReplace) FetchTencentCloudExpiringCerts() error {

	offset := uint64(0)
	pageSize := uint64(100)

	fetchedCertificates := make([]*txssl.Certificates, 0)

	for {
		req := txssl.NewDescribeCertificatesRequest()
		req.Offset = txcommon.Uint64Ptr(offset)
		req.Limit = txcommon.Uint64Ptr(pageSize)
		req.CertificateType = txcommon.StringPtr("SVR")          // 服务端证书
		req.CertificateStatus = []*uint64{txcommon.Uint64Ptr(1)} // 正常状态的证书
		req.FilterSource = txcommon.StringPtr("upload")          // 上传的证书
		req.FilterExpiring = txcommon.Uint64Ptr(1)               // 临期证书

		noMoreResult := false
		err := utils.Retry(3, func() error {
			resp, err := r.client.DescribeCertificates(req)
			//var tencentCloudSDKError *txerr.TencentCloudSDKError
			//if errors.As(err, &tencentCloudSDKError) {
			//	fmt.Printf("An API error has returned: %s", err)
			//}
			if err != nil {
				logging.Error("DescribeCertificates req: %v, failed: %v", req, err)
				return err
			}

			fetchedCertificates = append(fetchedCertificates, resp.Response.Certificates...)
			noMoreResult = len(resp.Response.Certificates) == 0
			return nil
		})

		if err != nil {
			logging.Fatal("failed to list all certificates, error: %v", err)
		}

		offset = offset + pageSize
		if noMoreResult {
			break
		}
	}

	return nil
}

type txcReplaceCertsConf struct {
	confPath *string
}

var cfg *txcReplaceCertsConf
var certDXDaemon *client.CertDXClientDaemon
var tencentCloudCertReplace *TencentCloudCertificateReplace

func initCmd() error {
	var (
		clientCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		clientHelp = clientCMD.BoolP("help", "h", false, "Print help")
		conf       = clientCMD.StringP("conf", "c", "./client.toml", "Config file path")
		pDebug     = clientCMD.BoolP("debug", "d", false, "Enable debug log")
	)
	clientCMD.Parse(os.Args[2:])

	if *clientHelp {
		clientCMD.PrintDefaults()
		os.Exit(0)
	}

	logging.SetDebug(*pDebug)
	if conf == nil || len(*conf) == 0 {
		logging.Fatal("Config file path is empty")
	}

	cfg = &txcReplaceCertsConf{
		confPath: conf,
	}

	return nil
}

// Init CretDX Client
func InitCertDX() error {
	certDXDaemon = client.MakeCertDXClientDaemon()
	err := certDXDaemon.LoadConfigurationAndValidateOpt(*cfg.confPath, []config.ValidatingOption{
		config.WithAcceptEmptyCertificateSavePath(true),
		config.WithAcceptEmptyCertificatesList(false),
	})
	if err != nil {
		logging.Fatal("Invalid config: %s", err)
	}
	logging.Debug("Reconnect duration is: %s", certDXDaemon.Config.Common.ReconnectDuration)

	return nil
}

// Init Tencent Cloud Client
func InitTencentCloud() error {
	tencentCloudCertReplace = &TencentCloudCertificateReplace{
		cfg: &TencentCloudConfig{},
	}

	cfile, err := os.Open(*cfg.confPath)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
		return err
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, tencentCloudCertReplace.cfg); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshalling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	credential := txcommon.NewCredential(tencentCloudCertReplace.cfg.Authorization.SecretID,
		tencentCloudCertReplace.cfg.Authorization.SecretKey)

	cpf := txprofile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 60

	tencentCloudCertReplace.client, err = txssl.NewClient(credential, "", cpf)
	if err != nil {
		logging.Fatal("Fail to create tencent cloud client, err: %s", err)
	}

	return nil
}

func TencentCloudReplaceCertificate() {
	// init
	err := initCmd()
	if err != nil {
		logging.Fatal("Failed to initialize certdx: %s", err)
	}

	err = InitCertDX()
	if err != nil {
		logging.Fatal("Failed to initialize certdx: %s", err)
	}

	err = InitTencentCloud()
	if err != nil {
		logging.Fatal("Failed to initialize tencent cloud: %s", err)
	}

	err = tencentCloudCertReplace.FetchTencentCloudExpiringCerts()

	//tencentCloudCfg.certifications = make([]ClientCertification, 0)
	//for _, c := range certDXDaemon.Config.Certifications {
	//	cert := ClientCertification{
	//		Name:    c.Name,
	//		Domains: c.Domains,
	//		key:     utils.DomainsAsKey(c.Domains),
	//	}
	//	tencentCloudCfg.certifications = append(tencentCloudCfg.certifications, cert)
	//}

	// update certs
	//if err := certDXDaemon.AddCertToWatch(cert.Name, cert.Domains); err != nil {
	//	logging.Fatal("Failed to add cert to watch: %s", err)
	//}
}
