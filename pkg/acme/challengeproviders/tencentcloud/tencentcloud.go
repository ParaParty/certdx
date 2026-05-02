package tencentcloud

import (
	"github.com/go-acme/lego/v4/challenge"
	legoTencentCloud "github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"pkg.para.party/certdx/pkg/config"
)

func New(p config.DnsProvider) (challenge.Provider, error) {
	tencentCloudConfig := legoTencentCloud.NewDefaultConfig()
	tencentCloudConfig.SecretID = p.SecretID
	tencentCloudConfig.SecretKey = p.SecretKey
	return legoTencentCloud.NewDNSProviderConfig(tencentCloudConfig)
}
