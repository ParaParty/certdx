package aliesa

import (
	"github.com/go-acme/lego/v4/challenge"
	legoAliESA "github.com/go-acme/lego/v4/providers/dns/aliesa"
	"pkg.para.party/certdx/pkg/config"
)

func New(p config.DnsProvider) (challenge.Provider, error) {
	aliESAConfig := legoAliESA.NewDefaultConfig()
	aliESAConfig.APIKey = p.AccessKeyID
	aliESAConfig.SecretKey = p.AccessKeySecret
	aliESAConfig.SecurityToken = p.SecurityToken
	aliESAConfig.RAMRole = p.RAMRole
	aliESAConfig.RegionID = p.RegionID
	return legoAliESA.NewDNSProviderConfig(aliESAConfig)
}
