package ali

import (
	"github.com/go-acme/lego/v4/challenge"
	legoAli "github.com/go-acme/lego/v4/providers/dns/alidns"
	"pkg.para.party/certdx/pkg/config"
)

func New(p config.DnsProvider) (challenge.Provider, error) {
	aliConfig := legoAli.NewDefaultConfig()
	aliConfig.APIKey = p.AccessKeyId
	aliConfig.SecretKey = p.AccessKeySecret
	aliConfig.SecurityToken = p.SecurityToken
	return legoAli.NewDNSProviderConfig(aliConfig)
}
