package alidns

import (
	"github.com/go-acme/lego/v4/challenge"
	legoAliDNS "github.com/go-acme/lego/v4/providers/dns/alidns"
	"pkg.para.party/certdx/pkg/config"
)

func New(p config.DnsProvider) (challenge.Provider, error) {
	aliDNSConfig := legoAliDNS.NewDefaultConfig()
	aliDNSConfig.APIKey = p.AccessKeyID
	aliDNSConfig.SecretKey = p.AccessKeySecret
	aliDNSConfig.SecurityToken = p.SecurityToken
	return legoAliDNS.NewDNSProviderConfig(aliDNSConfig)
}
