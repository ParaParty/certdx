package cloudflare

import (
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	legoCloudflare "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"pkg.para.party/certdx/pkg/config"
)

func New(legoCfg *lego.Config, p config.DnsProvider) (challenge.Provider, error) {
	// zone token
	if p.ZoneToken != "" && p.AuthToken != "" {
		cloudflareConfig := legoCloudflare.NewDefaultConfig()
		cloudflareConfig.ZoneToken = p.ZoneToken
		cloudflareConfig.AuthToken = p.AuthToken
		return legoCloudflare.NewDNSProviderConfig(cloudflareConfig)
	}

	// global token
	return legoCloudflare.NewDNSProviderConfig(&legoCloudflare.Config{
		AuthEmail:          p.Email,
		AuthKey:            p.APIKey,
		TTL:                120,
		PropagationTimeout: 30 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient:         legoCfg.HTTPClient,
	})
}
