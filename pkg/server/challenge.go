package server

import (
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"pkg.para.party/certdx/pkg/config"
	"time"
)

const (
	ChallengeTypeDns01 string = "dns01"
)

func SetChallenger(legoCfg *lego.Config, instance *ACME, p config.DnsProvider) error {
	tpy, dnsClg, err := getChallenger(legoCfg, p)
	if err != nil {
		return fmt.Errorf("unexpected error constructing cloudflare dns client: %w", err)
	}

	opt := make([]dns01.ChallengeOption, 0)

	if p.DisableCompletePropagationRequirement {
		opt = append(opt, dns01.DisableCompletePropagationRequirement())
	}

	switch tpy {
	case ChallengeTypeDns01:
		if err := instance.Client.Challenge.SetDNS01Provider(dnsClg, opt...); err != nil {
			return fmt.Errorf("unexpected error setting up dns challenge: %w", err)
		}
	default:
		return fmt.Errorf("unknown provider: type %v", tpy)
	}

	return nil
}

func getChallenger(legoCfg *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	switch p.Type {
	case config.DnsProviderTypeCloudflare:
		return makeCloudflareProvider(legoCfg, p)
	case config.DnsProviderTypeTencentCloud:
		return makeTencentCLoudProvider(legoCfg, p)
	}

	return "", nil, fmt.Errorf("unknown dns provider: type %v", p.Type)
}

func makeCloudflareProvider(legoCfg *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	c, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthEmail:          p.Email,
		AuthKey:            p.APIKey,
		TTL:                120,
		PropagationTimeout: 30 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient:         legoCfg.HTTPClient,
	})
	return ChallengeTypeDns01, c, err
}

func makeTencentCLoudProvider(_ *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	tencentCloudConfig := tencentcloud.NewDefaultConfig()
	tencentCloudConfig.SecretID = p.SecretID
	tencentCloudConfig.SecretKey = p.SecretKey
	c, err := tencentcloud.NewDNSProviderConfig(tencentCloudConfig)
	return ChallengeTypeDns01, c, err
}
