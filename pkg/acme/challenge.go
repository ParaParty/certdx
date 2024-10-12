package acme

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"pkg.para.party/certdx/pkg/acme/http/s3"
	"pkg.para.party/certdx/pkg/config"
)

func SetChallenger(legoCfg *lego.Config, instance *ACME, p *config.ServerConfigT) error {
	typ, clg, err := getChallenger(legoCfg, p)
	if err != nil {
		return fmt.Errorf("unexpected error constructing cloudflare dns client: %w", err)
	}
	switch typ {
	case config.ChallengeTypeDns01:
		opt := make([]dns01.ChallengeOption, 0)

		if p.DnsProvider.DisableCompletePropagationRequirement {
			opt = append(opt, dns01.DisableCompletePropagationRequirement())
		}

		if err := instance.Client.Challenge.SetDNS01Provider(clg, opt...); err != nil {
			return fmt.Errorf("unexpected error setting up dns challenge: %w", err)
		}
	case config.ChallengeTypeHttp01:
		if err := instance.Client.Challenge.SetHTTP01Provider(clg); err != nil {
			return fmt.Errorf("unexpected error setting up http challenge: %w", err)
		}
	default:
		return fmt.Errorf("unknown provider: type %v", typ)
	}

	return nil
}

func getChallenger(legoCfg *lego.Config, p *config.ServerConfigT) (string, challenge.Provider, error) {
	switch p.ACME.ChallengeType {
	case config.ChallengeTypeDns01:
		switch p.DnsProvider.Type {
		case config.DnsProviderTypeCloudflare:
			return makeCloudflareProvider(legoCfg, *p.DnsProvider)
		case config.DnsProviderTypeTencentCloud:
			return makeTencentCLoudProvider(legoCfg, *p.DnsProvider)
		default:
			return "", nil, fmt.Errorf("unknown dns provider type: %s", p.DnsProvider.Type)
		}
	case config.ChallengeTypeHttp01:
		switch p.HttpProvider.Type {
		case config.HttpProviderTypeS3:
			return makeS3Provider(legoCfg, *p.HttpProvider.S3)
		default:
			return "", nil, fmt.Errorf("unknown http provider type: %s", p.HttpProvider.Type)
		}
	}

	return "", nil, fmt.Errorf("unknown challenge type: %s", p.ACME.ChallengeType)
}

func makeCloudflareProvider(legoCfg *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	// zone token
	if p.ZoneToken != "" && p.AuthToken != "" {
		cloudflareConfig := cloudflare.NewDefaultConfig()
		cloudflareConfig.ZoneToken = p.ZoneToken
		cloudflareConfig.AuthToken = p.AuthToken
		cloudflareDnsProvider, err := cloudflare.NewDNSProviderConfig(cloudflareConfig)
		if err != nil {
			return config.ChallengeTypeDns01, nil, err
		}

		return config.ChallengeTypeDns01, cloudflareDnsProvider, err
	}

	// global token
	c, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthEmail:          p.Email,
		AuthKey:            p.APIKey,
		TTL:                120,
		PropagationTimeout: 30 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient:         legoCfg.HTTPClient,
	})
	return config.ChallengeTypeDns01, c, err
}

func makeTencentCLoudProvider(_ *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	tencentCloudConfig := tencentcloud.NewDefaultConfig()
	tencentCloudConfig.SecretID = p.SecretID
	tencentCloudConfig.SecretKey = p.SecretKey
	c, err := tencentcloud.NewDNSProviderConfig(tencentCloudConfig)
	return config.ChallengeTypeDns01, c, err
}

func makeS3Provider(_ *lego.Config, p config.S3Client) (string, challenge.Provider, error) {
	c, err := s3.NewHTTPProvider(p)
	return config.ChallengeTypeHttp01, c, err
}
