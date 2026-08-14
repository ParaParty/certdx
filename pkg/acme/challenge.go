package acme

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"pkg.para.party/certdx/pkg/acme/challengeproviders/cloudflare"
	"pkg.para.party/certdx/pkg/acme/challengeproviders/s3"
	"pkg.para.party/certdx/pkg/acme/challengeproviders/tencentcloud"
	"pkg.para.party/certdx/pkg/config"
)

func SetChallenger(legoCfg *lego.Config, instance *ACME, p *config.ServerConfig) error {
	typ, clg, err := getChallenger(legoCfg, p)
	if err != nil {
		return fmt.Errorf("unexpected error constructing cloudflare dns client: %w", err)
	}
	switch typ {
	case config.ChallengeTypeDns01:
		opt := make([]dns01.ChallengeOption, 0)

		if p.DnsProvider.DisableCompletePropagationRequirement {
			opt = append(opt, dns01.DisableAuthoritativeNssPropagationRequirement())
		}

		// 添加自定义 DNS 服务器
		if len(p.DnsProvider.Nameservers) > 0 {
			opt = append(opt, dns01.AddRecursiveNameservers(p.DnsProvider.Nameservers))
		}

		// 添加 DNS 超时
		if p.DnsProvider.DNSTimeout != "" {
			timeout, err := time.ParseDuration(p.DnsProvider.DNSTimeout)
			if err != nil {
				return fmt.Errorf("invalid dnsTimeout %q: %w", p.DnsProvider.DNSTimeout, err)
			}
			opt = append(opt, dns01.AddDNSTimeout(timeout))
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

func getChallenger(legoCfg *lego.Config, p *config.ServerConfig) (string, challenge.Provider, error) {
	switch p.ACME.ChallengeType {
	case config.ChallengeTypeDns01:
		switch p.DnsProvider.Type {
		case config.DnsProviderTypeCloudflare:
			return makeCloudflareProvider(legoCfg, *p.DnsProvider)
		case config.DnsProviderTypeTencentCloud:
			return makeTencentCloudProvider(legoCfg, *p.DnsProvider)
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
	c, err := cloudflare.New(legoCfg, p)
	return config.ChallengeTypeDns01, c, err
}

func makeTencentCloudProvider(_ *lego.Config, p config.DnsProvider) (string, challenge.Provider, error) {
	c, err := tencentcloud.New(p)
	return config.ChallengeTypeDns01, c, err
}

func makeS3Provider(_ *lego.Config, p config.S3Client) (string, challenge.Provider, error) {
	c, err := s3.NewHTTPProvider(p)
	return config.ChallengeTypeHttp01, c, err
}
