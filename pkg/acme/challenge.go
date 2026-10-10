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
	"pkg.para.party/certdx/pkg/logging"
)

func SetChallenger(legoCfg *lego.Config, instance *ACME, p *config.ServerConfig) error {
	typ, clg, err := getChallenger(legoCfg, p)
	if err != nil {
		return fmt.Errorf("unexpected error constructing cloudflare dns client: %w", err)
	}
	switch typ {
	case config.ChallengeTypeDns01:
		opts, dnsTimeout, err := dns01Options(p.DnsProvider)
		if err != nil {
			return err
		}
		if p.DnsProvider.DNSTimeout != "" {
			clg = overridePropagationTimeout(clg, dnsTimeout)
		}

		if err := instance.Client.Challenge.SetDNS01Provider(clg, opts...); err != nil {
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

// dns01Options builds the lego DNS-01 options for p and returns the DNS
// timeout in effect.
func dns01Options(p *config.DnsProvider) ([]dns01.ChallengeOption, time.Duration, error) {
	var opts []dns01.ChallengeOption
	dnsTimeout := defaultConservativeDNSTimeout

	if len(p.Nameservers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(p.Nameservers))
	}

	if p.DNSTimeout != "" {
		timeout, err := time.ParseDuration(p.DNSTimeout)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid dnsTimeout %q: %w", p.DNSTimeout, err)
		}
		dnsTimeout = timeout
		opts = append(opts, dns01.AddDNSTimeout(timeout))
	}

	if p.ConservativeDNSCheck {
		if p.DisableCompletePropagationRequirement {
			logging.Warn("DnsProvider: disableCompletePropagationRequirement is ignored because conservativeDnsCheck is enabled")
		}
		checker := newConservativeChecker(p.Nameservers, dnsTimeout)
		opts = append(opts, dns01.WrapPreCheck(checker.Wrap))
	} else if p.DisableCompletePropagationRequirement {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
		logging.Warn("!!! DnsProvider: disableCompletePropagationRequirement is set: the DNS-01 TXT record is NOT verified before the CA validates it. Issuance may fail if the record has not propagated yet !!!")
	}

	return opts, dnsTimeout, nil
}

type propagationTimeoutProvider struct {
	challenge.Provider
	timeout  time.Duration
	interval time.Duration
}

func (p *propagationTimeoutProvider) Timeout() (time.Duration, time.Duration) {
	return p.timeout, p.interval
}

// overridePropagationTimeout keeps the provider's polling cadence while
// allowing the configured DNS timeout to extend lego's overall propagation
// wait. AddDNSTimeout separately applies the same value to individual DNS
// exchanges.
func overridePropagationTimeout(provider challenge.Provider, timeout time.Duration) challenge.Provider {
	interval := dns01.DefaultPollingInterval
	if timedProvider, ok := provider.(challenge.ProviderTimeout); ok {
		_, interval = timedProvider.Timeout()
	}

	return &propagationTimeoutProvider{
		Provider: provider,
		timeout:  timeout,
		interval: interval,
	}
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
