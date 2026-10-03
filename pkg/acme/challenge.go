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
		opt, timeout, err := dns01Options(p.DnsProvider)
		if err != nil {
			return err
		}
		if timeout > 0 {
			clg = overridePropagationTimeout(clg, timeout)
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

// dns01Options translates the [DnsProvider] config block into lego
// challenge options. It also returns the parsed dnsTimeout (zero when
// unset) so the caller can stretch the provider's overall propagation wait
// to it.
//
// Note on nameservers: lego's default pre-check only uses the recursive
// resolvers for zone / CNAME discovery, the TXT value itself is verified
// against the authoritative nameservers. So once the authoritative
// requirement is disabled, no TXT verification happens at all — the
// configured resolvers are never asked for the record.
// RecursiveNSsPropagationRequirement puts the verification back on them.
// With the authoritative check still on the record is already verified, so
// requiring it twice would only slow issuance down.
//
// conservativeDnsCheck replaces lego's pre-check and always checks every
// authoritative server, so it overrides disableCompletePropagationRequirement.
func dns01Options(p *config.DnsProvider) ([]dns01.ChallengeOption, time.Duration, error) {
	opt := make([]dns01.ChallengeOption, 0)
	dnsTimeout := defaultConservativeDNSTimeout

	disableAuthoritative := p.DisableCompletePropagationRequirement && !p.ConservativeDNSCheck
	if disableAuthoritative {
		opt = append(opt, dns01.DisableAuthoritativeNssPropagationRequirement())
		if len(p.Nameservers) == 0 {
			logging.Warn("DnsProvider: disableCompletePropagationRequirement is set without nameservers, " +
				"the TXT record is not verified at all before the CA is asked to validate")
		}
	}

	// 添加自定义 DNS 服务器
	if len(p.Nameservers) > 0 {
		opt = append(opt, dns01.AddRecursiveNameservers(p.Nameservers))
		if disableAuthoritative {
			opt = append(opt, dns01.RecursiveNSsPropagationRequirement())
		}
	}

	// 添加 DNS 超时
	var timeout time.Duration
	if p.DNSTimeout != "" {
		var err error
		timeout, err = time.ParseDuration(p.DNSTimeout)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid dnsTimeout %q: %w", p.DNSTimeout, err)
		}
		dnsTimeout = timeout
		opt = append(opt, dns01.AddDNSTimeout(timeout))
	}

	if p.ConservativeDNSCheck {
		checker := newConservativeChecker(p.Nameservers, dnsTimeout)
		opt = append(opt, dns01.WrapPreCheck(checker.Wrap))
	}

	return opt, timeout, nil
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
		case config.DnsProviderTypeTencentCloud, config.DnsProviderTypeTencent:
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
