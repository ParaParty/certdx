package acme

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	legoAliESA "github.com/go-acme/lego/v4/providers/dns/aliesa"
	"pkg.para.party/certdx/pkg/config"
)

type timedDNSProviderStub struct{}

func (timedDNSProviderStub) Present(string, string, string) error { return nil }
func (timedDNSProviderStub) CleanUp(string, string, string) error { return nil }
func (timedDNSProviderStub) Timeout() (time.Duration, time.Duration) {
	return time.Minute, 3 * time.Second
}

func TestDNS01Options(t *testing.T) {
	ns := []string{"1.1.1.1:53"}
	cases := []struct {
		name string
		p    config.DnsProvider
		want int
	}{
		{"defaults", config.DnsProvider{}, 0},
		// nameservers, disable authoritative check
		{"disabled with nameservers", config.DnsProvider{DisableCompletePropagationRequirement: true, Nameservers: ns}, 2},
		{"disabled without nameservers", config.DnsProvider{DisableCompletePropagationRequirement: true}, 1},
		// conservative check replaces the disable flag
		{"conservative wins", config.DnsProvider{DisableCompletePropagationRequirement: true, ConservativeDNSCheck: true}, 1},
	}
	for _, tc := range cases {
		opts, timeout, err := dns01Options(&tc.p)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(opts) != tc.want {
			t.Errorf("%s: %d options, want %d", tc.name, len(opts), tc.want)
		}
		if timeout != defaultConservativeDNSTimeout {
			t.Errorf("%s: timeout %s, want default", tc.name, timeout)
		}
	}

	opts, timeout, err := dns01Options(&config.DnsProvider{DNSTimeout: "2m"})
	if err != nil || len(opts) != 1 || timeout != 2*time.Minute {
		t.Fatalf("dnsTimeout: opts=%d timeout=%s err=%v", len(opts), timeout, err)
	}
	if _, _, err := dns01Options(&config.DnsProvider{DNSTimeout: "soon"}); err == nil {
		t.Fatal("expected error for an invalid dnsTimeout")
	}
}

func TestOverridePropagationTimeout(t *testing.T) {
	provider := overridePropagationTimeout(timedDNSProviderStub{}, 120*time.Second)
	timedProvider, ok := provider.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("overridden provider does not implement challenge.ProviderTimeout")
	}

	timeout, interval := timedProvider.Timeout()
	if timeout != 120*time.Second {
		t.Fatalf("propagation timeout: got %s want %s", timeout, 120*time.Second)
	}
	if interval != 3*time.Second {
		t.Fatalf("polling interval: got %s want %s", interval, 3*time.Second)
	}
}

func TestGetChallengerAliESA(t *testing.T) {
	cases := []struct {
		name     string
		provider config.DnsProvider
	}{
		{name: "default region", provider: config.DnsProvider{AccessKeyID: "test-id", AccessKeySecret: "test-secret"}},
		{name: "temporary credentials", provider: config.DnsProvider{AccessKeyID: "test-id", AccessKeySecret: "test-secret", SecurityToken: "test-token"}},
		{name: "custom region", provider: config.DnsProvider{AccessKeyID: "test-id", AccessKeySecret: "test-secret", RegionID: "ap-southeast-1"}},
		{name: "RAM role", provider: config.DnsProvider{RAMRole: "certdx-ecs-role"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.provider.Type = config.DnsProviderTypeAliESA
			cfg := &config.ServerConfig{
				ACME:        config.ACMEConfig{ChallengeType: config.ChallengeTypeDns01},
				DnsProvider: &testCase.provider,
			}
			typ, provider, err := getChallenger(&lego.Config{}, cfg)
			if err != nil {
				t.Fatalf("construct AliESA provider: %v", err)
			}
			if _, ok := provider.(*legoAliESA.DNSProvider); !ok || typ != config.ChallengeTypeDns01 {
				t.Fatalf("unexpected challenger: type=%q provider=%T", typ, provider)
			}
			if _, ok := provider.(challenge.ProviderTimeout); !ok {
				t.Fatal("AliESA provider does not implement challenge.ProviderTimeout")
			}
		})
	}
	if _, _, err := getChallenger(&lego.Config{}, &config.ServerConfig{
		ACME:        config.ACMEConfig{ChallengeType: config.ChallengeTypeDns01},
		DnsProvider: &config.DnsProvider{Type: config.DnsProviderTypeAliESA},
	}); err == nil {
		t.Fatal("expected an error for missing AliESA credentials")
	}
}

func TestGetChallengerAliDNS(t *testing.T) {
	for _, token := range []string{"", "test-token"} {
		cfg := &config.ServerConfig{
			ACME: config.ACMEConfig{ChallengeType: config.ChallengeTypeDns01},
			DnsProvider: &config.DnsProvider{
				Type:            config.DnsProviderTypeAliDNS,
				AccessKeyID:     "test-id",
				AccessKeySecret: "test-secret",
				SecurityToken:   token,
			},
		}
		typ, provider, err := getChallenger(&lego.Config{}, cfg)
		if err != nil {
			t.Fatalf("construct AliDNS provider: %v", err)
		}
		if typ != config.ChallengeTypeDns01 || provider == nil {
			t.Fatalf("unexpected challenger: type=%q provider=%T", typ, provider)
		}
	}
	cfg := &config.ServerConfig{
		ACME:        config.ACMEConfig{ChallengeType: config.ChallengeTypeDns01},
		DnsProvider: &config.DnsProvider{Type: config.DnsProviderTypeAliDNS, RAMRole: "certdx-ecs-role"},
	}
	if typ, provider, err := getChallenger(&lego.Config{}, cfg); err != nil || typ != config.ChallengeTypeDns01 || provider == nil {
		t.Fatalf("construct AliDNS RAM role provider: type=%q provider=%T err=%v", typ, provider, err)
	}
}
