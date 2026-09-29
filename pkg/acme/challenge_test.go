package acme

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"pkg.para.party/certdx/pkg/config"
)

type timedDNSProviderStub struct{}

func (timedDNSProviderStub) Present(string, string, string) error { return nil }
func (timedDNSProviderStub) CleanUp(string, string, string) error { return nil }
func (timedDNSProviderStub) Timeout() (time.Duration, time.Duration) {
	return time.Minute, 3 * time.Second
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

// preCheckState applies the options to a throw-away lego challenge and
// reports the propagation requirements it ended up with, plus whether a
// custom pre-check (the conservative checker) replaced lego's own. The
// fields are unexported, but reflect can read them without going through
// Interface().
func preCheckState(t *testing.T, opts []dns01.ChallengeOption) (authoritative, recursive, wrapped bool) {
	t.Helper()
	chlg := dns01.NewChallenge(nil, nil, nil, opts...)
	preCheck := reflect.ValueOf(chlg).Elem().FieldByName("preCheck")
	if !preCheck.IsValid() {
		t.Fatal("dns01.Challenge has no preCheck field, lego internals changed")
	}
	return preCheck.FieldByName("requireAuthoritativeNssPropagation").Bool(),
		preCheck.FieldByName("requireRecursiveNssPropagation").Bool(),
		!preCheck.FieldByName("checkFunc").IsNil()
}

func TestDns01OptionsPropagationRequirements(t *testing.T) {
	cases := []struct {
		name              string
		provider          config.DnsProvider
		wantAuthoritative bool
		wantRecursive     bool
		wantWrapped       bool
	}{
		{
			name:              "defaults keep authoritative check",
			provider:          config.DnsProvider{},
			wantAuthoritative: true,
		},
		{
			name:              "nameservers alone do not add recursive check",
			provider:          config.DnsProvider{Nameservers: []string{"1.1.1.1"}},
			wantAuthoritative: true,
		},
		{
			name: "disabled authoritative check without nameservers",
			provider: config.DnsProvider{
				DisableCompletePropagationRequirement: true,
			},
		},
		{
			// The regression: disabling the authoritative requirement while
			// pointing lego at custom resolvers used to verify nothing at all.
			name: "disabled authoritative check with nameservers verifies on the resolvers",
			provider: config.DnsProvider{
				DisableCompletePropagationRequirement: true,
				Nameservers:                           []string{"1.1.1.1", "8.8.8.8:53"},
			},
			wantRecursive: true,
		},
		{
			// conservativeDnsCheck overrides the disable flag and replaces
			// lego's pre-check with its own authoritative check.
			name: "conservative check overrides disabled authoritative check",
			provider: config.DnsProvider{
				DisableCompletePropagationRequirement: true,
				ConservativeDNSCheck:                  true,
				Nameservers:                           []string{"1.1.1.1"},
			},
			wantAuthoritative: true,
			wantWrapped:       true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, err := dns01Options(&tc.provider)
			if err != nil {
				t.Fatalf("dns01Options: %v", err)
			}
			authoritative, recursive, wrapped := preCheckState(t, opts)
			if authoritative != tc.wantAuthoritative {
				t.Errorf("requireAuthoritativeNssPropagation=%v want %v", authoritative, tc.wantAuthoritative)
			}
			if recursive != tc.wantRecursive {
				t.Errorf("requireRecursiveNssPropagation=%v want %v", recursive, tc.wantRecursive)
			}
			if wrapped != tc.wantWrapped {
				t.Errorf("custom pre-check installed=%v want %v", wrapped, tc.wantWrapped)
			}
		})
	}
}

func TestDns01OptionsTimeout(t *testing.T) {
	_, timeout, err := dns01Options(&config.DnsProvider{})
	if err != nil {
		t.Fatalf("dns01Options: %v", err)
	}
	if timeout != 0 {
		t.Fatalf("unset dnsTimeout: got %s want 0", timeout)
	}

	_, timeout, err = dns01Options(&config.DnsProvider{DNSTimeout: "120s"})
	if err != nil {
		t.Fatalf("dns01Options: %v", err)
	}
	if timeout != 120*time.Second {
		t.Fatalf("dnsTimeout: got %s want %s", timeout, 120*time.Second)
	}

	if _, _, err := dns01Options(&config.DnsProvider{DNSTimeout: "not a duration"}); err == nil {
		t.Fatal("expected an error for an unparseable dnsTimeout")
	}
}

// TestGetChallengerTencentAlias checks the short "tencent" type still picks
// the Tencent Cloud DNS provider.
func TestGetChallengerTencentAlias(t *testing.T) {
	cfg := &config.ServerConfig{
		ACME: config.ACMEConfig{ChallengeType: config.ChallengeTypeDns01},
		DnsProvider: &config.DnsProvider{
			Type:      config.DnsProviderTypeTencent,
			SecretID:  "id",
			SecretKey: "key",
		},
	}
	typ, provider, err := getChallenger(nil, cfg)
	if err != nil {
		t.Fatalf("getChallenger: %v", err)
	}
	if typ != config.ChallengeTypeDns01 || provider == nil {
		t.Fatalf("getChallenger: got type %q provider %v", typ, provider)
	}
}
