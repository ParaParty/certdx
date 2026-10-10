package acme

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
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
