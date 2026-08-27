package acme

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
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
