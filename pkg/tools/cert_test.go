package tools

import (
	"net"
	"testing"
)

func TestSplitIPsAndDNS(t *testing.T) {
	dns, ips := splitIPsAndDNS([]string{
		"example.com",
		"127.0.0.1",
		"api.example.com",
		"::1",
	})

	if got, want := len(dns), 2; got != want {
		t.Fatalf("dns count = %d, want %d: %v", got, want, dns)
	}
	if dns[0] != "example.com" || dns[1] != "api.example.com" {
		t.Fatalf("unexpected dns names: %v", dns)
	}

	wantIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if got, want := len(ips), len(wantIPs); got != want {
		t.Fatalf("ip count = %d, want %d: %v", got, want, ips)
	}
	for i := range wantIPs {
		if !ips[i].Equal(wantIPs[i]) {
			t.Fatalf("ip[%d] = %v, want %v", i, ips[i], wantIPs[i])
		}
	}
}
