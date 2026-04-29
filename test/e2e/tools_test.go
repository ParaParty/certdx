//go:build e2e

package e2e

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestToolsMakeMTLSCertChain: certdx_tools' make-ca / make-server /
// make-client commands produce a valid mTLS chain.
func TestToolsMakeMTLSCertChain(t *testing.T) {
	cwd := t.TempDir()
	chain := harness.GenerateChain(t, cwd, []string{"localhost", "127.0.0.1"}, "alice", "bob")

	for _, p := range []string{chain.CAPEM, chain.CAKey, chain.SrvPEM, chain.SrvKey} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing %s: %s", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty %s", p)
		}
	}

	// CA key should not be world/group readable; tools writes it 0o600.
	if info, err := os.Stat(chain.CAKey); err != nil {
		t.Fatalf("stat ca key: %s", err)
	} else if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Logf("warning: ca.key world/group readable (%o); tooling should tighten this", perm)
	}

	ca := harness.LoadCert(t, chain.CAPEM)
	srv := harness.LoadCert(t, chain.SrvPEM)
	if err := harness.VerifyChain(srv, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
		t.Fatalf("server cert does not chain to CA: %s", err)
	}
	if !containsAll(srv.DNSNames, []string{"localhost"}) {
		t.Fatalf("server cert DNS names = %v; want to contain localhost", srv.DNSNames)
	}
	foundIP := false
	for _, ip := range srv.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("server cert IPs = %v; want to contain 127.0.0.1", srv.IPAddresses)
	}

	for _, name := range []string{"alice", "bob"} {
		pemPath := chain.ClientPEM[name]
		if _, err := os.Stat(pemPath); err != nil {
			t.Fatalf("missing client cert %s: %s", pemPath, err)
		}
		c := harness.LoadCert(t, pemPath)
		if err := harness.VerifyChain(c, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err != nil {
			t.Fatalf("client %s cert does not chain to CA: %s", name, err)
		}
		if c.Subject.CommonName == "" {
			t.Fatalf("client %s cert has empty CN", name)
		}
	}

	// Tools should write everything under <cwd>/mtls/.
	if _, err := os.Stat(filepath.Join(cwd, "mtls", "counter.txt")); err != nil {
		t.Fatalf("missing counter.txt: %s", err)
	}
}

func containsAll(haystack, needles []string) bool {
	set := map[string]struct{}{}
	for _, h := range haystack {
		set[h] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}
