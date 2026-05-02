//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	assertPerm(t, filepath.Join(cwd, "mtls"), 0o700)
	assertPerm(t, chain.CAPEM, 0o644)
	assertPerm(t, chain.CAKey, 0o600)
	assertPerm(t, chain.SrvPEM, 0o644)
	assertPerm(t, chain.SrvKey, 0o600)
	for name := range chain.ClientPEM {
		assertPerm(t, chain.ClientPEM[name], 0o644)
		assertPerm(t, chain.ClientKey[name], 0o600)
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

func TestToolsMakeClientRejectsReservedMTLSNames(t *testing.T) {
	cwd := t.TempDir()
	chain := harness.GenerateChain(t, cwd, []string{"localhost"})
	originalCA := mustReadFile(t, chain.CAPEM)
	originalServer := mustReadFile(t, chain.SrvPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, name := range []string{"ca", "server"} {
		out, err := harness.RunTool(ctx, t, cwd, "make-client", "-n", name, "-o", "CertDX E2E")
		if err == nil {
			t.Fatalf("make-client %q succeeded; output:\n%s", name, out)
		}
		if !strings.Contains(out, "reserved") {
			t.Fatalf("make-client %q output = %q; want reserved-name error", name, out)
		}
	}

	if got := mustReadFile(t, chain.CAPEM); string(got) != string(originalCA) {
		t.Fatalf("ca.pem changed after reserved-name make-client")
	}
	if got := mustReadFile(t, chain.SrvPEM); string(got) != string(originalServer) {
		t.Fatalf("server.pem changed after reserved-name make-client")
	}
}

func TestToolsMTLSDirFlagOverride(t *testing.T) {
	cwd := t.TempDir()
	mtlsDir := filepath.Join(t.TempDir(), "flag-mtls")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if out, err := harness.RunTool(ctx, t, cwd, "make-ca", "--mtls-dir", mtlsDir, "-o", "CertDX E2E", "-c", "CertDX E2E CA"); err != nil {
		t.Fatalf("make-ca with --mtls-dir: %s\n%s", err, out)
	}
	if out, err := harness.RunTool(ctx, t, cwd, "make-server", "--mtls-dir", mtlsDir, "-d", "localhost", "-o", "CertDX E2E"); err != nil {
		t.Fatalf("make-server with --mtls-dir: %s\n%s", err, out)
	}
	if out, err := harness.RunTool(ctx, t, cwd, "make-client", "--mtls-dir", mtlsDir, "-n", "alice", "-o", "CertDX E2E"); err != nil {
		t.Fatalf("make-client with --mtls-dir: %s\n%s", err, out)
	}

	assertMTLSLayout(t, mtlsDir, "alice")
	if _, err := os.Stat(filepath.Join(cwd, "mtls")); !os.IsNotExist(err) {
		t.Fatalf("cwd mtls dir exists after --mtls-dir override: %v", err)
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

func assertMTLSLayout(t *testing.T, mtlsDir string, clientName string) {
	t.Helper()
	assertPerm(t, mtlsDir, 0o700)
	assertPerm(t, filepath.Join(mtlsDir, "ca.pem"), 0o644)
	assertPerm(t, filepath.Join(mtlsDir, "ca.key"), 0o600)
	assertPerm(t, filepath.Join(mtlsDir, "server.pem"), 0o644)
	assertPerm(t, filepath.Join(mtlsDir, "server.key"), 0o600)
	assertPerm(t, filepath.Join(mtlsDir, clientName+".pem"), 0o644)
	assertPerm(t, filepath.Join(mtlsDir, clientName+".key"), 0o600)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %s", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o; want %o", path, got, want)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %s", path, err)
	}
	return data
}
