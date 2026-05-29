//go:build e2e

package harness

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// MTLSChain holds the absolute paths of an mTLS chain produced by certdx_tools.
type MTLSChain struct {
	// Dir is the working directory tools were run in. Chain files live
	// under <Dir>/mtls/.
	Dir string

	CABundle  string // ca.pem bundle (CA cert + CA key)
	SrvBundle string // server bundle (server cert + key + CA cert)

	// ClientBundle is keyed by client name (see GenerateChain).
	ClientBundle map[string]string
}

// GenerateChain runs certdx_tools make-ca, make-server and one make-client
// per name in cwd, returning the resulting chain. Server SANs default to
// ["localhost", "127.0.0.1"]. The server bundle is named "server".
func GenerateChain(tb testing.TB, cwd string, serverDNS []string, clientNames ...string) *MTLSChain {
	tb.Helper()

	if len(serverDNS) == 0 {
		serverDNS = []string{"localhost", "127.0.0.1"}
	}

	// Tools resolve mtls/ under --data-dir, so pass <cwd> explicitly.
	// This isolates each test from the shared tools binary's exe-adjacent
	// default and removes the need to pre-create <cwd>/mtls.

	// Trigger the (potentially slow, one-shot) binary build before
	// starting the per-command context timer; on a cold CI runner the
	// initial `go build` of all binaries can otherwise consume the
	// entire 30s budget.
	ToolsBin(tb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if out, err := RunTool(ctx, tb, cwd, "make-ca", "--data-dir", cwd, "-o", "CertDX E2E", "-c", "CertDX E2E CA"); err != nil {
		tb.Fatalf("make-ca: %s\n%s", err, out)
	}

	dnsArg := joinDNS(serverDNS)
	if out, err := RunTool(ctx, tb, cwd, "make-server", "--data-dir", cwd, "-n", "server", "-d", dnsArg, "-o", "CertDX E2E"); err != nil {
		tb.Fatalf("make-server: %s\n%s", err, out)
	}

	chain := &MTLSChain{
		Dir:          cwd,
		CABundle:     filepath.Join(cwd, "mtls", "ca.pem"),
		SrvBundle:    filepath.Join(cwd, "mtls", "server.pem"),
		ClientBundle: map[string]string{},
	}

	for _, name := range clientNames {
		if out, err := RunTool(ctx, tb, cwd, "make-client", "--data-dir", cwd, "-n", name, "-o", "CertDX E2E"); err != nil {
			tb.Fatalf("make-client %s: %s\n%s", name, err, out)
		}
		chain.ClientBundle[name] = filepath.Join(cwd, "mtls", name+".pem")
	}

	return chain
}

func joinDNS(names []string) string {
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ","
		}
		s += n
	}
	return s
}

// LoadCert reads and parses the PEM-encoded x509 certificate at path.
func LoadCert(tb testing.TB, path string) *x509.Certificate {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %s", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		tb.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tb.Fatalf("parse %s: %s", path, err)
	}
	return cert
}

// VerifyChain verifies that leaf chains to ca with the given extended key
// usages.
func VerifyChain(leaf, ca *x509.Certificate, usages []x509.ExtKeyUsage) error {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: usages,
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

// LinkMTLSInto symlinks <dst>/mtls to the chain's mtls dir so a server with
// cwd=dst resolves its CA/server cert/keys via the shared chain. Used to
// share one chain across multiple gRPC server instances.
func LinkMTLSInto(tb testing.TB, chain *MTLSChain, dst string) {
	tb.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		tb.Fatalf("mkdir %s: %s", dst, err)
	}
	link := filepath.Join(dst, "mtls")
	src := filepath.Join(chain.Dir, "mtls")
	if _, err := os.Lstat(link); err == nil {
		return
	}
	if err := os.Symlink(src, link); err != nil {
		tb.Fatalf("symlink %s -> %s: %s", link, src, err)
	}
}
