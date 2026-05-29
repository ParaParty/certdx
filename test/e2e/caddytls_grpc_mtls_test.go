//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestCaddyTLS_GRPCMTLS exercises the exec/caddytls plugin in gRPC + mTLS
// mode. It builds a real caddy binary with the plugin via xcaddy, points
// it at a live certdx_server over an mTLS-protected gRPC stream, and
// verifies that a TLS handshake against caddy returns a cert whose SANs
// match the configured domain.
func TestCaddyTLS_GRPCMTLS(t *testing.T) {
	cwd := t.TempDir()
	serverPort := harness.MustFreePort()
	caddyPort := harness.MustFreePort()
	const domain = "caddy-grpc.test"

	chain := harness.GenerateChain(t, cwd, []string{"localhost", "127.0.0.1"}, "caddyclient")

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{domain},
		GRPCEnabled:    true,
		GRPCListen:     fmt.Sprintf(":%d", serverPort),
		MTLSPEM:        chain.SrvBundle,
	})
	srv := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", serverPort, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, srv.CombinedOutput())
	}

	caddyDir := filepath.Join(cwd, "caddy")
	harness.EnsureDir(t, caddyDir)
	harness.WriteCaddyfile(t, caddyDir, harness.CaddyfileOpts{
		Mode:              "grpc",
		ReconnectInterval: "10s",
		GRPC: &harness.CaddyfileGRPCServer{
			Server: fmt.Sprintf("localhost:%d", serverPort),
			PEM:    chain.ClientBundle["caddyclient"],
		},
		Certificates: []harness.CaddyfileCertEntry{{
			ID:      "site",
			Domains: []string{domain},
		}},
		Sites: []harness.CaddyfileSite{{
			Domain: domain,
			Port:   caddyPort,
			CertID: "site",
		}},
	})
	caddyProc := harness.Start(t, "caddy", harness.CaddyBin(t), caddyDir,
		"run", "--config", filepath.Join(caddyDir, "Caddyfile"), "--adapter", "caddyfile")
	if err := harness.WaitListening("127.0.0.1", caddyPort, 30*time.Second); err != nil {
		t.Fatalf("caddy not listening: %s\n%s", err, caddyProc.CombinedOutput())
	}

	addr := fmt.Sprintf("127.0.0.1:%d", caddyPort)
	cert := harness.WaitForTLSCert(t, addr, domain, nil, 30*time.Second)

	found := false
	for _, n := range cert.DNSNames {
		if n == domain {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("served cert DNS = %v; want %s\n%s", cert.DNSNames, domain, caddyProc.CombinedOutput())
	}
}
