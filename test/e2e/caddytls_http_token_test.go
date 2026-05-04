//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestCaddyTLS_HTTPToken exercises the exec/caddytls plugin in HTTP +
// token-auth mode. It builds a real caddy binary with the plugin via
// xcaddy, points it at a live certdx_server, and verifies that a TLS
// handshake against caddy returns a cert whose SANs match the configured
// domain — proof that the plugin's get_certificate callback was invoked
// and the cert was delivered through the certdx pipeline.
func TestCaddyTLS_HTTPToken(t *testing.T) {
	cwd := t.TempDir()
	serverPort := harness.MustFreePort()
	caddyPort := harness.MustFreePort()
	const token = "caddytls-e2e-token"
	const apiPath = "/e2e"
	const domain = "caddy-http.test"

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{domain},
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", serverPort),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "token",
		HTTPSecure:     false,
		HTTPToken:      token,
	})
	srv := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", serverPort, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, srv.CombinedOutput())
	}

	caddyDir := filepath.Join(cwd, "caddy")
	harness.EnsureDir(t, caddyDir)
	harness.WriteCaddyfile(t, caddyDir, harness.CaddyfileOpts{
		Mode: "http",
		HTTP: &harness.CaddyfileHTTPServer{
			URL:        fmt.Sprintf("http://127.0.0.1:%d%s", serverPort, apiPath),
			AuthMethod: "token",
			Token:      token,
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
