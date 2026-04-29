//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestHTTPTokenAuth: basic HTTP token-authenticated cert delivery.
func TestHTTPTokenAuth(t *testing.T) {
	cwd := t.TempDir()
	port := harness.MustFreePort()
	const token = "e2e-test-token"
	const apiPath = "/e2e"

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", port),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "token",
		HTTPSecure:     false,
		HTTPToken:      token,
	})

	srv := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, srv.CombinedOutput())
	}

	clientDir := filepath.Join(cwd, "client")
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)

	harness.WriteHTTPClientConfig(t, clientDir, harness.HTTPClientOpts{
		Main: harness.HTTPClientServer{
			URL:        fmt.Sprintf("http://127.0.0.1:%d%s", port, apiPath),
			AuthMethod: "token",
			Token:      token,
		},
		Certs: []harness.ClientCert{{
			Name:     "site",
			SavePath: saveDir,
			Domains:  []string{"example.test"},
		}},
	})

	cli := harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")
	_ = cli

	certPath := filepath.Join(saveDir, "site.pem")
	cert := harness.WaitForCertFile(t, certPath, 15*time.Second)

	found := false
	for _, n := range cert.DNSNames {
		if n == "example.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("delivered cert DNS names = %v; want example.test", cert.DNSNames)
	}
}
