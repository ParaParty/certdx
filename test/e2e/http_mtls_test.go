//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestHTTPMutualTLS: HTTPS + mTLS client-cert authenticated cert delivery.
func TestHTTPMutualTLS(t *testing.T) {
	cwd := t.TempDir()
	chainDir := t.TempDir()
	port := harness.MustFreePort()
	const apiPath = "/e2e"

	chain := harness.GenerateChain(t, chainDir, []string{"localhost", "127.0.0.1"}, "client1")

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test", "localhost"},
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", port),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "mtls",
		HTTPNames:      []string{"localhost"},
	})

	srv := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "--mtls-dir", filepath.Join(chainDir, "mtls"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, srv.CombinedOutput())
	}

	clientDir := filepath.Join(cwd, "client")
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)

	harness.WriteHTTPClientConfig(t, clientDir, harness.HTTPClientOpts{
		Main: harness.HTTPClientServer{
			URL:        fmt.Sprintf("https://localhost:%d%s", port, apiPath),
			AuthMethod: "mtls",
			CA:         chain.CAPEM,
			Cert:       chain.ClientPEM["client1"],
			Key:        chain.ClientKey["client1"],
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
	harness.WaitForCertFile(t, certPath, 15*time.Second)

	t.Run("rejects connection without client cert", func(t *testing.T) {
		caPEM, err := os.ReadFile(chain.CAPEM)
		if err != nil {
			t.Fatalf("read CA: %s", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatalf("append CA")
		}
		c := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					ServerName: "localhost",
					MinVersion: tls.VersionTLS13,
				},
			},
		}
		resp, err := c.Post(fmt.Sprintf("https://localhost:%d%s", port, apiPath), "application/json", strings.NewReader(`{"domains":["example.test"]}`))
		if err == nil {
			resp.Body.Close()
			t.Fatalf("request without client cert succeeded with status %d; expected TLS handshake failure", resp.StatusCode)
		}
	})
}
