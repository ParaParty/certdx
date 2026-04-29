//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// renewalTimings yields cert lifetime / renew-time-left / wait values short
// enough for tests but long enough to avoid flakes. Renewal cadence is
// RenewTimeLeft/4 ≈ 4s, so a renewal arrives ~4-8s after first delivery.
func renewalTimings() (lifetime, renewTimeLeft, wait time.Duration) {
	return 30 * time.Second, 16 * time.Second, 25 * time.Second
}

// TestCertRenewalHTTP: client receives a renewed cert via HTTP polling.
func TestCertRenewalHTTP(t *testing.T) {
	cwd := t.TempDir()
	port := harness.MustFreePort()
	const token = "renewal-token"
	const apiPath = "/e2e"
	lifetime, renewLeft, wait := renewalTimings()

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		CertLifetime:   lifetime,
		RenewTimeLeft:  renewLeft,
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", port),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "token",
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

	_ = harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")

	certPath := filepath.Join(saveDir, "site.pem")
	first := harness.WaitForCertFile(t, certPath, 15*time.Second)
	t.Logf("first cert serial: %s", first.SerialNumber)

	second := harness.WaitForCertChange(t, certPath, first, wait)
	t.Logf("renewed cert serial: %s", second.SerialNumber)
}

// TestCertRenewalGRPC: client receives a renewed cert via gRPC SDS push.
func TestCertRenewalGRPC(t *testing.T) {
	cwd := t.TempDir()
	port := harness.MustFreePort()
	lifetime, renewLeft, wait := renewalTimings()

	chain := harness.GenerateChain(t, cwd, []string{"localhost", "127.0.0.1"}, "grpcclient")

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		CertLifetime:   lifetime,
		RenewTimeLeft:  renewLeft,
		GRPCEnabled:    true,
		GRPCListen:     fmt.Sprintf(":%d", port),
		GRPCNames:      []string{"localhost"},
	})

	srv := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, srv.CombinedOutput())
	}

	clientDir := filepath.Join(cwd, "client")
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)

	harness.WriteGRPCClientConfig(t, clientDir, harness.GRPCClientOpts{
		Main: harness.GRPCClientServer{
			Server: fmt.Sprintf("localhost:%d", port),
			CA:     chain.CAPEM,
			Cert:   chain.ClientPEM["grpcclient"],
			Key:    chain.ClientKey["grpcclient"],
		},
		Certs: []harness.ClientCert{{
			Name:     "site",
			SavePath: saveDir,
			Domains:  []string{"example.test"},
		}},
	})

	_ = harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")

	certPath := filepath.Join(saveDir, "site.pem")
	first := harness.WaitForCertFile(t, certPath, 20*time.Second)
	t.Logf("first cert serial: %s", first.SerialNumber)

	second := harness.WaitForCertChange(t, certPath, first, wait)
	t.Logf("renewed cert serial: %s", second.SerialNumber)
}
