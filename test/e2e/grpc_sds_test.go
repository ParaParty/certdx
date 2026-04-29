//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestGRPCSDS: cert delivery via the gRPC SDS streaming mode under mTLS.
func TestGRPCSDS(t *testing.T) {
	cwd := t.TempDir()
	port := harness.MustFreePort()

	chain := harness.GenerateChain(t, cwd, []string{"localhost", "127.0.0.1"}, "grpcclient")

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
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

	cli := harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")
	_ = cli

	certPath := filepath.Join(saveDir, "site.pem")
	cert := harness.WaitForCertFile(t, certPath, 20*time.Second)
	found := false
	for _, n := range cert.DNSNames {
		if n == "example.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("delivered cert DNS = %v; want example.test", cert.DNSNames)
	}
}
