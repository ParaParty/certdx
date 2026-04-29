//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// httpServerOpts builds a token-auth HTTP server config bound to port.
func httpServerOpts(port int, token, apiPath string) harness.ServerOpts {
	return harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		CertLifetime:   30 * time.Second,
		RenewTimeLeft:  16 * time.Second,
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", port),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "token",
		HTTPToken:      token,
	}
}

// startHTTPServer renders server.toml and spawns certdx_server, then waits
// for it to listen. Each call needs a unique tag so log files don't collide.
func startHTTPServer(t *testing.T, tag, dir string, port int, token, apiPath string) *harness.Process {
	t.Helper()
	harness.WriteServerConfig(t, dir, httpServerOpts(port, token, apiPath))
	p := harness.Start(t, tag, harness.ServerBin(t), dir, "-c", filepath.Join(dir, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("%s not listening: %s\n%s", tag, err, p.CombinedOutput())
	}
	return p
}

// TestHTTPMainToStandbyFailover: HTTP-mode client falls over to standby
// when main becomes unavailable.
func TestHTTPMainToStandbyFailover(t *testing.T) {
	cwd := t.TempDir()
	mainPort := harness.MustFreePort()
	standbyPort := harness.MustFreePort()
	const token = "failover-token"
	const apiPath = "/e2e"

	mainDir := filepath.Join(cwd, "main")
	standbyDir := filepath.Join(cwd, "standby")
	mainSrv := startHTTPServer(t, "main", mainDir, mainPort, token, apiPath)
	_ = startHTTPServer(t, "standby", standbyDir, standbyPort, token, apiPath)

	clientDir := filepath.Join(cwd, "client")
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)

	standby := harness.HTTPClientServer{
		URL:        fmt.Sprintf("http://127.0.0.1:%d%s", standbyPort, apiPath),
		AuthMethod: "token",
		Token:      token,
	}
	harness.WriteHTTPClientConfig(t, clientDir, harness.HTTPClientOpts{
		Main: harness.HTTPClientServer{
			URL:        fmt.Sprintf("http://127.0.0.1:%d%s", mainPort, apiPath),
			AuthMethod: "token",
			Token:      token,
		},
		Standby:      &standby,
		ReconnectInt: "2s",
		Certs: []harness.ClientCert{{
			Name:     "site",
			SavePath: saveDir,
			Domains:  []string{"example.test"},
		}},
	})

	_ = harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")

	certPath := filepath.Join(saveDir, "site.pem")
	first := harness.WaitForCertFile(t, certPath, 15*time.Second)
	t.Logf("first cert delivered (serial %s)", first.SerialNumber)

	mainSrv.Stop(2 * time.Second)
	t.Log("main server stopped")

	second := harness.WaitForCertChange(t, certPath, first, 30*time.Second)
	t.Logf("post-failover cert delivered (serial %s)", second.SerialNumber)
}

// TestHTTPFailoverThenFallback: after failover to standby, the client
// returns to main once it is reachable again. The HTTP client tries main
// first per poll cycle, so the next cycle after recovery is served by main.
func TestHTTPFailoverThenFallback(t *testing.T) {
	cwd := t.TempDir()
	mainPort := harness.MustFreePort()
	standbyPort := harness.MustFreePort()
	const token = "fallback-token"
	const apiPath = "/e2e"

	mainDir := filepath.Join(cwd, "main")
	standbyDir := filepath.Join(cwd, "standby")
	mainSrv := startHTTPServer(t, "main-1", mainDir, mainPort, token, apiPath)
	_ = startHTTPServer(t, "standby", standbyDir, standbyPort, token, apiPath)

	clientDir := filepath.Join(cwd, "client")
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)

	standby := harness.HTTPClientServer{
		URL:        fmt.Sprintf("http://127.0.0.1:%d%s", standbyPort, apiPath),
		AuthMethod: "token",
		Token:      token,
	}
	harness.WriteHTTPClientConfig(t, clientDir, harness.HTTPClientOpts{
		Main: harness.HTTPClientServer{
			URL:        fmt.Sprintf("http://127.0.0.1:%d%s", mainPort, apiPath),
			AuthMethod: "token",
			Token:      token,
		},
		Standby:      &standby,
		ReconnectInt: "2s",
		Certs: []harness.ClientCert{{
			Name:     "site",
			SavePath: saveDir,
			Domains:  []string{"example.test"},
		}},
	})

	_ = harness.Start(t, "client", harness.ClientBin(t), clientDir, "-c", filepath.Join(clientDir, "client.toml"), "-d")

	certPath := filepath.Join(saveDir, "site.pem")

	// Phase 1: main delivers the first cert.
	first := harness.WaitForCertFile(t, certPath, 15*time.Second)
	t.Logf("phase 1: main delivered cert (serial %s)", first.SerialNumber)

	// Phase 2: kill main, standby takes over.
	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	t.Log("phase 2: main stopped")
	second := harness.WaitForCertChange(t, certPath, first, 30*time.Second)
	t.Logf("phase 2: standby delivered cert (serial %s)", second.SerialNumber)

	// Phase 3: bring main back; client must fall back to it.
	_ = startHTTPServer(t, "main-2", mainDir, mainPort, token, apiPath)
	t.Log("phase 3: main restarted")
	third := harness.WaitForCertChange(t, certPath, second, 30*time.Second)
	t.Logf("phase 3: post-fallback cert delivered (serial %s)", third.SerialNumber)
}
