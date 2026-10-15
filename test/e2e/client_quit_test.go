//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

func writeHTTPQuitConfig(t *testing.T, serverURL string) (clientDir, certPath string) {
	t.Helper()
	clientDir = t.TempDir()
	saveDir := filepath.Join(clientDir, "saved")
	harness.EnsureDir(t, saveDir)
	harness.WriteHTTPClientConfig(t, clientDir, harness.HTTPClientOpts{
		Main: harness.HTTPClientServer{
			URL:        serverURL,
			AuthMethod: "token",
			Token:      "e2e-test-token",
		},
		RetryCount: 1,
		Certs: []harness.ClientCert{{
			Name: "site", SavePath: saveDir, Domains: []string{"example.test"},
		}},
	})
	return clientDir, filepath.Join(saveDir, "site.pem")
}

func TestHTTPClientQuitAfterFileAction(t *testing.T) {
	cwd := t.TempDir()
	port := harness.MustFreePort()
	const apiPath = "/e2e"

	harness.WriteServerConfig(t, cwd, harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		HTTPEnabled:    true,
		HTTPListen:     fmt.Sprintf(":%d", port),
		HTTPApiPath:    apiPath,
		HTTPAuth:       "token",
		HTTPToken:      "e2e-test-token",
	})
	server := harness.Start(t, "server", harness.ServerBin(t), cwd, "-c", filepath.Join(cwd, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("server not listening: %s\n%s", err, server.CombinedOutput())
	}

	clientDir, certPath := writeHTTPQuitConfig(t,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, apiPath))
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove stale certificate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, harness.ClientBin(t), "--quit", "-c", filepath.Join(clientDir, "client.toml"))
	cmd.Dir = clientDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client --quit: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("client --quit timed out: %v\n%s", ctx.Err(), output)
	}
	harness.WaitForCertFile(t, certPath, time.Second)
}

func TestHTTPClientQuitReturnsFailureWhenServerIsUnavailable(t *testing.T) {
	port := harness.MustFreePort()
	clientDir, _ := writeHTTPQuitConfig(t, fmt.Sprintf("http://127.0.0.1:%d/e2e", port))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, harness.ClientBin(t), "--quit", "-c", filepath.Join(clientDir, "client.toml"))
	cmd.Dir = clientDir
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("client --quit timed out: %v\n%s", ctx.Err(), output)
	}
	if err == nil || cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("client --quit exit = %v, want status 1\n%s", err, output)
	}
	if !strings.Contains(string(output), "all HTTP servers failed") {
		t.Fatalf("client --quit output = %s, want the HTTP failure", output)
	}
}

func TestGRPCClientQuitIsRejected(t *testing.T) {
	_, _, setup := setupGRPCFailover(t, grpcSetupOpts{NoStandby: true})
	setup.clientProc.Stop(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, harness.ClientBin(t), "--quit", "-c", filepath.Join(setup.clientDir, "client.toml"))
	cmd.Dir = setup.clientDir
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("client --quit timed out: %v\n%s", ctx.Err(), output)
	}
	if err == nil || cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("client --quit exit = %v, want status 1\n%s", err, output)
	}
	if !strings.Contains(string(output), "--quit is not supported in grpc mode") {
		t.Fatalf("client --quit output = %s, want gRPC rejection", output)
	}
}
