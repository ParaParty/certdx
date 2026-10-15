//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

func TestGRPCClientQuitAfterFileAction(t *testing.T) {
	_, _, setup := setupGRPCFailover(t, grpcSetupOpts{NoStandby: true})
	setup.clientProc.Stop(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, harness.ClientBin(t), "--quit", "-c", filepath.Join(setup.clientDir, "client.toml"))
	cmd.Dir = setup.clientDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client --quit: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("client --quit timed out: %v\n%s", ctx.Err(), output)
	}
	harness.WaitForCertFile(t, setup.certPath, time.Second)
}

func TestGRPCClientQuitReturnsFailureWhenServerIsUnavailable(t *testing.T) {
	server, _, setup := setupGRPCFailover(t, grpcSetupOpts{NoStandby: true})
	setup.clientProc.Stop(3 * time.Second)
	server.Stop(3 * time.Second)

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
}
