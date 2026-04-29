//go:build e2e

package e2e

import (
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// gracefulStopTimeout caps how long SIGTERM may take before the shutdown
// path is considered broken.
const gracefulStopTimeout = 10 * time.Second

// assertGraceful sends SIGTERM and asserts exit within gracefulStopTimeout
// without falling back to SIGKILL.
func assertGraceful(t *testing.T, p *harness.Process, what string) {
	t.Helper()
	if !p.GracefulStop(gracefulStopTimeout) {
		t.Errorf("%s did not exit within %s of SIGTERM", what, gracefulStopTimeout)
	}
}

// TestGRPCServerGracefulStopWithClient: server exits cleanly on SIGTERM
// while a client has an active SDS stream.
func TestGRPCServerGracefulStopWithClient(t *testing.T) {
	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{})

	// Cert delivery proves the client has an open stream against main.
	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	assertGraceful(t, mainSrv, "main server")
}

// TestGRPCClientGracefulStop_MainRunning: main stream open, delivering certs.
func TestGRPCClientGracefulStop_MainRunning(t *testing.T) {
	_, _, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	assertGraceful(t, s.clientProc, "client (state=MAIN)")
}

// TestGRPCClientGracefulStop_MainRetrySleep: stops the client inside the
// main goroutine's 15s retry-window sleep (pre-failover).
func TestGRPCClientGracefulStop_MainRetrySleep(t *testing.T) {
	if testing.Short() {
		t.Skip("hits hard-coded 15s sleep; skipping in -short mode")
	}

	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 3, ReconnectInt: "120s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	// 3s lands inside the 15s retry-window branch.
	time.Sleep(3 * time.Second)

	assertGraceful(t, s.clientProc, "client (state=MAIN retry sleep)")
}

// TestGRPCClientGracefulStop_StandbyRunning: FAILOVER state with standby
// streaming; TRY_FALLBACK and RESTART_MAIN goroutines parked.
func TestGRPCClientGracefulStop_StandbyRunning(t *testing.T) {
	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 1, ReconnectInt: "120s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}

	// Standby delivery confirms FAILOVER with all auxiliary goroutines alive.
	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	if tag := certTag(got); tag != tagStandby {
		t.Fatalf("expected failover cert tag %q, got %q", tagStandby, tag)
	}

	assertGraceful(t, s.clientProc, "client (state=FAILOVER, standby streaming)")
}

// TestGRPCClientGracefulStop_StandbyRetrySleep: stops the client while the
// standby goroutine is in its 15s retry-window sleep.
func TestGRPCClientGracefulStop_StandbyRetrySleep(t *testing.T) {
	if testing.Short() {
		t.Skip("hits hard-coded 15s sleep; skipping in -short mode")
	}

	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 3, ReconnectInt: "120s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	// Main retries 2×15s → FAILOVER at ~30s, then standby's 15s retry runs
	// 30–45s. 35s lands inside that window.
	time.Sleep(35 * time.Second)

	assertGraceful(t, s.clientProc, "client (state=standby retry sleep)")
}

// TestGRPCClientGracefulStop_StandbyReconnectSleep: stops the client while
// the standby goroutine is in its ReconnectInterval sleep (RetryCount=1
// skips the 15s retry branch).
func TestGRPCClientGracefulStop_StandbyReconnectSleep(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 1, ReconnectInt: "60s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	// FAILOVER is entered immediately; standby's first dial fails into the
	// 60s ReconnectInterval sleep. 5s lands inside that window.
	time.Sleep(5 * time.Second)

	assertGraceful(t, s.clientProc, "client (state=standby ReconnectInterval sleep)")
}

// TestGRPCClientGracefulStop_BothDownConcurrentRetry: stops the client
// with both servers down and four goroutines (main, standby, TRY_FALLBACK,
// RESTART_MAIN) concurrently parked in select/sleep. ReconnectInt=60s
// ensures no timer fires; only stopChan/resetChan can release them.
func TestGRPCClientGracefulStop_BothDownConcurrentRetry(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 1, ReconnectInt: "60s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	// 8s is enough for FAILOVER to spawn standby/TRY_FALLBACK/RESTART_MAIN
	// and for all four to settle into their 60s sleeps.
	time.Sleep(8 * time.Second)

	assertGraceful(t, s.clientProc, "client (state=both down, concurrent retry)")
}

// TestGRPCClientGracefulStop_MainAndStandbyBothRunning: stops the client
// with the standby goroutine streaming and the main goroutine parked in
// its 15s retry-sleep. A TCP tarpit on the main port makes Stream() fail
// fast (so it settles into retry-sleep) without ever delivering a cert
// (which would let TRY_FALLBACK kill the standby).
func TestGRPCClientGracefulStop_MainAndStandbyBothRunning(t *testing.T) {
	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 2, ReconnectInt: "3s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	// Phase 1: kill main, wait until standby is streaming.
	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	if tag := certTag(got); tag != tagStandby {
		t.Fatalf("expected failover cert tag %q, got %q", tagStandby, tag)
	}

	// Phase 2: tarpit on main port. RESTART_MAIN ticks every 3s, dials the
	// tarpit, gets EOF, and parks the main goroutine in its retry-sleep.
	harness.StartTarpit(t, s.mainPort)
	time.Sleep(6 * time.Second)

	assertGraceful(t, s.clientProc, "client (main retry-sleep + standby streaming)")
}

// State-machine coverage matrix:
//
//	MAIN     Stream() recv              : MainRunning
//	MAIN     retry sleep                : MainRetrySleep
//	FAILOVER Stream() recv              : StandbyRunning
//	FAILOVER retry sleep                : StandbyRetrySleep
//	FAILOVER ReconnectInterval sleep    : StandbyReconnectSleep
//	TRY_FALLBACK / RESTART_MAIN parked  : StandbyRunning (concurrent)
//	main + standby goroutines alive     : MainAndStandbyBothRunning
//	all four goroutines parked          : BothDownConcurrentRetry
//	no-standby RESTART_MAIN sleep       : NoStandbyRestartSleep

// TestGRPCClientGracefulStop_NoStandbyRestartSleep: no standby configured;
// main retry exhaustion routes into RESTART_MAIN's ReconnectInterval sleep,
// which SIGTERM must wake via resetChan.
func TestGRPCClientGracefulStop_NoStandbyRestartSleep(t *testing.T) {
	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{
		RetryCount:   1,
		ReconnectInt: "60s",
		NoStandby:    true,
	})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("expected baseline cert tag %q, got %q", tagMain, tag)
	}

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	// RetryCount=1 → straight into RESTART_MAIN's 60s sleep.
	time.Sleep(3 * time.Second)

	assertGraceful(t, s.clientProc, "client (state=no-standby RESTART_MAIN sleep)")
}
