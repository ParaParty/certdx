//go:build e2e

package e2e

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/test/e2e/harness"
)

// mockACMETagEnv is the env var read by pkg/acme.MockACME to tag minted
// certs via Subject.OrganizationalUnit. Duplicated as a literal to avoid
// pulling lego deps into the test/e2e module; must match acme.MockACMETagEnv.
const mockACMETagEnv = "CERTDX_MOCK_TAG"

// Tags embedded into Subject.OrganizationalUnit by the mock ACME so tests
// can identify the originating server from the cert file alone.
const (
	tagMain    = "main"
	tagStandby = "standby"
)

// certTag returns the first OU of the cert subject (set from $CERTDX_MOCK_TAG).
func certTag(c *x509.Certificate) string {
	if len(c.Subject.OrganizationalUnit) == 0 {
		return ""
	}
	return c.Subject.OrganizationalUnit[0]
}

// grpcServerOpts builds a gRPC SDS server config bound to port. Short
// timings keep tests fast.
func grpcServerOpts(port int) harness.ServerOpts {
	return harness.ServerOpts{
		AllowedDomains: []string{"example.test"},
		CertLifetime:   30 * time.Second,
		RenewTimeLeft:  16 * time.Second,
		GRPCEnabled:    true,
		GRPCListen:     fmt.Sprintf(":%d", port),
		GRPCNames:      []string{"localhost"},
	}
}

// startGRPCServer renders server.toml and spawns certdx_server with the
// given mock-cert tag, then waits for it to listen.
func startGRPCServer(t *testing.T, logTag, tag, dir string, port int) *harness.Process {
	t.Helper()
	harness.WriteServerConfig(t, dir, grpcServerOpts(port))
	env := []string{mockACMETagEnv + "=" + tag}
	p := harness.StartEnv(t, logTag, harness.ServerBin(t), dir, env, "-c", filepath.Join(dir, "server.toml"), "-d")
	if err := harness.WaitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("%s not listening: %s\n%s", logTag, err, p.CombinedOutput())
	}
	return p
}

// grpcSetup holds the artifacts of a main+standby+client gRPC test setup.
type grpcSetup struct {
	chain       *harness.MTLSChain
	mainDir     string
	standbyDir  string
	mainPort    int
	standbyPort int
	clientDir   string
	saveDir     string
	certPath    string
	clientProc  *harness.Process
}

// grpcSetupOpts tunes the failover setup. Zero-valued fields use defaults.
type grpcSetupOpts struct {
	RetryCount   int    // default 1
	ReconnectInt string // default "3s"
	NoStandby    bool   // omit standby from client config
}

// setupGRPCFailover spawns a main + standby gRPC server pair sharing one
// mTLS chain, plus a gRPC-mode client wired to both. With opts.NoStandby,
// no standby is spawned and standbySrv is nil.
func setupGRPCFailover(t *testing.T, opts grpcSetupOpts) (mainSrv, standbySrv *harness.Process, s *grpcSetup) {
	t.Helper()
	if opts.RetryCount == 0 {
		opts.RetryCount = 1
	}
	if opts.ReconnectInt == "" {
		opts.ReconnectInt = "3s"
	}

	cwd := t.TempDir()
	s = &grpcSetup{
		mainPort: harness.MustFreePort(),
	}
	if !opts.NoStandby {
		s.standbyPort = harness.MustFreePort()
	}
	s.chain = harness.GenerateChain(t, cwd, []string{"localhost", "127.0.0.1"}, "grpcclient")
	s.mainDir = filepath.Join(cwd, "main")
	harness.LinkMTLSInto(t, s.chain, s.mainDir)
	mainSrv = startGRPCServer(t, "main-0", tagMain, s.mainDir, s.mainPort)

	var standbyCfg *harness.GRPCClientServer
	if !opts.NoStandby {
		s.standbyDir = filepath.Join(cwd, "standby")
		harness.LinkMTLSInto(t, s.chain, s.standbyDir)
		standbySrv = startGRPCServer(t, "standby-0", tagStandby, s.standbyDir, s.standbyPort)
		standbyCfg = &harness.GRPCClientServer{
			Server: fmt.Sprintf("localhost:%d", s.standbyPort),
			CA:     s.chain.CAPEM,
			Cert:   s.chain.ClientPEM["grpcclient"],
			Key:    s.chain.ClientKey["grpcclient"],
		}
	}

	s.clientDir = filepath.Join(cwd, "client")
	s.saveDir = filepath.Join(s.clientDir, "saved")
	harness.EnsureDir(t, s.saveDir)

	harness.WriteGRPCClientConfig(t, s.clientDir, harness.GRPCClientOpts{
		Main: harness.GRPCClientServer{
			Server: fmt.Sprintf("localhost:%d", s.mainPort),
			CA:     s.chain.CAPEM,
			Cert:   s.chain.ClientPEM["grpcclient"],
			Key:    s.chain.ClientKey["grpcclient"],
		},
		Standby:      standbyCfg,
		RetryCount:   opts.RetryCount,
		ReconnectInt: opts.ReconnectInt,
		Certs: []harness.ClientCert{{
			Name:     "site",
			SavePath: s.saveDir,
			Domains:  []string{"example.test"},
		}},
	})

	s.clientProc = harness.Start(t, "client", harness.ClientBin(t), s.clientDir, "-c", filepath.Join(s.clientDir, "client.toml"), "-d")
	s.certPath = filepath.Join(s.saveDir, "site.pem")
	return
}

// killBoth stops main + standby and waits for both ports to free.
func killBoth(t *testing.T, mainSrv, standbySrv *harness.Process, mainPort, standbyPort int) {
	t.Helper()
	mainSrv.Stop(2 * time.Second)
	standbySrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	if err := harness.WaitNotListening("127.0.0.1", standbyPort, 5*time.Second); err != nil {
		t.Fatalf("standby port did not free: %s", err)
	}
}

// TestGRPCFailoverThenFallback: gRPC client falls over to standby when main
// is killed, then back to main once it returns.
func TestGRPCFailoverThenFallback(t *testing.T) {
	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("phase 1: main delivered cert (tag=%q serial %s)", certTag(first), first.SerialNumber)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("phase 1: expected cert tag %q (from main), got %q", tagMain, tag)
	}

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	t.Log("phase 2: main stopped")
	second := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("phase 2: standby delivered cert (tag=%q serial %s)", certTag(second), second.SerialNumber)
	if tag := certTag(second); tag != tagStandby {
		t.Errorf("phase 2: expected cert tag %q (from standby), got %q", tagStandby, tag)
	}

	_ = startGRPCServer(t, "main-r1", tagMain, s.mainDir, s.mainPort)
	t.Log("phase 3: main restarted")
	third := harness.WaitForCertChange(t, s.certPath, second, 60*time.Second)
	t.Logf("phase 3: post-fallback cert delivered (tag=%q serial %s)", certTag(third), third.SerialNumber)
	if tag := certTag(third); tag != tagMain {
		t.Errorf("phase 3: expected cert tag %q (from main after fallback), got %q", tagMain, tag)
	}
}

// TestGRPCBothDownThenMainRecovers: both servers down, only main recovers;
// next cert must carry the main tag.
func TestGRPCBothDownThenMainRecovers(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (tag=%q)", certTag(first))

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	t.Log("both servers stopped; sleeping to let the client enter retry loops")
	time.Sleep(8 * time.Second)

	_ = startGRPCServer(t, "main-r1", tagMain, s.mainDir, s.mainPort)
	t.Log("main restarted")
	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagMain {
		t.Errorf("expected cert tag %q (only main was restarted), got %q", tagMain, tag)
	}
}

// TestGRPCBothDownThenStandbyRecovers: both servers down, only standby
// recovers; cert tag must be standby's.
func TestGRPCBothDownThenStandbyRecovers(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (tag=%q)", certTag(first))

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	t.Log("both servers stopped; sleeping to let the client enter retry loops")
	time.Sleep(8 * time.Second)

	_ = startGRPCServer(t, "standby-r1", tagStandby, s.standbyDir, s.standbyPort)
	t.Log("standby restarted")
	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagStandby {
		t.Errorf("expected cert tag %q (only standby was restarted), got %q", tagStandby, tag)
	}
}

// TestGRPCBothDownThenBothRecover: both servers down, both come back; cert
// flow continues (TRY_FALLBACK eventually converges onto main).
func TestGRPCBothDownThenBothRecover(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (serial %s)", first.SerialNumber)

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
	t.Log("both servers stopped; sleeping to let the client enter retry loops")
	time.Sleep(8 * time.Second)

	_ = startGRPCServer(t, "standby-r1", tagStandby, s.standbyDir, s.standbyPort)
	_ = startGRPCServer(t, "main-r1", tagMain, s.mainDir, s.mainPort)
	t.Log("both servers restarted")
	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagMain && tag != tagStandby {
		t.Errorf("expected cert tag %q or %q, got %q", tagMain, tagStandby, tag)
	}
}

// TestGRPCStandbyOnlyDown: standby down does not disrupt cert delivery; the
// main stream keeps serving renewals.
func TestGRPCStandbyOnlyDown(t *testing.T) {
	_, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (serial %s)", first.SerialNumber)

	standbySrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.standbyPort, 5*time.Second); err != nil {
		t.Fatalf("standby port did not free: %s", err)
	}
	t.Log("standby stopped; main keeps serving")

	got := harness.WaitForCertChange(t, s.certPath, first, 30*time.Second)
	t.Logf("renewal cert via main (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagMain {
		t.Errorf("expected cert tag %q (main only), got %q", tagMain, tag)
	}
}

// TestGRPCFailoverFallbackStress: repeatedly toggles main availability and
// verifies the client keeps receiving cert updates through every transition.
func TestGRPCFailoverFallbackStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short mode")
	}

	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{})

	prev := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (serial %s)", prev.SerialNumber)

	const cycles = 3
	for i := 1; i <= cycles; i++ {
		mainSrv.Stop(2 * time.Second)
		if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
			t.Fatalf("cycle %d: main port did not free: %s", i, err)
		}
		got := harness.WaitForCertChange(t, s.certPath, prev, 60*time.Second)
		t.Logf("cycle %d: failover cert (serial %s)", i, got.SerialNumber)
		prev = got

		mainSrv = startGRPCServer(t, fmt.Sprintf("main-r%d", i), tagMain, s.mainDir, s.mainPort)
		got = harness.WaitForCertChange(t, s.certPath, prev, 60*time.Second)
		t.Logf("cycle %d: fallback cert (tag=%q serial %s)", i, certTag(got), got.SerialNumber)
		if tag := certTag(got); tag != tagMain {
			t.Errorf("cycle %d: expected fallback cert tag %q, got %q", i, tagMain, tag)
		}
		prev = got
	}
}

// TestGRPCBothDownStress: repeatedly takes both servers down and brings one
// back, alternating which side recovers each cycle.
func TestGRPCBothDownStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short mode")
	}

	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{})

	prev := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (serial %s)", prev.SerialNumber)

	const cycles = 3
	for i := 1; i <= cycles; i++ {
		killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)
		time.Sleep(6 * time.Second)

		if i%2 == 1 {
			// odd cycle: main recovers first.
			mainSrv = startGRPCServer(t, fmt.Sprintf("main-r%d", i), tagMain, s.mainDir, s.mainPort)
			got := harness.WaitForCertChange(t, s.certPath, prev, 60*time.Second)
			t.Logf("cycle %d: main recovered, cert (tag=%q)", i, certTag(got))
			if tag := certTag(got); tag != tagMain {
				t.Errorf("cycle %d: expected cert tag %q, got %q", i, tagMain, tag)
			}
			prev = got
			// Bring standby back so the next cycle has both targets.
			standbySrv = startGRPCServer(t, fmt.Sprintf("standby-r%d", i), tagStandby, s.standbyDir, s.standbyPort)
		} else {
			// even cycle: standby recovers first.
			standbySrv = startGRPCServer(t, fmt.Sprintf("standby-r%d", i), tagStandby, s.standbyDir, s.standbyPort)
			got := harness.WaitForCertChange(t, s.certPath, prev, 60*time.Second)
			t.Logf("cycle %d: standby recovered, cert (tag=%q)", i, certTag(got))
			if tag := certTag(got); tag != tagStandby {
				t.Errorf("cycle %d: expected cert tag %q, got %q", i, tagStandby, tag)
			}
			prev = got
			mainSrv = startGRPCServer(t, fmt.Sprintf("main-r%d", i), tagMain, s.mainDir, s.mainPort)
		}
	}
}

// TestGRPCMainRetryRecoversBeforeFailover: main goroutine's 15s retry-window
// branch. Restarting main inside that window must resume cleanly without
// triggering FAILOVER (a stray failover would surface as a standby cert tag).
func TestGRPCMainRetryRecoversBeforeFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("hits hard-coded 15s sleep; skipping in -short mode")
	}

	mainSrv, _, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 3, ReconnectInt: "30s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (tag=%q)", certTag(first))

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	// Restart main well within the 15s retry window.
	time.Sleep(3 * time.Second)
	_ = startGRPCServer(t, "main-r1", tagMain, s.mainDir, s.mainPort)
	t.Log("main restarted within retry window")

	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)

	// A "main" tag proves the retry-window branch was taken instead of FAILOVER.
	if tag := certTag(got); tag != tagMain {
		t.Errorf("expected cert tag %q (recovered main), got %q — client failed over to standby instead of using the retry window", tagMain, tag)
	}
}

// TestGRPCStandbyRetryRecoversBeforeReconnect: standby goroutine's 15s
// retry-window branch. Restart standby inside that window before the
// ReconnectInterval branch is reached.
func TestGRPCStandbyRetryRecoversBeforeReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("hits hard-coded 15s sleep; skipping in -short mode")
	}

	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 2, ReconnectInt: "60s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (tag=%q)", certTag(first))

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)

	// Main retries 2×15s → FAILOVER at ~30s; standby's first failed dial
	// then enters its 15s retry. 20s lands inside that window.
	time.Sleep(20 * time.Second)

	_ = startGRPCServer(t, "standby-r1", tagStandby, s.standbyDir, s.standbyPort)
	t.Log("standby restarted within standby-retry window")

	got := harness.WaitForCertChange(t, s.certPath, first, 90*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagStandby {
		t.Errorf("expected cert tag %q (only standby restarted), got %q", tagStandby, tag)
	}
}

// TestGRPCStandbyReconnectIntervalRecovers: standby goroutine's
// ReconnectInterval branch (RetryCount=1 skips the 15s retry).
func TestGRPCStandbyReconnectIntervalRecovers(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{RetryCount: 1, ReconnectInt: "20s"})

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	t.Logf("baseline cert (tag=%q)", certTag(first))

	killBoth(t, mainSrv, standbySrv, s.mainPort, s.standbyPort)

	// RetryCount=1 → main FAILOVERs immediately; standby's first dial fails
	// and enters the 20s ReconnectInterval sleep. 5s lands inside that window.
	time.Sleep(5 * time.Second)

	_ = startGRPCServer(t, "standby-r1", tagStandby, s.standbyDir, s.standbyPort)
	t.Log("standby restarted within ReconnectInterval window")

	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	t.Logf("post-recovery cert (tag=%q serial %s)", certTag(got), got.SerialNumber)
	if tag := certTag(got); tag != tagStandby {
		t.Errorf("expected cert tag %q (only standby restarted), got %q", tagStandby, tag)
	}
}

// TestGRPCNoStandbyMainRecovers: single-server deployment. Main retry
// exhaustion routes to GRPC_STATE_RESTART_MAIN; restarting main must
// produce another main-tagged cert after the RESTART_MAIN sleep.
func TestGRPCNoStandbyMainRecovers(t *testing.T) {
	mainSrv, standbySrv, s := setupGRPCFailover(t, grpcSetupOpts{
		RetryCount:   1,
		ReconnectInt: "5s",
		NoStandby:    true,
	})
	if standbySrv != nil {
		t.Fatalf("expected no standby server in NoStandby mode")
	}

	first := harness.WaitForCertFile(t, s.certPath, 20*time.Second)
	if tag := certTag(first); tag != tagMain {
		t.Fatalf("baseline: expected cert tag %q, got %q", tagMain, tag)
	}

	mainSrv.Stop(2 * time.Second)
	if err := harness.WaitNotListening("127.0.0.1", s.mainPort, 5*time.Second); err != nil {
		t.Fatalf("main port did not free: %s", err)
	}
	// RetryCount=1 → RESTART_MAIN's 5s sleep. Restart inside the window.
	time.Sleep(2 * time.Second)
	_ = startGRPCServer(t, "main-r1", tagMain, s.mainDir, s.mainPort)

	got := harness.WaitForCertChange(t, s.certPath, first, 60*time.Second)
	if tag := certTag(got); tag != tagMain {
		t.Errorf("post-recovery: expected cert tag %q, got %q", tagMain, tag)
	}
}
