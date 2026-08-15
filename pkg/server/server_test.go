package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/domain"
)

// fakeObtainer is an acme.Obtainer stand-in whose behavior each test picks.
type fakeObtainer struct {
	calls atomic.Int64
	fn    func(ctx context.Context, domains []string) ([]byte, []byte, error)
}

func (f *fakeObtainer) Obtain(ctx context.Context, domains []string, _ time.Time) ([]byte, []byte, error) {
	f.calls.Add(1)
	return f.fn(ctx, domains)
}

func (f *fakeObtainer) RetryObtain(ctx context.Context, domains []string, deadline time.Time) ([]byte, []byte, error) {
	return f.Obtain(ctx, domains, deadline)
}

// newTestServer builds a server whose cert store writes into a temp dir, so
// tests never touch the real cache.json.
func newTestServer(t *testing.T) *CertDXServer {
	t.Helper()
	s, err := MakeCertDXServer()
	if err != nil {
		t.Fatal(err)
	}
	s.certStore = CertStore{
		path:    filepath.Join(t.TempDir(), "cache.json"),
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
	return s
}

func TestLeafNotAfterReadsIssuedCert(t *testing.T) {
	mock := acme.NewMockACME(90 * time.Minute)
	fullchain, _, err := mock.Obtain(context.Background(), []string{"example.com"}, time.Time{})
	if err != nil {
		t.Fatalf("mock obtain: %v", err)
	}

	notAfter, err := leafNotAfter(fullchain)
	if err != nil {
		t.Fatalf("leafNotAfter: %v", err)
	}
	if d := time.Until(notAfter); d < 80*time.Minute || d > 100*time.Minute {
		t.Fatalf("NotAfter in %s, want ~90m", d)
	}
}

func TestLeafNotAfterRejectsGarbage(t *testing.T) {
	if _, err := leafNotAfter([]byte("not pem at all")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})
	if _, err := leafNotAfter(junk); err == nil {
		t.Fatal("expected error for unparsable certificate")
	}
}

// A certLifeTime longer than what the CA actually issues must not keep an
// expired cert in service: ValidBefore is clamped to the leaf's real NotAfter
// minus the renew margin.
func TestRenewClampsValidBeforeToRealNotAfter(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = time.Hour
	s.acme = acme.NewMockACME(2 * time.Hour)

	entry := newCertEntry([]string{"example.com"})
	obtained, err := s.renew(context.Background(), entry, false)
	if err != nil || !obtained {
		t.Fatalf("renew: obtained=%v err=%v", obtained, err)
	}

	cert := entry.Cert()
	notAfter, err := leafNotAfter(cert.FullChain)
	if err != nil {
		t.Fatalf("leafNotAfter: %v", err)
	}
	want := notAfter.Add(-s.Config.ACME.RenewTimeLeftDuration)
	if !cert.ValidBefore.Equal(want) {
		t.Fatalf("ValidBefore = %s, want %s (leaf NotAfter %s)", cert.ValidBefore, want, notAfter)
	}
	if cert.ValidBefore.After(notAfter) {
		t.Fatal("ValidBefore outlives the certificate itself")
	}
}

// A cert that is issued for longer than certLifeTime keeps the configured
// (shorter) ValidBefore — the clamp only ever shortens.
func TestRenewKeepsConfiguredValidBeforeWhenShorter(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.CertLifeTimeDuration = time.Hour
	s.Config.ACME.RenewTimeLeftDuration = time.Minute
	s.acme = acme.NewMockACME(240 * time.Hour)

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry, false); err != nil {
		t.Fatalf("renew: %v", err)
	}

	want := time.Now().Truncate(time.Hour).Add(time.Hour)
	if !entry.Cert().ValidBefore.Equal(want) {
		t.Fatalf("ValidBefore = %s, want configured %s", entry.Cert().ValidBefore, want)
	}
}

// The hour-truncated validity target loses up to 59m59s of lifetime, which for
// a sub-hour certLifeTime puts ValidBefore in the past: the cert is invalid the
// moment it is minted, SDS never offers it, HTTP answers 503 forever and the
// renewer re-obtains on every check. Whatever the wall clock and the configured
// lifetime, the target must be strictly in the future.
func TestTargetValidBeforeIsAlwaysInTheFuture(t *testing.T) {
	base := time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)
	offsets := []time.Duration{
		0, time.Second, 30 * time.Second, time.Minute, 29 * time.Minute,
		30*time.Minute + 1, 59 * time.Minute, 59*time.Minute + 59*time.Second,
	}
	lifetimes := []time.Duration{
		time.Second, 30 * time.Second, time.Minute, 30 * time.Minute,
		time.Hour, 168 * time.Hour,
	}

	for _, off := range offsets {
		now := base.Add(off)
		for _, life := range lifetimes {
			got := targetValidBefore(now, life)
			if !got.After(now) {
				t.Fatalf("now %s, certLifeTime %s: target %s is not after now", now, life, got)
			}
			// Never hand out more lifetime than configured either.
			if got.After(now.Add(life)) {
				t.Fatalf("now %s, certLifeTime %s: target %s overshoots now+certLifeTime", now, life, got)
			}
		}
	}
}

// Hour alignment is still the rule whenever it produces a usable target.
func TestTargetValidBeforeKeepsHourAlignment(t *testing.T) {
	now := time.Date(2026, 8, 15, 13, 42, 17, 0, time.UTC)
	got := targetValidBefore(now, 168*time.Hour)
	want := now.Truncate(time.Hour).Add(168 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("target = %s, want hour-aligned %s", got, want)
	}
}

func TestClampValidBefore(t *testing.T) {
	now := time.Date(2026, 8, 15, 13, 42, 17, 0, time.UTC)
	configured := now.Add(24 * time.Hour)

	cases := []struct {
		name        string
		notAfter    time.Time
		renewLeft   time.Duration
		want        time.Time
		wantOutcome clampOutcome
	}{
		{
			name:        "cert outlives configured target",
			notAfter:    now.Add(90 * 24 * time.Hour),
			renewLeft:   time.Hour,
			want:        configured,
			wantOutcome: clampNone,
		},
		{
			name:        "cert shorter than configured, margin still fits",
			notAfter:    now.Add(6 * time.Hour),
			renewLeft:   time.Hour,
			want:        now.Add(5 * time.Hour),
			wantOutcome: clampApplied,
		},
		{
			// The clamped value would be in the past: keep the cert's real
			// expiry instead of declaring it invalid at birth.
			name:        "cert lifetime shorter than the renew margin",
			notAfter:    now.Add(10 * time.Minute),
			renewLeft:   time.Hour,
			want:        now.Add(10 * time.Minute),
			wantOutcome: clampFloored,
		},
		{
			name:        "clamped value lands exactly on now",
			notAfter:    now.Add(time.Hour),
			renewLeft:   time.Hour,
			want:        now.Add(time.Hour),
			wantOutcome: clampFloored,
		},
		{
			// Nothing sane to derive from a leaf that is already expired;
			// keep the configured (future) target so the entry stays usable.
			name:        "leaf already expired on arrival",
			notAfter:    now.Add(-time.Minute),
			renewLeft:   time.Hour,
			want:        configured,
			wantOutcome: clampFloored,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, outcome := clampValidBefore(now, configured, tc.notAfter, tc.renewLeft)
			if !got.Equal(tc.want) {
				t.Fatalf("validBefore = %s, want %s", got, tc.want)
			}
			if outcome != tc.wantOutcome {
				t.Fatalf("outcome = %d, want %d", outcome, tc.wantOutcome)
			}
			if !got.After(now) {
				t.Fatalf("validBefore %s is not after now %s", got, now)
			}
		})
	}
}

// The everyday clamp (CA backdates notBefore ~1h, our own target loses up to
// 59m to hour-truncation) must stay below the warn threshold; a clamp that
// eats a real fraction of the configured lifetime must cross it.
func TestClampWarnThreshold(t *testing.T) {
	const life = 60 * 24 * time.Hour
	if got := clampWarnThreshold(life); got <= 2*time.Hour {
		t.Fatalf("threshold for %s = %s, want more than the ~2h everyday clamp", life, got)
	}
	if got := clampWarnThreshold(30 * time.Second); got < 2*time.Hour {
		t.Fatalf("threshold for a sub-hour lifetime = %s, want at least 2h", got)
	}
}

// A cert whose real lifetime is shorter than renewTimeLeft used to get a
// ValidBefore in the past, so it was invalid the moment it was obtained:
// permanent 503 plus one ACME obtain per request.
func TestRenewCertShorterThanRenewMarginStaysValid(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour
	s.acme = acme.NewMockACME(30 * time.Minute)

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry, false); err != nil {
		t.Fatalf("renew: %v", err)
	}

	cert := entry.Cert()
	if !cert.IsValid() {
		t.Fatalf("cert invalid on arrival: ValidBefore %s, now %s", cert.ValidBefore, time.Now())
	}
	notAfter, err := leafNotAfter(cert.FullChain)
	if err != nil {
		t.Fatalf("leafNotAfter: %v", err)
	}
	if cert.ValidBefore.After(notAfter) {
		t.Fatalf("ValidBefore %s outlives the certificate itself (%s)", cert.ValidBefore, notAfter)
	}
}

// A sub-hour certLifeTime issued at an arbitrary point in the hour must
// produce an immediately valid cert, and the renewer must then treat the entry
// as healthy instead of re-obtaining on every check.
func TestRenewShortCertLifeTimeIsValidImmediately(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.CertLifeTimeDuration = 30 * time.Second
	s.Config.ACME.RenewTimeLeftDuration = 10 * time.Second

	mock := acme.NewMockACME(5 * time.Minute)
	fake := &fakeObtainer{fn: func(_ context.Context, domains []string) ([]byte, []byte, error) {
		return mock.Obtain(context.Background(), domains, time.Time{})
	}}
	s.acme = fake

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry, false); err != nil {
		t.Fatalf("renew: %v", err)
	}

	cert := entry.Cert()
	if !cert.IsValid() {
		t.Fatalf("cert invalid on arrival: ValidBefore %s, now %s", cert.ValidBefore, time.Now())
	}
	if d := time.Until(cert.ValidBefore); d > 30*time.Second {
		t.Fatalf("ValidBefore is %s out, longer than the configured 30s lifetime", d)
	}

	// The renewer's early return keys on the same IsValid check.
	obtained, err := s.renew(context.Background(), entry, false)
	if err != nil {
		t.Fatalf("second renew: %v", err)
	}
	if obtained {
		t.Fatal("renew re-obtained a cert it had just issued")
	}
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("obtain called %d times, want 1", got)
	}
}

// A cancelled caller ctx (subscription or HTTP request) must not cost us a
// real issuance: the cert still reaches the cache-file writer.
func TestRenewPersistsWhenCallerCtxCancelled(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mock := acme.NewMockACME(48 * time.Hour)
	s.acme = &fakeObtainer{fn: func(obtainCtx context.Context, domains []string) ([]byte, []byte, error) {
		// The caller goes away while the ACME round-trip is in flight.
		cancel()
		return mock.Obtain(context.Background(), domains, time.Time{})
	}}

	entry := newCertEntry([]string{"example.com"})
	obtained, err := s.renew(ctx, entry, false)
	if err != nil || !obtained {
		t.Fatalf("renew: obtained=%v err=%v", obtained, err)
	}

	select {
	case fe := <-s.certStore.update:
		if len(fe.Domains) != 1 || fe.Domains[0] != "example.com" {
			t.Fatalf("persisted domains: %v", fe.Domains)
		}
	default:
		t.Fatal("obtained cert was broadcast but never handed to the cert store")
	}
}

func TestRenewCheckIntervalFloorsShortRenewTimeLeft(t *testing.T) {
	s := newTestServer(t)

	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour
	if got := s.renewCheckInterval(); got != 6*time.Hour {
		t.Fatalf("interval = %s, want 6h", got)
	}

	for _, d := range []time.Duration{0, -time.Hour, time.Second} {
		s.Config.ACME.RenewTimeLeftDuration = d
		if got := s.renewCheckInterval(); got != renewCheckMinInterval {
			t.Fatalf("RenewTimeLeft %s: interval = %s, want floor %s", d, got, renewCheckMinInterval)
		}
	}
}

// A failing obtain must be retried on the short backoff instead of parking the
// entry for RenewTimeLeft/4 (6h with the default config).
func TestRenewerRetriesQuicklyWhenNoValidCert(t *testing.T) {
	s := newTestServer(t)
	s.renewRetryMin, s.renewRetryMax = 10*time.Millisecond, 20*time.Millisecond
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour // healthy interval would be 6h

	fake := &fakeObtainer{fn: func(context.Context, []string) ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("acme is down")
	}}
	s.acme = fake

	entry := newCertEntry([]string{"example.com"})
	s.subscribe(entry)
	defer s.release(entry)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fake.calls.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fake.calls.Load(); got < 3 {
		t.Fatalf("obtain called %d times, want >= 3 (renewer parked on the long interval)", got)
	}
}

// Once a cert is in hand the renewer falls back to the long steady-state
// interval rather than hammering ACME on the retry backoff.
func TestRenewerUsesLongIntervalWhenHealthy(t *testing.T) {
	s := newTestServer(t)
	s.renewRetryMin, s.renewRetryMax = 10*time.Millisecond, 20*time.Millisecond
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour

	mock := acme.NewMockACME(240 * time.Hour)
	fake := &fakeObtainer{fn: func(_ context.Context, domains []string) ([]byte, []byte, error) {
		return mock.Obtain(context.Background(), domains, time.Time{})
	}}
	s.acme = fake

	entry := newCertEntry([]string{"example.com"})
	s.subscribe(entry)
	defer s.release(entry)

	time.Sleep(200 * time.Millisecond)
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("obtain called %d times, want 1 (renewer should sleep the long interval)", got)
	}
}

// Stop must not return before the cache-file writer has stopped, otherwise the
// documented shutdown drain races process exit.
func TestStopJoinsTrackedGoroutines(t *testing.T) {
	s := newTestServer(t)

	stopped := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-s.rootCtx.Done()
		time.Sleep(50 * time.Millisecond) // stand-in for the drain + write
		close(stopped)
	}()

	s.Stop()
	select {
	case <-stopped:
	default:
		t.Fatal("Stop returned before the tracked goroutine finished")
	}

	// Stop is idempotent and Wait must not block once everything is done.
	s.Stop()
	s.Wait()
}

// Renewers must not be joined by Stop: lego's Obtain is not context-aware, so
// a renewer parked in an issuance can only be waited out, and waiting burns
// shutdownDrainTimeout (30s) — long enough to lose the race against the
// caller's own shutdown deadline and turn a clean exit into a Fatal.
func TestStopDoesNotWaitForParkedRenewer(t *testing.T) {
	s := newTestServer(t)

	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.acme = &fakeObtainer{fn: func(context.Context, []string) ([]byte, []byte, error) {
		// Stands in for a lego Obtain that ignores ctx entirely.
		once.Do(func() { close(parked) })
		<-release
		return nil, nil, fmt.Errorf("acme gave up")
	}}
	defer close(release)

	entry := newCertEntry([]string{"example.com"})
	s.subscribe(entry)

	<-parked

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked on a renewer parked inside ACME")
	}
}
