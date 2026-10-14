package server

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"pkg.para.party/certdx/pkg/acme"
)

func TestTargetValidBeforeIsAlwaysInTheFuture(t *testing.T) {
	base := time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)
	for _, off := range []time.Duration{0, time.Second, 30 * time.Minute, 59*time.Minute + 59*time.Second} {
		now := base.Add(off)
		for _, life := range []time.Duration{time.Second, 30 * time.Second, 30 * time.Minute, time.Hour, 168 * time.Hour} {
			got := targetValidBefore(now, life)
			if !got.After(now) || got.After(now.Add(life)) {
				t.Fatalf("now %s, certLifeTime %s: target %s not in (now, now+life]", now, life, got)
			}
		}
	}

	now := time.Date(2026, 8, 15, 13, 42, 17, 0, time.UTC)
	if got, want := targetValidBefore(now, 168*time.Hour), now.Truncate(time.Hour).Add(168*time.Hour); !got.Equal(want) {
		t.Fatalf("target = %s, want hour-aligned %s", got, want)
	}
}

func TestLeafNotAfterRejectsGarbage(t *testing.T) {
	if _, err := leafNotAfter([]byte("not pem")); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenewClampsValidBeforeToRealNotAfter(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = time.Hour
	s.acme = acme.NewMockACME(2 * time.Hour)

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry); err != nil {
		t.Fatalf("renew: %v", err)
	}
	cert := entry.Cert()
	notAfter, err := leafNotAfter(cert.FullChain)
	if err != nil {
		t.Fatal(err)
	}
	if want := notAfter.Add(-time.Hour); !cert.ValidBefore.Equal(want) {
		t.Fatalf("ValidBefore = %s, want %s", cert.ValidBefore, want)
	}
}

func TestRenewRejectsCertShorterThanRenewTimeLeft(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour
	s.acme = acme.NewMockACME(30 * time.Minute)

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry); err == nil {
		t.Fatal("expected error for a cert shorter than renewTimeLeft")
	}
	if cert := entry.Cert(); len(cert.FullChain) != 0 {
		t.Fatal("short cert was stored")
	}
}

// failingObtainer fails every order with err and counts the orders.
type failingObtainer struct {
	err    error
	orders int
	// cancel, if set, cancels the caller's ctx during the order.
	cancel context.CancelFunc
}

func (f *failingObtainer) Obtain(context.Context, []string, time.Time) ([]byte, []byte, error) {
	f.orders++
	if f.cancel != nil {
		f.cancel()
	}
	return nil, nil, f.err
}

func TestRenewRecordsFailureWhenCallerCancelsMidOrder(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	obtainer := &failingObtainer{err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized"}}
	s.acme = obtainer

	entry := newCertEntry([]string{"example.com"})
	for range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		obtainer.cancel = cancel
		s.renew(ctx, entry)
	}
	if obtainer.orders != 1 {
		t.Fatalf("orders = %d, want 1: a cancelled caller bypassed the retry delay", obtainer.orders)
	}
}

func TestRenewWaitsBeforeOrderingAgain(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour
	obtainer := &failingObtainer{err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized"}}
	s.acme = obtainer

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry); err == nil {
		t.Fatal("expected the order to fail")
	}
	if _, err := s.renew(context.Background(), entry); !errors.Is(err, errRenewBackoff) {
		t.Fatalf("second renew: err = %v, want errRenewBackoff", err)
	}
	if obtainer.orders != 1 {
		t.Fatalf("orders = %d, want 1 while backing off", obtainer.orders)
	}
	if wait := time.Until(entry.nextOrder()); wait < failureRetryMin-time.Minute || wait > failureRetryMin {
		t.Fatalf("next order in %s, want about %s", wait, failureRetryMin)
	}

	entry.retryAt = time.Now().Add(-time.Second)
	s.acme = acme.NewMockACME(s.Config.ACME.CertLifeTimeDuration + s.Config.ACME.RenewTimeLeftDuration)
	if _, err := s.renew(context.Background(), entry); err != nil {
		t.Fatalf("renew after the delay: %v", err)
	}
	if !entry.nextOrder().IsZero() || entry.failures != 0 {
		t.Fatal("a successful order did not reset the failure streak")
	}
}

func TestRetryDelay(t *testing.T) {
	rejected := &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized"}
	netErr := &url.Error{Op: "Post", URL: "https://acme.example", Err: errors.New("refused")}
	limited := func(after string) error {
		return &legoacme.RateLimitedError{ProblemDetails: &legoacme.ProblemDetails{Type: legoacme.RateLimitedErr}, RetryAfter: after}
	}

	cases := []struct {
		name     string
		err      error
		failures int
		want     time.Duration
	}{
		{"network, first", netErr, 1, networkRetryMin},
		{"network, third", netErr, 3, 4 * networkRetryMin},
		{"network, capped", netErr, 20, networkRetryMax},
		{"rejected, first", rejected, 1, failureRetryMin},
		{"rejected, capped", rejected, 20, failureRetryMax},
		{"propagation", errors.New("time limit exceeded"), 2, 2 * failureRetryMin},
		{"rate limited", limited("7200"), 1, 2 * time.Hour},
		{"rate limited, tiny Retry-After", limited("1"), 1, networkRetryMin},
		{"rate limited, no Retry-After", limited(""), 1, failureRetryMax},
	}
	for _, tc := range cases {
		if _, got := retryDelay(tc.err, tc.failures); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}
