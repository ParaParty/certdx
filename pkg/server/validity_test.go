package server

import (
	"context"
	"testing"
	"time"

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

func TestClampValidBefore(t *testing.T) {
	now := time.Date(2026, 8, 15, 13, 42, 17, 0, time.UTC)
	target := now.Add(24 * time.Hour)

	cases := []struct {
		name     string
		notAfter time.Time
		want     time.Time
	}{
		{"cert outlives target", now.Add(90 * 24 * time.Hour), target},
		{"cert shorter than target", now.Add(6 * time.Hour), now.Add(5 * time.Hour)},
		{"cert shorter than renew margin", now.Add(10 * time.Minute), now.Add(10 * time.Minute)},
		{"leaf already expired", now.Add(-time.Minute), target},
	}
	for _, tc := range cases {
		if got := clampValidBefore(now, target, tc.notAfter, time.Hour); !got.Equal(tc.want) {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
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
	if _, err := s.renew(context.Background(), entry, false); err != nil {
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

func TestRenewShortLivedCertIsValidOnArrival(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = 24 * time.Hour
	s.acme = acme.NewMockACME(30 * time.Minute)

	entry := newCertEntry([]string{"example.com"})
	if _, err := s.renew(context.Background(), entry, false); err != nil {
		t.Fatalf("renew: %v", err)
	}
	cert := entry.Cert()
	if !cert.IsValid() {
		t.Fatalf("cert invalid on arrival: ValidBefore %s", cert.ValidBefore)
	}
	if notAfter, _ := leafNotAfter(cert.FullChain); cert.ValidBefore.After(notAfter) {
		t.Fatalf("ValidBefore %s outlives the cert (%s)", cert.ValidBefore, notAfter)
	}
}
