package client

import (
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

// TestPollIntervalFloors pins the poll-interval clamp: a server that
// reports a zero or negative RenewTimeLeft must not put the poller in a
// tight request loop, while every usable RenewTimeLeft — including
// short-lived certs measured in seconds — must still be polled at the
// server's own RenewTimeLeft/4 cadence.
func TestPollIntervalFloors(t *testing.T) {
	cases := []struct {
		renewTimeLeft time.Duration
		want          time.Duration
	}{
		{0, httpPollMinInterval},
		{-24 * time.Hour, httpPollMinInterval},
		// Sub-second lifetime: clamped, but never past the margin itself.
		{100 * time.Millisecond, 100 * time.Millisecond},
		{time.Second, time.Second},
		// Short-lived certs (the e2e config uses certLifeTime 30s /
		// renewTimeLeft 16s) must keep their RenewTimeLeft/4 cadence.
		{16 * time.Second, 4 * time.Second},
		{2 * time.Minute, 30 * time.Second},
		{8 * time.Hour, 2 * time.Hour},
	}
	for _, tc := range cases {
		if got := pollInterval(tc.renewTimeLeft); got != tc.want {
			t.Errorf("pollInterval(%s): got %s want %s", tc.renewTimeLeft, got, tc.want)
		}
	}
}

// TestPollIntervalNeverExceedsRenewMargin is the invariant behind the
// clamp: polling slower than the server's own renewal margin means the
// client can serve an expired cert.
func TestPollIntervalNeverExceedsRenewMargin(t *testing.T) {
	for _, renewTimeLeft := range []time.Duration{
		time.Millisecond, 100 * time.Millisecond, time.Second, 4 * time.Second,
		16 * time.Second, 45 * time.Second, time.Minute, 2 * time.Minute,
		4 * time.Minute, time.Hour,
	} {
		if got := pollInterval(renewTimeLeft); got > renewTimeLeft {
			t.Errorf("pollInterval(%s) = %s exceeds the renewal margin", renewTimeLeft, got)
		}
	}
}

// TestPollWaitServerErrorIsNotTransportFailure pins the split between
// "the server answered with an error" and "nothing answered". A
// permanent, actionable server error (HTTP 200 + resp.Err) must not be
// hammered on the 15s→60s transport backoff forever.
func TestPollWaitServerErrorIsNotTransportFailure(t *testing.T) {
	const success = 30 * time.Minute

	// Transport failure: short backoff, and it doubles.
	wait, next := pollWait(nil, success, httpPollRetryInterval)
	if wait != httpPollRetryInterval {
		t.Errorf("transport failure wait: got %s want %s", wait, httpPollRetryInterval)
	}
	if next != nextRetryInterval(httpPollRetryInterval) {
		t.Errorf("transport failure backoff: got %s want %s", next, nextRetryInterval(httpPollRetryInterval))
	}

	// Server answered with an error: success interval, backoff reset.
	wait, next = pollWait(&api.HttpCertResp{Err: "Domains not allowed"}, success, httpPollMaxRetryInterval)
	if wait != success {
		t.Errorf("server error wait: got %s want %s", wait, success)
	}
	if next != httpPollRetryInterval {
		t.Errorf("server error must reset the transport backoff: got %s want %s", next, httpPollRetryInterval)
	}

	// Success: success interval, backoff reset.
	wait, next = pollWait(&api.HttpCertResp{}, success, httpPollMaxRetryInterval)
	if wait != success {
		t.Errorf("success wait: got %s want %s", wait, success)
	}
	if next != httpPollRetryInterval {
		t.Errorf("success must reset the transport backoff: got %s want %s", next, httpPollRetryInterval)
	}
}

// TestPollWaitTransportBackoffClimbsOnlyOnTransportFailure walks a few
// rounds to show a repeatedly-refusing server never escalates the
// transport backoff.
func TestPollWaitTransportBackoffClimbsOnlyOnTransportFailure(t *testing.T) {
	retryInterval := httpPollRetryInterval
	errResp := &api.HttpCertResp{Err: "Domains not allowed"}
	for range 5 {
		var wait time.Duration
		wait, retryInterval = pollWait(errResp, httpPollDefaultInterval, retryInterval)
		if wait != httpPollDefaultInterval {
			t.Fatalf("server error waited %s, want the success interval %s", wait, httpPollDefaultInterval)
		}
	}
	if retryInterval != httpPollRetryInterval {
		t.Fatalf("transport backoff drifted on server errors: got %s want %s", retryInterval, httpPollRetryInterval)
	}
}

// TestNextRetryIntervalCaps checks the failure backoff doubles and then
// stays at the cap.
func TestNextRetryIntervalCaps(t *testing.T) {
	interval := httpPollRetryInterval
	for range 10 {
		interval = nextRetryInterval(interval)
		if interval > httpPollMaxRetryInterval {
			t.Fatalf("backoff exceeded cap: got %s want <= %s", interval, httpPollMaxRetryInterval)
		}
	}
	if interval != httpPollMaxRetryInterval {
		t.Fatalf("backoff did not reach cap: got %s want %s", interval, httpPollMaxRetryInterval)
	}
	// A failed round must never wait out the success interval.
	if httpPollMaxRetryInterval >= httpPollDefaultInterval {
		t.Fatalf("retry backoff %s is not shorter than the success interval %s",
			httpPollMaxRetryInterval, httpPollDefaultInterval)
	}
}

// TestHttpRequestCertMTLSFailureIsNotFatal pins the os.Exit fix on the
// poll path: an unreadable mTLS bundle must come back as a failed fetch
// (nil response), not take the process down.
func TestHttpRequestCertMTLSFailureIsNotFatal(t *testing.T) {
	d := MakeCertDXClientDaemon()
	d.Config.Common.RetryCount = 0
	d.Config.Http.MainServer = config.ClientHttpServer{
		Url:              "https://127.0.0.1:1",
		AuthMethod:       config.HTTP_AUTH_MTLS,
		ClientMtlsConfig: config.ClientMtlsConfig{PEM: filepath.Join(t.TempDir(), "does-not-exist.pem")},
	}

	if resp := d.httpRequestCert([]string{"example.com"}); resp != nil {
		t.Fatalf("expected nil response for unloadable mtls bundle, got %+v", resp)
	}
}
