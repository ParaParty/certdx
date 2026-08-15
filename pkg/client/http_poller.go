package client

import (
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

// Poll pacing. sleepTime is normally derived from the server's
// RenewTimeLeft; the constants below keep that derivation sane and give
// a failed round something shorter than a full success interval to wait
// on.
const (
	// httpPollDefaultInterval is used until the server has told us how
	// much of the cert lifetime is left.
	httpPollDefaultInterval = 1 * time.Hour
	// httpPollMinInterval is the fallback interval for a server that
	// reports a zero or negative RenewTimeLeft: the number is unusable,
	// so we fall back to a fixed cadence rather than spin.
	httpPollMinInterval = 1 * time.Minute
	// httpPollFloorInterval is the absolute lower bound on a
	// server-derived interval, guarding a sub-second RenewTimeLeft from
	// turning the loop into a tight request loop. It is itself clamped to
	// RenewTimeLeft, so it can never stretch a poll beyond the server's
	// own renewal margin.
	httpPollFloorInterval = 1 * time.Second
	// httpPollRetryInterval / httpPollMaxRetryInterval bound the backoff
	// used when the server could not be reached at all.
	httpPollRetryInterval    = 15 * time.Second
	httpPollMaxRetryInterval = 60 * time.Second
)

// pollInterval derives the success-path poll interval from the
// server-reported remaining lifetime, mirroring the server's own
// renewer cadence of RenewTimeLeft/4.
//
// Only the pathological cases are clamped. A blanket one-minute floor
// would be wrong for short-lived certs: with RenewTimeLeft below four
// minutes it polls slower than the server renews, and below one minute
// the poll interval would exceed the whole renewal margin, letting the
// client serve an expired cert. So the floor is itself capped by
// renewTimeLeft and never exceeds it.
func pollInterval(renewTimeLeft time.Duration) time.Duration {
	if renewTimeLeft <= 0 {
		// Unusable number: don't derive anything from it.
		return httpPollMinInterval
	}
	return max(renewTimeLeft/4, min(httpPollFloorInterval, renewTimeLeft))
}

// nextRetryInterval doubles the failure backoff up to the cap.
func nextRetryInterval(current time.Duration) time.Duration {
	return min(2*current, httpPollMaxRetryInterval)
}

// pollWait decides how long the poll loop sleeps after a round and what
// the transport backoff should be on the next one.
//
// The short doubling backoff is reserved for resp == nil, i.e. neither
// server could be reached: retry.Do can bail out in milliseconds
// (connection refused fast-fails), so waiting out a full success
// interval would black the cert out for an hour.
//
// A non-empty resp.Err is a different animal: the server answered, and
// answered with a considered error ("Domains not allowed"). That is
// usually permanent and never fixed by hammering, so it waits the
// success interval and resets the transport backoff — the fast backoff
// exists for a dead socket, not for a healthy server saying no.
func pollWait(resp *api.HttpCertResp, successInterval, retryInterval time.Duration) (wait, nextRetry time.Duration) {
	if resp == nil {
		return retryInterval, nextRetryInterval(retryInterval)
	}
	return successInterval, httpPollRetryInterval
}

// httpRequestCert fetches the cert for domains from the configured main
// HTTP server, falling back to the standby server if the main fails the
// retry budget. Returns nil only when both are unreachable.
func (r *CertDXClientDaemon) httpRequestCert(domains []string) *api.HttpCertResp {
	var resp *api.HttpCertResp
	err := retry.Do(r.rootCtx, r.Config.Common.RetryCount, func() error {
		certdxClient, err := r.httpClientFor(&r.Config.Http.MainServer)
		if err != nil {
			return err
		}
		resp, err = certdxClient.GetCertCtx(r.rootCtx, domains)
		return err
	})
	if err == nil {
		return resp
	}
	logging.Warn("Failed to get cert %v from MainServer, err: %s", domains, err)

	if r.Config.Http.StandbyServer.Url != "" {
		err = retry.Do(r.rootCtx, r.Config.Common.RetryCount, func() error {
			certdxClient, err := r.httpClientFor(&r.Config.Http.StandbyServer)
			if err != nil {
				return err
			}
			resp, err = certdxClient.GetCertCtx(r.rootCtx, domains)
			return err
		})
		if err == nil {
			return resp
		}
		logging.Warn("Failed to get cert %v from StandbyServer, err: %s", domains, err)
	}
	return nil
}

// httpPollingCert is the per-cert HTTP-mode poll loop. It requests the
// cert, hands the result to the watcher via cert.UpdateChan, and sleeps
// for RenewTimeLeft/4 — or one hour by default — before the next round.
// A round in which the server could not be reached at all waits on a
// short doubling backoff instead, so a dead server is retried in
// seconds rather than after a full success interval.
// Exits when rootCtx fires.
func (r *CertDXClientDaemon) httpPollingCert(cert *watchingCert) {
	sleepTime := httpPollDefaultInterval // default sleep time
	retryInterval := httpPollRetryInterval
	for {
		logging.Info("Requesting cert %v", cert.Config.Domains)
		resp := r.httpRequestCert(cert.Config.Domains)
		switch {
		case resp == nil:
			// Transport failure: no server answered.
			logging.Error("Failed to request cert, retry next round.")
		case resp.Err != "":
			// The server answered and refused. Usually permanent
			// (mis-configured domains, missing auth), so it is not worth
			// the fast retry backoff.
			logging.Error("Server refused cert request %v, err: %s", cert.Config.Domains, resp.Err)
		default:
			if resp.RenewTimeLeft <= 0 {
				logging.Warn("Server reported renew time left %s for cert %v, polling every %s instead",
					resp.RenewTimeLeft, cert.Config.Domains, httpPollMinInterval)
			}
			sleepTime = pollInterval(resp.RenewTimeLeft)
			select {
			case cert.UpdateChan <- certData{
				Domains:   cert.Config.Domains,
				Fullchain: resp.FullChain,
				Key:       resp.Key,
			}:
			case <-r.rootCtx.Done():
				return
			}
		}

		wait, nextRetry := pollWait(resp, sleepTime, retryInterval)
		retryInterval = nextRetry

		t := time.NewTimer(wait)
		select {
		case <-t.C:
			// continue
		case <-r.rootCtx.Done():
			t.Stop()
			return
		}
	}
}

// HttpMain runs the HTTP polling client until Stop is called. It
// launches one watchUpdate + one httpPollingCert per registered cert
// and blocks until rootCtx is done.
func (r *CertDXClientDaemon) HttpMain() {
	r.startWatchers()

	for _, c := range r.certs {
		r.wg.Add(1)
		go func(_c *watchingCert) {
			defer r.wg.Done()
			r.httpPollingCert(_c)
		}(c)
	}

	<-r.rootCtx.Done()

	logging.Info("Stopping Http client")
	r.wg.Wait()
}
