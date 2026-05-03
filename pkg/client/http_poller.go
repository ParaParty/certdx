package client

import (
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

// httpRequestCert fetches the cert for domains from the configured main
// HTTP server, falling back to the standby server if the main fails the
// retry budget. Returns nil only when both are unreachable.
func (r *CertDXClientDaemon) httpRequestCert(domains []string) *api.HttpCertResp {
	var resp *api.HttpCertResp
	err := retry.Do(r.rootCtx, r.Config.Common.RetryCount, func() error {
		certdxClient := MakeCertDXHttpClient(append(r.ClientOpt, WithCertDXServerInfo(&r.Config.Http.MainServer))...)
		var err error
		resp, err = certdxClient.GetCertCtx(r.rootCtx, domains)
		return err
	})
	if err == nil {
		return resp
	}
	logging.Warn("Failed to get cert %v from MainServer, err: %s", domains, err)

	if r.Config.Http.StandbyServer.Url != "" {
		certdxClient := MakeCertDXHttpClient(append(r.ClientOpt, WithCertDXServerInfo(&r.Config.Http.StandbyServer))...)
		err = retry.Do(r.rootCtx, r.Config.Common.RetryCount, func() error {
			var err error
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
// for RenewTimeLeft/4 (or one hour by default) before the next round.
// Exits when rootCtx fires.
func (r *CertDXClientDaemon) httpPollingCert(cert *watchingCert) {
	sleepTime := 1 * time.Hour // default sleep time
	for {
		logging.Info("Requesting cert %v", cert.Config.Domains)
		resp := r.httpRequestCert(cert.Config.Domains)
		if resp != nil {
			if resp.Err != "" {
				logging.Error("Failed to request cert, err: %s", resp.Err)
			} else {
				sleepTime = resp.RenewTimeLeft / 4
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
		} else {
			logging.Error("Failed to request cert, retry next round.")
		}
		t := time.NewTimer(sleepTime)
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
