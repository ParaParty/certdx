package client

import (
	"fmt"
	"slices"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

// httpRequestCert fetches the cert for domains from the main HTTP server,
// falling back to standby (if non-nil) when the main fails the retry
// budget. Returns nil only when both are unreachable.
func (r *CertDXClientDaemon) httpRequestCert(domains []string, main, standby *CertDXHttpClient) *api.HttpCertResp {
	var resp *api.HttpCertResp
	request := func(c *CertDXHttpClient) func() error {
		return func() error {
			var err error
			resp, err = c.GetCertCtx(r.rootCtx, domains)
			return err
		}
	}

	err := retry.Do(r.rootCtx, r.Config.Common.RetryCount, request(main))
	if err == nil {
		return resp
	}
	logging.Warn("Failed to get cert %v from MainServer, err: %s", domains, err)

	if standby != nil {
		err = retry.Do(r.rootCtx, r.Config.Common.RetryCount, request(standby))
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
func (r *CertDXClientDaemon) httpPollingCert(cert *watchingCert, main, standby *CertDXHttpClient) {
	sleepTime := 1 * time.Hour // default sleep time
	for {
		logging.Info("Requesting cert %v", cert.Config.Domains)
		resp := r.httpRequestCert(cert.Config.Domains, main, standby)
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
// and blocks until rootCtx is done. It returns early if a server's
// client can't be built, e.g. an unloadable mTLS bundle.
func (r *CertDXClientDaemon) HttpMain() error {
	main, err := r.makeHttpClient(&r.Config.Http.MainServer)
	if err != nil {
		return fmt.Errorf("http main server: %w", err)
	}
	var standby *CertDXHttpClient
	if r.Config.Http.StandbyServer.Url != "" {
		if standby, err = r.makeHttpClient(&r.Config.Http.StandbyServer); err != nil {
			return fmt.Errorf("http standby server: %w", err)
		}
	}

	r.startWatchers()

	for _, c := range r.certs {
		r.wg.Add(1)
		go func(_c *watchingCert) {
			defer r.wg.Done()
			r.httpPollingCert(_c, main, standby)
		}(c)
	}

	<-r.rootCtx.Done()

	logging.Info("Stopping Http client")
	r.wg.Wait()
	return nil
}

func (r *CertDXClientDaemon) makeHttpClient(server *config.ClientHttpServer) (*CertDXHttpClient, error) {
	opts := append(slices.Clone(r.ClientOpt), WithCertDXServerInfo(server))
	return MakeCertDXHttpClient(opts...)
}
