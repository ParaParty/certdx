package client

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

const (
	// Wait between retries of the same server, doubling up to max.
	pollRetryMin = 30 * time.Second
	pollRetryMax = 90 * time.Second

	// Wait after every server used up its retries, and before the first
	// successful round tells us the server's RenewTimeLeft.
	pollIdleWait = time.Hour
)

// pollInterval is the wait after a successful round: RenewTimeLeft/4 as sent
// by the server, one minute if that is not positive, and never under 1s.
func pollInterval(renewTimeLeft time.Duration) time.Duration {
	if renewTimeLeft <= 0 {
		return time.Minute
	}
	return max(renewTimeLeft/4, time.Second)
}

// httpPoller polls the HTTP servers for one certificate. It sticks to the
// main server and only moves to the standby once the main has failed
// retryCount times, since the two may issue from different CAs.
type httpPoller struct {
	daemon  *CertDXClientDaemon
	cert    *watchingCert
	servers []*CertDXHttpClient // main, then standby if configured

	current   int           // index into servers
	failures  int           // consecutive failures of servers[current]
	retryWait time.Duration // wait before the next retry of servers[current]
	interval  time.Duration // wait after a successful round
}

func (r *CertDXClientDaemon) newHttpPoller(cert *watchingCert, main, standby *CertDXHttpClient) *httpPoller {
	p := &httpPoller{
		daemon:    r,
		cert:      cert,
		servers:   []*CertDXHttpClient{main},
		retryWait: pollRetryMin,
		interval:  pollIdleWait,
	}
	if standby != nil {
		p.servers = append(p.servers, standby)
	}
	return p
}

// run polls until the daemon stops.
func (p *httpPoller) run() {
	for p.sleep(p.poll()) {
	}
}

// poll runs one round and returns how long to wait before the next.
func (p *httpPoller) poll() time.Duration {
	domains := p.cert.Config.Domains
	logging.Info("Requesting cert %v from %s", domains, p.serverName())

	resp, err := p.servers[p.current].GetCertCtx(p.daemon.rootCtx, domains)
	if err != nil {
		return p.onFailure(err)
	}
	p.current, p.failures, p.retryWait = 0, 0, pollRetryMin

	if resp.Err != "" {
		// A refusal such as "domains not allowed" won't change soon.
		logging.Error("Server refused cert %v: %s", domains, resp.Err)
		return p.interval
	}

	p.interval = pollInterval(resp.RenewTimeLeft)
	select {
	case p.cert.UpdateChan <- certData{Domains: domains, Fullchain: resp.FullChain, Key: resp.Key}:
	case <-p.daemon.rootCtx.Done():
	}
	return p.interval
}

// onFailure retries the current server on a backoff until it has failed
// retryCount times, then moves to the next server. Once every server has
// failed it starts over from the main server after pollIdleWait.
func (p *httpPoller) onFailure(err error) time.Duration {
	attempts := max(p.daemon.Config.Common.RetryCount, 1)
	p.failures++
	logging.Warn("Failed to get cert %v from %s (%d/%d): %s", p.cert.Config.Domains, p.serverName(), p.failures, attempts, err)

	if p.failures < attempts {
		wait := p.retryWait
		p.retryWait = min(p.retryWait*2, pollRetryMax)
		return wait
	}

	p.failures, p.retryWait = 0, pollRetryMin
	if p.current+1 < len(p.servers) {
		p.current++
		return 0
	}
	p.current = 0
	logging.Error("All servers failed for cert %v, retrying in %s", p.cert.Config.Domains, pollIdleWait)
	return pollIdleWait
}

func (p *httpPoller) serverName() string {
	if p.current == 0 {
		return "MainServer"
	}
	return "StandbyServer"
}

// sleep waits for d and reports false if the daemon stopped meanwhile.
func (p *httpPoller) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-p.daemon.rootCtx.Done():
		return false
	}
}

// HttpMain runs the HTTP polling client until Stop is called. It
// launches one watchUpdate + one httpPoller per registered cert
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
		r.wg.Go(r.newHttpPoller(c, main, standby).run)
	}

	<-r.rootCtx.Done()

	logging.Info("Stopping Http client")
	r.wg.Wait()
	return nil
}

func (r *CertDXClientDaemon) makeHttpClient(server *config.ClientHttpServer) (*CertDXHttpClient, error) {
	if server.AuthMethod == config.HTTP_AUTH_TOKEN && server.Token != "" &&
		strings.HasPrefix(strings.ToLower(server.Url), "http://") {
		logging.Warn("HTTP API token is sent unencrypted to %s", server.Url)
	}
	opts := append(slices.Clone(r.ClientOpt), WithCertDXServerInfo(server))
	return MakeCertDXHttpClient(opts...)
}
