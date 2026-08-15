package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

const (
	// renewRetryMinInterval / renewRetryMaxInterval bound the exponential
	// backoff a renewer uses while the entry holds no cert — a failed ACME
	// obtain must not park the entry for RenewTimeLeft/4 (6h by default).
	renewRetryMinInterval = 30 * time.Second
	renewRetryMaxInterval = 5 * time.Minute

	// renewCheckMinInterval floors the healthy steady-state re-check
	// interval, so a zero or negative RenewTimeLeft that slipped through
	// config validation can't turn the renewer into a busy loop.
	renewCheckMinInterval = 5 * time.Second

	// shutdownDrainTimeout caps how long Stop / Wait block joining the
	// cache-file writer before giving up, so a wedged goroutine can't hang
	// process exit forever. It is a backstop only: the writer exits within
	// microseconds of rootCtx firing, and renewers are deliberately not
	// joined (see subscribe).
	shutdownDrainTimeout = 30 * time.Second
)

type CertT struct {
	FullChain   []byte    `json:"fullChain"`
	Key         []byte    `json:"key"`
	ValidBefore time.Time `json:"validBefore"`
	RenewAt     time.Time `json:"renewAt"`
}

type CertDXServer struct {
	Config config.ServerConfig

	acme      acme.Obtainer
	certCache certCache
	certStore CertStore

	// renewRetryMin / renewRetryMax bound the renewer's retry backoff.
	// Seeded from the package defaults by MakeCertDXServer; per-server so
	// tests can shrink them without racing other servers' renewers.
	renewRetryMin time.Duration
	renewRetryMax time.Duration

	// rootCtx is the lifecycle parent for every server subgoroutine
	// (HttpSrv, SDSSrv, the cache-file writer, every per-entry renewer).
	// Stop cancels it exactly once via stopOnce. There is no separate
	// stop chan — context cancellation is the single signal.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	stopOnce   sync.Once
	// wg tracks only the subgoroutines Stop must join before the process may
	// exit — currently just the cache-file writer, whose drain would
	// otherwise race process exit and truncate cache.json. Renewers are NOT
	// tracked: they park inside lego's non-context-aware Obtain, so joining
	// them would burn shutdownDrainTimeout on every shutdown that catches an
	// issuance in flight and race the caller's own shutdown deadline. They
	// are best-effort on shutdown and select on rootCtx between attempts.
	wg sync.WaitGroup
}

func MakeCertDXServer() (*CertDXServer, error) {
	store, err := NewCertStore()
	if err != nil {
		return nil, err
	}
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ret := &CertDXServer{
		certCache:     makeCertCache(),
		certStore:     store,
		rootCtx:       rootCtx,
		rootCancel:    rootCancel,
		renewRetryMin: renewRetryMinInterval,
		renewRetryMax: renewRetryMaxInterval,
	}
	ret.Config.SetDefault()

	return ret, nil
}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func (s *CertDXServer) Init() error {
	var err error

	s.acme, err = acme.MakeACME(&s.Config)
	if err != nil {
		return fmt.Errorf("initialize ACME: %w", err)
	}

	s.certCache.setMaxEntries(s.Config.ACME.MaxCacheEntries)

	if err = s.loadCertStore(); err != nil {
		// It's okay that previous saved cert can not be loaded, just log and continue to run
		logging.Warn("Load cache file failed: %s", err)
	}

	// The cache-file writer is the one goroutine Stop joins. Adding to wg
	// after Stop has already drained would race wg.Wait, so an Init that
	// somehow runs against a stopped server just skips it — listenUpdate
	// would return on the cancelled rootCtx immediately anyway.
	if s.rootCtx.Err() != nil {
		return nil
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.certStore.listenUpdate(s.rootCtx)
	}()

	return nil
}

func (s *CertDXServer) loadCertStore() error {
	err := s.certStore.Load()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return err
		}
	}

	s.certCache.mutex.Lock()
	for _, cache := range s.certStore.entries {
		entry, err := s.certCache.getNoLock(cache.Domains)
		if err != nil {
			logging.Warn("Skipping cached cert for domains %v: %s", cache.Domains, err)
			continue
		}
		entry.stateMu.Lock()
		entry.cert = cache.Cert
		entry.stateMu.Unlock()
	}
	s.certCache.mutex.Unlock()

	logging.Info("Previous cache loaded")
	return nil
}

// renew obtains a fresh cert from ACME if the cached cert has expired or
// is missing, updates the cache, and broadcasts the new version to every
// subscriber waiting on WaitForUpdate.
//
// retry controls whether the underlying ACME obtain uses the retry-with-
// backoff helper. ctx bounds the operation; on cancellation renew returns
// ctx.Err() without contacting ACME (the underlying lego client is not
// context-aware, so cancellation is checked between operations rather
// than mid-flight).
func (s *CertDXServer) renew(ctx context.Context, c *certEntry, retry bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	logging.Info("Checking cert: %v", c.domains)
	// Re-check under renewMu: if a concurrent caller already refreshed the
	// cert while we were waiting on the mutex, observe the fresh cert and
	// skip the ACME round-trip. This collapses concurrent expired-cert
	// fetches into one ACME call.
	current, _ := c.Snapshot()
	if current.IsValid() {
		logging.Info("Cert: %v is valid until %s", c.domains, current.ValidBefore)
		return false, nil
	}

	newValidBefore := targetValidBefore(time.Now(), s.Config.ACME.CertLifeTimeDuration)

	var fullchain, key []byte
	var err error
	if retry {
		fullchain, key, err = s.acme.RetryObtain(ctx, c.domains, newValidBefore.Add(s.Config.ACME.RenewTimeLeftDuration))
	} else {
		fullchain, key, err = s.acme.Obtain(ctx, c.domains, newValidBefore.Add(s.Config.ACME.RenewTimeLeftDuration))
	}
	if err != nil {
		return false, err
	}

	// The issuer, not our config, decides how long the cert is actually
	// valid. Clamp ValidBefore against the leaf's real NotAfter (minus the
	// renew margin) so a too-generous certLifeTime can't keep an expired
	// cert in service. A leaf we can't parse is only logged: the cert is
	// still usable, we just fall back to the configured lifetime.
	validBefore := newValidBefore
	if notAfter, perr := leafNotAfter(fullchain); perr != nil {
		logging.Warn("Could not read NotAfter of issued cert %v: %s", c.domains, perr)
	} else {
		var outcome clampOutcome
		validBefore, outcome = clampValidBefore(time.Now(), newValidBefore, notAfter, s.Config.ACME.RenewTimeLeftDuration)
		switch outcome {
		case clampNone:
		case clampApplied:
			// Losing up to renewTimeLeft-ish here is the normal consequence of
			// the CA backdating notBefore and of our own hour-truncation, and
			// happens on every renewal of a config sitting at the provider's
			// maximum lifetime. Only a materially shorter cert is worth a Warn.
			if newValidBefore.Sub(validBefore) > clampWarnThreshold(s.Config.ACME.CertLifeTimeDuration) {
				logging.Warn("Issued cert %v expires at %s, capping validBefore %s -> %s (check certLifeTime)",
					c.domains, notAfter, newValidBefore, validBefore)
			} else {
				logging.Debug("Issued cert %v expires at %s, capping validBefore %s -> %s",
					c.domains, notAfter, newValidBefore, validBefore)
			}
		case clampFloored:
			logging.Warn("Issued cert %v expires at %s, sooner than renewTimeLeft (%s) from now; "+
				"serving it until %s instead of treating it as already expired (check renewTimeLeft)",
				c.domains, notAfter, s.Config.ACME.RenewTimeLeftDuration, validBefore)
		}
	}

	newCert := CertT{
		FullChain:   fullchain,
		Key:         key,
		ValidBefore: validBefore,
		RenewAt:     time.Now(),
	}

	// Broadcast: under stateMu, swap in the new cert + version and
	// close+replace the updated chan. Holding stateMu makes the
	// (cert, version) pair atomic for Snapshot readers and keeps
	// WaitForUpdate's chan snapshot consistent with the version it sees.
	c.stateMu.Lock()
	c.cert = newCert
	c.version++
	close(c.updated)
	c.updated = make(chan struct{})
	c.stateMu.Unlock()

	// Hand off the persisted cert to the cache-file writer. The handoff is
	// gated on the writer's lifecycle (rootCtx), never on the caller's ctx:
	// a cancelled request/subscription must not lose a real ACME issuance
	// that has already been broadcast. Try the buffered channel first, and
	// only then block until the writer takes it or the writer is gone.
	storeEntry := &certStoreEntry{
		Domains: c.domains,
		Cert:    newCert,
	}
	select {
	case s.certStore.update <- storeEntry:
	default:
		select {
		case s.certStore.update <- storeEntry:
		case <-s.rootCtx.Done():
			logging.Warn("Cert store writer stopped, new cert %v was not persisted", c.domains)
		}
	}

	logging.Info("Obtained new cert: %v", c.domains)
	return true, nil
}

// targetValidBefore is the ValidBefore a renewal aims for: certLifeTime past
// the top of the current hour.
//
// The hour truncation keeps renewals aligned on hour boundaries, but it also
// subtracts up to 59m59s of lifetime, so for a certLifeTime shorter than the
// elapsed part of the current hour the truncated target lands in the *past* —
// the freshly issued cert would be born invalid, the SDS handler would never
// offer it, the HTTP handler would answer 503 forever and the renewer would
// re-obtain on every check. Whenever truncation would do that, aim from now
// instead. certLifeTime is validated positive by config, so the result is
// always strictly after now.
func targetValidBefore(now time.Time, certLifeTime time.Duration) time.Time {
	target := now.Truncate(1 * time.Hour).Add(certLifeTime)
	if !target.After(now) {
		return now.Add(certLifeTime)
	}
	return target
}

// clampOutcome reports how clampValidBefore reconciled the configured
// ValidBefore with the leaf's real NotAfter.
type clampOutcome int

const (
	// clampNone: the cert outlives the configured target, nothing to do.
	clampNone clampOutcome = iota
	// clampApplied: ValidBefore was pulled back to NotAfter - renewTimeLeft.
	clampApplied
	// clampFloored: NotAfter - renewTimeLeft is already in the past, so the
	// margin was dropped rather than declaring the new cert invalid at birth.
	clampFloored
)

// clampValidBefore returns the ValidBefore to record for a freshly issued
// cert whose leaf really expires at notAfter.
//
// The configured target is shortened to notAfter - renewTimeLeft so a
// too-generous certLifeTime can't keep an expired cert in service. That
// subtraction has a floor: if the CA issues a cert whose whole lifetime is
// shorter than renewTimeLeft, the clamped value lands in the past and the
// cert would be invalid the moment it was obtained — 503 on every request
// plus one ACME obtain per request. In that case keep min(configured,
// notAfter) instead, which is still a real expiry and always after now
// (configured is, by targetValidBefore). Only a leaf that is already expired
// on arrival falls back to the configured target outright; nothing about
// such a cert is trustworthy and refusing to serve it helps no one.
func clampValidBefore(now, configured, notAfter time.Time, renewTimeLeft time.Duration) (time.Time, clampOutcome) {
	renewBy := notAfter.Add(-renewTimeLeft)
	if !renewBy.Before(configured) {
		return configured, clampNone
	}
	if renewBy.After(now) {
		return renewBy, clampApplied
	}

	clamped := configured
	if notAfter.Before(clamped) {
		clamped = notAfter
	}
	if !clamped.After(now) {
		return configured, clampFloored
	}
	return clamped, clampFloored
}

// clampWarnThreshold is how much shorter than the configured target the
// clamped ValidBefore has to be before it is worth a Warn rather than a
// Debug line. The everyday clamp — a config at the provider's maximum
// lifetime, where the CA backdates notBefore by about an hour and our own
// hour-truncation gives up to another 59m — must not warn on every single
// renewal, but a clamp that eats a real fraction of the configured lifetime
// means certLifeTime is set higher than the provider will ever issue.
func clampWarnThreshold(certLifeTime time.Duration) time.Duration {
	threshold := 2 * time.Hour
	if fraction := certLifeTime / 10; fraction > threshold {
		threshold = fraction
	}
	return threshold
}

// leafNotAfter parses the leaf (first) certificate of a PEM fullchain and
// returns its real expiry.
func leafNotAfter(fullchain []byte) (time.Time, error) {
	rest := fullchain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return time.Time{}, fmt.Errorf("no certificate block in fullchain")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
		}
		return cert.NotAfter, nil
	}
}

func (s *CertDXServer) subscribeCertCacheEntry(ctx context.Context, c *certEntry) {
	logging.Info("Start subscribing cert: %v", c.domains)
	defer logging.Info("Stopped subscribing cert: %v", c.domains)

	// Guard against a server that was built without MakeCertDXServer: a
	// zero backoff would turn the retry path into a busy loop.
	retryMin, retryMax := s.renewRetryMin, s.renewRetryMax
	if retryMin <= 0 {
		retryMin = renewRetryMinInterval
	}
	if retryMax < retryMin {
		retryMax = max(retryMin, renewRetryMaxInterval)
	}

	backoff := retryMin
	for {
		obtained, err := s.renew(ctx, c, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Error("Failed to renew cert %s: %s", c.domains, err)
		}

		// Only the healthy steady state earns the long interval: renew
		// succeeded and the entry now holds a cert (one we just minted, or
		// a still-valid cached one). A failed obtain leaves the entry
		// without a usable cert, so re-check on a short backoff instead of
		// parking it for RenewTimeLeft/4.
		var wait time.Duration
		cert := c.Cert()
		if err == nil && (obtained || cert.IsValid()) {
			wait = s.renewCheckInterval()
			backoff = retryMin
		} else {
			wait = backoff
			backoff = min(backoff*2, retryMax)
			logging.Warn("No usable cert for %v, re-checking in %s", c.domains, wait)
		}

		t := time.NewTimer(wait)
		select {
		case <-t.C:
			// Do next check
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
}

// renewCheckInterval is the healthy-state re-check cadence: a quarter of
// RenewTimeLeft, floored so a zero or negative configured value can't spin
// the renewer.
func (s *CertDXServer) renewCheckInterval() time.Duration {
	interval := s.Config.ACME.RenewTimeLeftDuration / 4
	if interval < renewCheckMinInterval {
		return renewCheckMinInterval
	}
	return interval
}

// Subscribe registers a consumer for the entry's renewal stream. The first
// subscriber kicks off a per-entry renewal goroutine whose context is
// derived from rootCtx (so server Stop signals it); further subscribers just
// bump the refcount.
//
// The renewer is deliberately not registered in s.wg: it can be parked
// inside lego's Obtain, which is not context-aware, so Stop could not
// unblock it and would simply burn shutdownDrainTimeout before giving up —
// long enough to blow past the caller's own shutdown deadline. Renewers are
// best-effort on shutdown; they check rootCtx between attempts, and a cert
// obtained during shutdown is handed to the store writer, which *is* joined.
func (s *CertDXServer) subscribe(c *certEntry) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		start  bool
	)

	c.stateMu.Lock()
	if c.subscribing == 0 {
		ctx, cancel = context.WithCancel(s.rootCtx)
		c.cancelRenew = cancel
		start = true
	}
	c.subscribing++
	c.stateMu.Unlock()

	if start {
		go s.subscribeCertCacheEntry(ctx, c)
	}
}

// Release drops a consumer. When the last consumer leaves, the renewal
// goroutine's context is cancelled and it winds down.
func (s *CertDXServer) release(c *certEntry) {
	var cancel context.CancelFunc

	c.stateMu.Lock()
	if c.subscribing > 0 {
		c.subscribing--
	}
	if c.subscribing == 0 {
		cancel = c.cancelRenew
		c.cancelRenew = nil
		c.stateMu.Unlock()
	} else {
		c.stateMu.Unlock()
	}

	if cancel != nil {
		cancel()
	}
}

func (s *CertDXServer) isSubscribing(c *certEntry) bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.subscribing != 0
}

// Stop signals every server goroutine to wind down and blocks until they
// have. It is safe to call concurrently and from any number of callers; only
// the first call cancels the root context. The wait is bounded by
// shutdownDrainTimeout so a wedged goroutine can't hang shutdown.
func (s *CertDXServer) Stop() {
	s.stopOnce.Do(s.rootCancel)
	s.drain()
}

// Wait blocks until Stop is called (by signal handler, by a failing
// subserver, or by any other caller). main uses it as the single
// blocking point so a subserver crash doesn't leave the process alive
// with no listener. It also joins the subgoroutines, so returning from
// Wait means the cache file has been written out.
func (s *CertDXServer) Wait() {
	<-s.rootCtx.Done()
	s.drain()
}

// drain joins the tracked subgoroutines — the cache-file writer, whose
// shutdown drain would otherwise race process exit and leave cache.json
// truncated mid-write. That writer returns as soon as rootCtx fires, so
// drain is effectively instant; the timeout is only a backstop.
func (s *CertDXServer) drain() {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	t := time.NewTimer(shutdownDrainTimeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		logging.Warn("Timed out after %s waiting for server goroutines to stop", shutdownDrainTimeout)
	}
}
