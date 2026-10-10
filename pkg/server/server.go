package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

const (
	// Retry backoff while an entry holds no valid cert.
	renewRetryMin = 30 * time.Second
	renewRetryMax = 5 * time.Minute
	// Floor for the healthy re-check so a cert at the edge of its validity
	// can't spin the renewer.
	renewCheckMin = 5 * time.Second
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
	certStore *CertStore

	// rootCtx is the lifecycle parent for every server subgoroutine
	// (HttpSrv, SDSSrv, every per-entry renewer).
	// Stop cancels it exactly once via stopOnce. There is no separate
	// stop chan — context cancellation is the single signal.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	stopOnce   sync.Once
}

func MakeCertDXServer() (*CertDXServer, error) {
	store, err := NewCertStore()
	if err != nil {
		return nil, err
	}
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ret := &CertDXServer{
		certCache:  makeCertCache(),
		certStore:  store,
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
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

	if err = s.loadCertStore(); err != nil {
		// It's okay that previous saved cert can not be loaded, just log and continue to run
		logging.Warn("Load cache file failed: %s", err)
	}

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

	if notAfter, err := leafNotAfter(fullchain); err != nil {
		logging.Warn("Could not read NotAfter of issued cert %v: %s", c.domains, err)
	} else if clamped := clampValidBefore(time.Now(), newValidBefore, notAfter, s.Config.ACME.RenewTimeLeftDuration); !clamped.Equal(newValidBefore) {
		logging.Info("Issued cert %v expires at %s, renewing it from %s", c.domains, notAfter, clamped)
		newValidBefore = clamped
	}

	newCert := CertT{
		FullChain:   fullchain,
		Key:         key,
		ValidBefore: newValidBefore,
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

	// Persisted regardless of ctx: the cert is already issued and broadcast.
	if err := s.certStore.saveEntry(&certStoreEntry{Domains: c.domains, Cert: newCert}); err != nil {
		logging.Warn("Update domains cache to file failed: %s", err)
	}

	logging.Info("Obtained new cert: %v", c.domains)
	return true, nil
}

func (s *CertDXServer) subscribeCertCacheEntry(ctx context.Context, c *certEntry) {
	logging.Info("Start subscribing cert: %v", c.domains)
	defer logging.Info("Stopped subscribing cert: %v", c.domains)

	backoff := renewRetryMin
	for {
		_, err := s.renew(ctx, c, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Error("Failed to renew cert %s: %s", c.domains, err)
		}

		var wait time.Duration
		if cert := c.Cert(); cert.IsValid() {
			wait = s.renewCheckInterval(time.Now(), cert.ValidBefore)
			backoff = renewRetryMin
		} else {
			wait = backoff
			backoff = min(backoff*2, renewRetryMax)
			logging.Warn("No valid cert for %v, retrying in %s", c.domains, wait)
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

// renewCheckInterval is how long a renewer holding a valid cert sleeps:
// RenewTimeLeft/4, but never past validBefore and never below renewCheckMin.
func (s *CertDXServer) renewCheckInterval(now, validBefore time.Time) time.Duration {
	interval := min(s.Config.ACME.RenewTimeLeftDuration/4, validBefore.Sub(now))
	return max(interval, renewCheckMin)
}

// Subscribe registers a consumer for the entry's renewal stream. The first
// subscriber kicks off a per-entry renewal goroutine whose context is
// derived from rootCtx (so server Stop drains it cleanly); further
// subscribers just bump the refcount.
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

// Stop signals every server goroutine to wind down. It is safe to call
// concurrently and from any number of callers; only the first call cancels
// the root context.
func (s *CertDXServer) Stop() {
	s.stopOnce.Do(s.rootCancel)
}

// Wait blocks until Stop is called (by signal handler, by a failing
// subserver, or by any other caller). main uses it as the single
// blocking point so a subserver crash doesn't leave the process alive
// with no listener.
func (s *CertDXServer) Wait() {
	<-s.rootCtx.Done()
}
