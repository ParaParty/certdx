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

	// rootCtx is the lifecycle parent for every server subgoroutine
	// (HttpSrv, SDSSrv, the cache-file writer, every per-entry renewer).
	// Stop cancels it exactly once via stopOnce. There is no separate
	// stop chan — context cancellation is the single signal.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	stopOnce   sync.Once
}

func MakeCertDXServer() *CertDXServer {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ret := &CertDXServer{
		certCache:  makeCertCache(),
		certStore:  NewCertStore(),
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
	}
	ret.Config.SetDefault()

	return ret
}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func (s *CertDXServer) Init() error {
	var err error

	s.acme, err = acme.MakeACME(&s.Config)
	if err != nil {
		return fmt.Errorf("initailizing ACME failed: %w", err)
	}

	if err = s.loadCertStore(); err != nil {
		// It's okay that previous saved cert can not be loaded, just log and continue to run
		logging.Warn("load cache file failed, err: %s", err)
	}
	go s.certStore.listenUpdate(s.rootCtx)

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
	for key, cache := range s.certStore.entries {
		if cache.Cert.IsValid() {
			entry := s.certCache.getNoLock(cache.Domains)
			entry.stateMu.Lock()
			entry.cert = cache.Cert
			entry.stateMu.Unlock()
		} else {
			delete(s.certStore.entries, key)
		}
	}
	s.certCache.mutex.Unlock()

	logging.Info("Previous cache loaded.")
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

	logging.Info("Renew cert: %v", c.domains)
	// Re-check under renewMu: if a concurrent caller already refreshed the
	// cert while we were waiting on the mutex, observe the fresh cert and
	// skip the ACME round-trip. This collapses concurrent expired-cert
	// fetches into one ACME call.
	current, _ := c.Snapshot()
	if current.IsValid() {
		logging.Info("Cert: %v not expired", c.domains)
		return false, nil
	}

	newValidBefore := time.Now().Truncate(1 * time.Hour).Add(s.Config.ACME.CertLifeTimeDuration)

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

	// Hand off the persisted cert to the cache-file writer. If the writer
	// has already exited (e.g. Stop fired and drained the buffer), we
	// honor ctx instead of blocking forever on a buffered send that no
	// one will receive.
	select {
	case s.certStore.update <- &certStoreEntry{
		Domains: c.domains,
		Cert:    newCert,
	}:
	case <-ctx.Done():
		return true, nil
	}

	logging.Info("Obtained cert: %v", c.domains)
	return true, nil
}

func (s *CertDXServer) subscribeCertCacheEntry(ctx context.Context, c *certEntry) {
	logging.Info("Start subscribing cert: %v", c.domains)
	defer logging.Info("Stopped subscribing cert: %v", c.domains)

	for {
		logging.Info("Server renew: %v", c.domains)
		_, err := s.renew(ctx, c, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Error("Failed to renew cert %s: %s", c.domains, err)
		}

		t := time.NewTimer(s.Config.ACME.RenewTimeLeftDuration / 4)
		select {
		case <-t.C:
			// Do next check
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
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
