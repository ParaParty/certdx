package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
)

type CertT struct {
	FullChain   []byte    `json:"fullChain"`
	Key         []byte    `json:"key"`
	ValidBefore time.Time `json:"validBefore"`
	RenewAt     time.Time `json:"renewAt"`
}

type ServerCacheFileEntry struct {
	Domains []string `json:"domains"`
	Cert    CertT    `json:"cert"`
}

type ServerCacheFile struct {
	path    string
	entries map[domain.Key]*ServerCacheFileEntry
	update  chan *ServerCacheFileEntry
}

// ServerCertCacheEntry holds one domain bundle's cached cert, the
// "renewed" broadcast channel, and the renewal-goroutine lifecycle.
//
// Concurrency:
//
//   - renewMu serializes concurrent Renew calls; held for the duration
//     of the ACME obtain so a single in-flight call wins per renewal.
//   - stateMu protects everything that is not the ACME call: the
//     cert/version pair, the `updated` chan swap, and the cancelRenew
//     handle that Subscribe / Release shuffle. It is held only briefly,
//     so readers (Snapshot, WaitForUpdate) never block waiting on an
//     ACME call to finish.
//   - Subscribing is the consumer refcount. Subscribe transitions 0→1
//     spawn the renewal goroutine; Release transitions 1→0 cancel it
//     via cancelRenew.
type ServerCertCacheEntry struct {
	domains []string

	renewMu sync.Mutex // serializes Renew (held during ACME)

	stateMu     sync.Mutex // brief; guards everything below
	cert        CertT
	version     uint64
	updated     chan struct{} // closed on each successful renewal, then replaced
	cancelRenew context.CancelFunc

	Subscribing atomic.Int64
}

type ServerCertCache struct {
	entries map[domain.Key]*ServerCertCacheEntry
	mutex   sync.Mutex
}

type CertDXServer struct {
	Config config.ServerConfig

	acme      acme.Obtainer
	certCache ServerCertCache
	cacheFile ServerCacheFile

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
		certCache:  makeServerCertCache(),
		cacheFile:  MakeServerCacheFile(),
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
	}
	ret.Config.SetDefault()

	return ret
}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func makeServerCertCache() ServerCertCache {
	return ServerCertCache{
		entries: make(map[domain.Key]*ServerCertCacheEntry),
	}
}

func (s *CertDXServer) Init() error {
	var err error

	s.acme, err = acme.MakeACME(&s.Config)
	if err != nil {
		return fmt.Errorf("initailizing ACME failed: %w", err)
	}

	if err = s.loadCacheFile(); err != nil {
		// It's okay that previous saved cert can not be loaded, just log and continue to run
		logging.Warn("load cache file failed, err: %s", err)
	}
	go s.cacheFile.listenUpdate(s.rootCtx)

	return nil
}

func MakeServerCacheFile() ServerCacheFile {
	cachePath := paths.ServerCacheSave()

	return ServerCacheFile{
		path:    cachePath,
		entries: make(map[domain.Key]*ServerCacheFileEntry),
		update:  make(chan *ServerCacheFileEntry, 10),
	}
}

func (s *ServerCacheFile) ReadCacheFile() error {
	exist := paths.FileExists(s.path)
	if !exist {
		return os.ErrNotExist
	}

	cfile, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("opening cache file failed: %w", err)
	}

	err = json.Unmarshal(cfile, &s.entries)
	if err != nil {
		return fmt.Errorf("unmarshaling cache file failed: %w", err)
	}

	return nil
}

func (s *CertDXServer) loadCacheFile() error {
	err := s.cacheFile.ReadCacheFile()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return err
		}
	}

	s.certCache.mutex.Lock()
	for key, cache := range s.cacheFile.entries {
		if cache.Cert.IsValid() {
			entry := s.getCertCacheEntryNoLock(cache.Domains)
			entry.stateMu.Lock()
			entry.cert = cache.Cert
			entry.stateMu.Unlock()
		} else {
			delete(s.cacheFile.entries, key)
		}
	}
	s.certCache.mutex.Unlock()

	logging.Info("Previous cache loaded.")
	return nil
}

func (s *ServerCacheFile) writeCacheFile() error {
	jsonBytes, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("failed to marshal cache file: %w", err)
	}

	err = os.WriteFile(s.path, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

func (s *ServerCacheFile) updateCacheFileEntry(fe *ServerCacheFileEntry) error {
	s.entries[domain.AsKey(fe.Domains)] = fe

	return s.writeCacheFile()
}

func (s *ServerCacheFile) PrintCertInfo() {
	for _, cert := range s.entries {
		fmt.Printf("\nDomains:     %s\nRenewAt:     %s\nValidBefore: %s\n", strings.Join(cert.Domains, ", "), cert.Cert.RenewAt, cert.Cert.ValidBefore)
	}
}

// listenUpdate drains the cache-file update queue, persisting each
// renewed cert to disk. It exits when ctx is done so it shares the
// server's lifecycle.
func (s *ServerCacheFile) listenUpdate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case fe := <-s.update:
			logging.Info("Update domains cache to file")
			if err := s.updateCacheFileEntry(fe); err != nil {
				logging.Warn("Update domains cache to file failed, err: %s", err)
			}
		}
	}
}

func (s *CertDXServer) getCertCacheEntryNoLock(domains []string) *ServerCertCacheEntry {
	entryKey := domain.AsKey(domains)
	entry, ok := s.certCache.entries[entryKey]
	if ok {
		return entry
	}

	entry = &ServerCertCacheEntry{
		domains: domains,
		updated: make(chan struct{}),
	}

	s.certCache.entries[entryKey] = entry
	return entry
}

func (s *CertDXServer) GetCertCacheEntry(domains []string) *ServerCertCacheEntry {
	s.certCache.mutex.Lock()
	defer s.certCache.mutex.Unlock()
	return s.getCertCacheEntryNoLock(domains)
}

// Snapshot returns the current cert and the version that minted it. The
// pair is read atomically under stateMu so callers get a consistent
// view: any subsequent renewal observed via WaitForUpdate is guaranteed
// to be a strictly newer version than the one returned here.
func (c *ServerCertCacheEntry) Snapshot() (CertT, uint64) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.cert, c.version
}

// Cert returns the current cached cert.
func (c *ServerCertCacheEntry) Cert() CertT {
	cert, _ := c.Snapshot()
	return cert
}

// WaitForUpdate blocks until the entry's version moves past seen, or
// until ctx is done. Returns the current version after waking. Callers
// should check ctx.Err() to distinguish "new version" from "ctx fired".
//
// stateMu is held only briefly to snapshot the current `updated` chan;
// the long blocking select happens with the mutex released. The
// renewer's update of cert/version and the chan swap happen together
// under stateMu, so a wait that observed an old version is guaranteed
// to be sleeping on the same chan the renewer will close.
func (c *ServerCertCacheEntry) WaitForUpdate(ctx context.Context, seen uint64) uint64 {
	c.stateMu.Lock()
	if c.version != seen {
		v := c.version
		c.stateMu.Unlock()
		return v
	}
	ch := c.updated
	c.stateMu.Unlock()

	select {
	case <-ch:
	case <-ctx.Done():
	}

	c.stateMu.Lock()
	v := c.version
	c.stateMu.Unlock()
	return v
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
func (s *CertDXServer) renew(ctx context.Context, c *ServerCertCacheEntry, retry bool) (bool, error) {
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
		fullchain, key, err = s.acme.RetryObtain(c.domains, newValidBefore.Add(s.Config.ACME.RenewTimeLeftDuration))
	} else {
		fullchain, key, err = s.acme.Obtain(c.domains, newValidBefore.Add(s.Config.ACME.RenewTimeLeftDuration))
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
	case s.cacheFile.update <- &ServerCacheFileEntry{
		Domains: c.domains,
		Cert:    newCert,
	}:
	case <-ctx.Done():
		return true, nil
	}

	logging.Info("Obtained cert: %v", c.domains)
	return true, nil
}

func (s *CertDXServer) subscribeCertCacheEntry(ctx context.Context, c *ServerCertCacheEntry) {
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
func (s *CertDXServer) Subscribe(c *ServerCertCacheEntry) {
	if c.Subscribing.Add(1) == 1 {
		ctx, cancel := context.WithCancel(s.rootCtx)
		c.stateMu.Lock()
		c.cancelRenew = cancel
		c.stateMu.Unlock()
		go s.subscribeCertCacheEntry(ctx, c)
	}
}

// Release drops a consumer. When the last consumer leaves, the renewal
// goroutine's context is cancelled and it winds down.
func (s *CertDXServer) Release(c *ServerCertCacheEntry) {
	if c.Subscribing.Add(-1) == 0 {
		c.stateMu.Lock()
		cancel := c.cancelRenew
		c.cancelRenew = nil
		c.stateMu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

func (s *CertDXServer) IsSubcribing(c *ServerCertCacheEntry) bool {
	return c.Subscribing.Load() != 0
}

// Stop signals every server goroutine to wind down. It is safe to call
// concurrently and from any number of callers; only the first call cancels
// the root context.
func (s *CertDXServer) Stop() {
	s.stopOnce.Do(s.rootCancel)
}
