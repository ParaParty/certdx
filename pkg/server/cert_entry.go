package server

import (
	"context"
	"sync"
	"sync/atomic"

	"pkg.para.party/certdx/pkg/domain"
)

// certEntry holds one domain bundle's cached cert, the "renewed" broadcast
// channel, and the renewal-goroutine lifecycle.
//
// Concurrency:
//
//   - renewMu serializes concurrent Renew calls; held for the duration of the
//     ACME obtain so a single in-flight call wins per renewal.
//   - stateMu protects everything that is not the ACME call: the cert/version
//     pair, the `updated` chan swap, and the cancelRenew handle that
//     subscribe / release shuffle. It is held only briefly, so readers
//     (Snapshot, WaitForUpdate) never block waiting on an ACME call to finish.
//   - subscribing is the consumer refcount. subscribe transitions 0->1 spawn
//     the renewal goroutine; release transitions 1->0 cancel it via
//     cancelRenew.
type certEntry struct {
	domains []string

	renewMu sync.Mutex // serializes Renew (held during ACME)

	stateMu     sync.Mutex // brief; guards everything below
	cert        CertT
	version     uint64
	updated     chan struct{} // closed on each successful renewal, then replaced
	cancelRenew context.CancelFunc

	subscribing atomic.Int64
}

type certCache struct {
	entries map[domain.Key]*certEntry
	mutex   sync.Mutex
}

func makeCertCache() certCache {
	return certCache{
		entries: make(map[domain.Key]*certEntry),
	}
}

func newCertEntry(domains []string) *certEntry {
	return &certEntry{
		domains: domains,
		updated: make(chan struct{}),
	}
}

func (c *certCache) getNoLock(domains []string) *certEntry {
	entryKey := domain.AsKey(domains)
	entry, ok := c.entries[entryKey]
	if ok {
		return entry
	}

	entry = newCertEntry(domains)
	c.entries[entryKey] = entry
	return entry
}

func (c *certCache) get(domains []string) *certEntry {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getNoLock(domains)
}

// Snapshot returns the current cert and the version that minted it. The pair
// is read atomically under stateMu so callers get a consistent view: any
// subsequent renewal observed via WaitForUpdate is guaranteed to be a strictly
// newer version than the one returned here.
func (c *certEntry) Snapshot() (CertT, uint64) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.cert, c.version
}

// Cert returns the current cached cert.
func (c *certEntry) Cert() CertT {
	cert, _ := c.Snapshot()
	return cert
}

// WaitForUpdate blocks until the entry's version moves past seen, or until ctx
// is done. Returns the current version after waking. Callers should check
// ctx.Err() to distinguish "new version" from "ctx fired".
//
// stateMu is held only briefly to snapshot the current `updated` chan; the long
// blocking select happens with the mutex released. The renewer's update of
// cert/version and the chan swap happen together under stateMu, so a wait that
// observed an old version is guaranteed to be sleeping on the same chan the
// renewer will close.
func (c *certEntry) WaitForUpdate(ctx context.Context, seen uint64) uint64 {
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
