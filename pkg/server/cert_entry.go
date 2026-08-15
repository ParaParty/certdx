package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
)

var (
	// ErrNoDomains is returned when a cert is requested for an empty domain
	// set. Such a request can never produce a certificate, so it is rejected
	// at the cache boundary instead of creating a useless entry.
	ErrNoDomains = errors.New("no domains requested")

	// ErrCacheFull is returned when a new cert pack would exceed the
	// configured cache-entry cap. Wrapped with the offending domains.
	ErrCacheFull = errors.New("cert cache entry limit reached")
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
//   - subscribing is the consumer refcount, guarded by stateMu. subscribe
//     transitions 0->1 spawn the renewal goroutine; release transitions 1->0
//     cancel it via cancelRenew.
type certEntry struct {
	domains []string
	// canonical is domains in the same canonical form domain.AsKey hashes.
	// Cache lookups compare against it so a Key collision can never hand
	// back a cert pack whose domain set differs from the requested one.
	canonical []string

	renewMu sync.Mutex // serializes Renew (held during ACME)

	stateMu     sync.Mutex // brief; guards everything below
	cert        CertT
	version     uint64
	updated     chan struct{} // closed on each successful renewal, then replaced
	cancelRenew context.CancelFunc

	subscribing int64
}

// certCache maps a domain.Key to the cert packs stored under it. The value is
// a slice because domain.Key is a 64-bit hash: two different domain sets can
// collide, and serving one set's cert to the other would be a mis-issuance, so
// colliding packs live side by side and are told apart by their canonical
// domain lists.
type certCache struct {
	entries map[domain.Key][]*certEntry
	mutex   sync.Mutex

	// maxEntries caps the number of distinct cert packs held. Zero (the
	// default) means unlimited, which preserves the historical behavior for
	// configs that don't set it.
	maxEntries int
	size       int
}

func makeCertCache() certCache {
	return certCache{
		entries: make(map[domain.Key][]*certEntry),
	}
}

func newCertEntry(domains []string) *certEntry {
	return &certEntry{
		domains:   domains,
		canonical: canonicalDomains(domains),
		updated:   make(chan struct{}),
	}
}

// canonicalDomains returns domains in the canonical form domain.AsKey hashes:
// lower-cased, trailing root dot trimmed, empty names dropped, de-duplicated
// and sorted. Two slices describing the same domain set canonicalize equal.
func canonicalDomains(domains []string) []string {
	canon := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		canon = append(canon, d)
	}
	sort.Strings(canon)
	return canon
}

// getNoLock returns the entry for domains, creating it if absent. The caller
// must hold c.mutex. It fails on an empty domain set and when a new entry
// would exceed maxEntries; on a Key hit whose stored domain set differs, a
// separate entry is created rather than handing back the wrong cert pack.
func (c *certCache) getNoLock(domains []string) (*certEntry, error) {
	canon := canonicalDomains(domains)
	if len(canon) == 0 {
		return nil, ErrNoDomains
	}

	entryKey := domain.AsKey(domains)
	stored := c.entries[entryKey]
	for _, entry := range stored {
		if slices.Equal(entry.canonical, canon) {
			return entry, nil
		}
	}
	if len(stored) != 0 {
		logging.Warn("Cert cache key collision: requested %v does not match stored %v, using a separate entry",
			domains, stored[0].domains)
	}

	if c.maxEntries > 0 && c.size >= c.maxEntries {
		return nil, fmt.Errorf("%w (%d), refusing cert pack %v", ErrCacheFull, c.maxEntries, domains)
	}

	entry := newCertEntry(domains)
	c.entries[entryKey] = append(stored, entry)
	c.size++
	return entry, nil
}

func (c *certCache) get(domains []string) (*certEntry, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getNoLock(domains)
}

// setMaxEntries applies the configured cap on distinct cert packs. Zero or
// negative means unlimited. Existing entries are never evicted; the cap only
// refuses new ones.
func (c *certCache) setMaxEntries(max int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if max < 0 {
		max = 0
	}
	c.maxEntries = max
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
