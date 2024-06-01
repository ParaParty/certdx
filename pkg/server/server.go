package server

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pkg.para.party/certdx/pkg/config"
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
	entries map[string]*ServerCacheFileEntry
	update  chan *ServerCacheFileEntry
}

type ServerCertCacheEntry struct {
	domains []string
	cert    CertT
	mutex   sync.Mutex

	Listening atomic.Uint64
	Updated   atomic.Pointer[chan struct{}]
	Stop      atomic.Pointer[chan struct{}]
}

type ServerCertCacheT struct {
	entries map[string]*ServerCertCacheEntry
	mutex   sync.Mutex
}

var serverCacheFile = ServerCacheFile{
	entries: make(map[string]*ServerCacheFileEntry),
	update:  make(chan *ServerCacheFileEntry, 10),
}
var ServerCertCache = ServerCertCacheT{
	entries: make(map[string]*ServerCertCacheEntry),
}
var Config = &config.ServerConfigT{}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func InitCache() {
	if err := serverCacheFile.loadCacheFile(); err != nil {
		log.Printf("[WRN] Failed to load cache file: %s", err)
	}

	go serverCacheFile.listenUpdate()
}

func (s *ServerCacheFile) loadCacheFile() error {
	cachePath, exist := getCacheSavePath()
	if !exist {
		return nil
	}

	cfile, err := os.ReadFile(cachePath)
	if err != nil {
		return fmt.Errorf("open cache file failed: %w", err)
	}

	entries := make(map[string]*ServerCacheFileEntry)
	err = json.Unmarshal(cfile, &entries)
	if err != nil {
		return fmt.Errorf("unmarshal cache file failed: %w", err)
	}

	ServerCertCache.mutex.Lock()
	for _, cache := range entries {
		if cache.Cert.IsValid() {
			s.entries[domainsAsKey(cache.Domains)] = cache

			entry := ServerCertCache.getEntryNoLock(cache.Domains)
			entry.mutex.Lock()
			entry.cert = cache.Cert
			entry.mutex.Unlock()
		}
	}
	ServerCertCache.mutex.Unlock()

	log.Printf("[INF] Previous cache loaded.")
	return nil
}

func (s *ServerCacheFile) writeCacheFile(fe *ServerCacheFileEntry) error {
	s.entries[domainsAsKey(fe.Domains)] = fe

	jsonBytes, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("failed marshal cache file: %w", err)
	}

	err = os.WriteFile(s.path, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed write cache file: %w", err)
	}

	return nil
}

func (s *ServerCacheFile) listenUpdate() {
	cachePath, _ := getCacheSavePath()
	serverCacheFile.path = cachePath

	for fe := range s.update {
		log.Printf("[INF] Update domains cache to file")
		if err := s.writeCacheFile(fe); err != nil {
			log.Printf("[WRN] Update domains cache to file failed: %s", err)
		}
	}
}

func domainsAsKey(domains []string) string {
	return strings.Join(domains, "&_&")
}

func (s *ServerCertCacheT) getEntryNoLock(domains []string) *ServerCertCacheEntry {
	entryKey := domainsAsKey(domains)
	entry, ok := s.entries[entryKey]
	if ok {
		return entry
	}

	entry = &ServerCertCacheEntry{
		domains: domains,
	}
	updated := make(chan struct{})
	entry.Updated.Store(&updated)
	stop := make(chan struct{})
	entry.Stop.Store(&stop)

	s.entries[entryKey] = entry
	return entry
}

func (s *ServerCertCacheT) GetEntry(domains []string) *ServerCertCacheEntry {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.getEntryNoLock(domains)
}

func (c *ServerCertCacheEntry) Cert() CertT {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cert
}

func (c *ServerCertCacheEntry) Renew(retry bool) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.Printf("[INF] Renew cert: %v", c.domains)
	if !c.cert.IsValid() {
		newValidBefore := time.Now().Truncate(1 * time.Hour).Add(Config.ACME.CertLifeTimeDuration)

		acme, err := MakeACME()
		if err != nil {
			return false, err
		}

		var fullchain, key []byte
		if retry {
			fullchain, key, err = acme.RetryObtain(c.domains, newValidBefore.Add(Config.ACME.RenewTimeLeftDuration))
		} else {
			fullchain, key, err = acme.Obtain(c.domains, newValidBefore.Add(Config.ACME.RenewTimeLeftDuration))
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
		c.cert = newCert

		serverCacheFile.update <- &ServerCacheFileEntry{
			Domains: c.domains,
			Cert:    newCert,
		}

		log.Printf("[INF] Obtained cert: %v", c.domains)
		return true, nil
	}

	log.Printf("[INF] Cert: %v not expired", c.domains)
	return false, nil
}

func (c *ServerCertCacheEntry) certWatchDog() {
	log.Printf("[INF] start cert watch dog for: %v", c.domains)
	defer log.Printf("[INF] stop cert watch dog for: %v", c.domains)

	for {
		log.Printf("[INF] Server renew: %v", c.domains)
		changed, err := c.Renew(true)
		if err != nil {
			log.Printf("[ERR] Failed renew cert %s: %s", c.domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			log.Printf("[INF] Notify cert %v updated", c.domains)
			close(*c.Updated.Swap(&newUpdated))
		}

		t := time.NewTimer(Config.ACME.RenewTimeLeftDuration / 4)
		select {
		case <-t.C:
			// Do next check
		case <-*c.Stop.Load():
			t.Stop()
			return
		}
	}
}

func (c *ServerCertCacheEntry) Subscrib() {
	if c.Listening.Add(1) == 1 {
		go c.certWatchDog()
	}
}

func (c *ServerCertCacheEntry) Release() {
	if c.Listening.Add(math.MaxUint64) == 0 {
		*c.Stop.Load() <- struct{}{}
	}
}

func (c *ServerCertCacheEntry) IsSubcribing() bool {
	return c.Listening.Load() != 0
}

func isSubdomain(domain string, allowedDomains []string) bool {
	for _, allowedDomain := range allowedDomains {
		if allowedDomain == domain {
			return true
		}
		if strings.HasSuffix(domain, "."+allowedDomain) {
			return true
		}
	}
	return false
}

func domainsAllowed(domains []string) bool {
	for _, i := range domains {
		if !isSubdomain(i, Config.ACME.AllowedDomains) {
			return false
		}
	}
	return true
}
