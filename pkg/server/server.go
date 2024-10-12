package server

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/utils"
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
var serverCertCache = ServerCertCacheT{
	entries: make(map[string]*ServerCertCacheEntry),
}
var Config = &config.ServerConfigT{}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func InitCache() {
	if err := serverCacheFile.loadCacheFile(); err != nil {
		logging.Warn("Failed to load cache file, err: %s", err)
	}

	go serverCacheFile.listenUpdate()
}

func (s *ServerCacheFile) loadCacheFile() error {
	cachePath, exist := utils.GetServerCacheSavePath()
	if !exist {
		return nil
	}

	cfile, err := os.ReadFile(cachePath)
	if err != nil {
		return fmt.Errorf("opening cache file failed: %w", err)
	}

	entries := make(map[string]*ServerCacheFileEntry)
	err = json.Unmarshal(cfile, &entries)
	if err != nil {
		return fmt.Errorf("unmarshaling cache file failed: %w", err)
	}

	serverCertCache.mutex.Lock()
	for _, cache := range entries {
		if cache.Cert.IsValid() {
			s.entries[domainsAsKey(cache.Domains)] = cache

			entry := serverCertCache.getEntryNoLock(cache.Domains)
			entry.mutex.Lock()
			entry.cert = cache.Cert
			entry.mutex.Unlock()
		}
	}
	serverCertCache.mutex.Unlock()

	logging.Info("Previous cache loaded.")
	return nil
}

func (s *ServerCacheFile) writeCacheFile(fe *ServerCacheFileEntry) error {
	s.entries[domainsAsKey(fe.Domains)] = fe

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

func (s *ServerCacheFile) listenUpdate() {
	cachePath, _ := utils.GetServerCacheSavePath()
	serverCacheFile.path = cachePath

	for fe := range s.update {
		logging.Info("Update domains cache to file")
		if err := s.writeCacheFile(fe); err != nil {
			logging.Warn("Update domains cache to file failed, err: %s", err)
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

	logging.Info("Renew cert: %v", c.domains)
	if !c.cert.IsValid() {
		newValidBefore := time.Now().Truncate(1 * time.Hour).Add(Config.ACME.CertLifeTimeDuration)

		acme, err := acme.MakeACME(Config)
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

		logging.Info("Obtained cert: %v", c.domains)
		return true, nil
	}

	logging.Info("Cert: %v not expired", c.domains)
	return false, nil
}

func (c *ServerCertCacheEntry) certWatchDog() {
	logging.Info("Starting cert watch dog for: %v", c.domains)
	defer logging.Info("Cert watch dog for: %v stopped", c.domains)

	for {
		logging.Info("Server renew: %v", c.domains)
		changed, err := c.Renew(true)
		if err != nil {
			logging.Error("Failed to renew cert %s: %s", c.domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			logging.Notice("Notify cert %v updated", c.domains)
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

func (c *ServerCertCacheEntry) Subscribe() {
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
