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

var serverCacheFile = MakeServerCacheFile()
var serverCertCache = makeServerCertCache()
var Config = &config.ServerConfigT{}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func (c *CertT) IsNeedRenew() bool {
	return time.Now().Before(c.ValidBefore.Add(-Config.ACME.RenewTimeLeftDuration))
}

func makeServerCertCache() ServerCertCacheT {
	return ServerCertCacheT{
		entries: make(map[string]*ServerCertCacheEntry),
	}
}

func InitCache() {
	if err := serverCacheFile.loadCacheFile(); err != nil {
		logging.Warn("Failed to load cache file, err: %s", err)
	}

	go serverCacheFile.listenUpdate()
}

func MakeServerCacheFile() ServerCacheFile {
	cachePath := utils.GetServerCacheSavePath()

	return ServerCacheFile{
		path:    cachePath,
		entries: make(map[string]*ServerCacheFileEntry),
		update:  make(chan *ServerCacheFileEntry, 10),
	}
}

func (s *ServerCacheFile) ReadCacheFile() error {
	exist := utils.FileExists(s.path)
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

func (s *ServerCacheFile) loadCacheFile() error {
	err := s.ReadCacheFile()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return err
		}
	}

	serverCertCache.mutex.Lock()
	for key, cache := range s.entries {
		if cache.Cert.IsValid() {
			entry := serverCertCache.getEntryNoLock(cache.Domains)
			entry.mutex.Lock()
			entry.cert = cache.Cert
			entry.mutex.Unlock()
		} else {
			delete(s.entries, key)
		}
	}
	serverCertCache.mutex.Unlock()

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
	s.entries[domainsAsKey(fe.Domains)] = fe

	return s.writeCacheFile()
}

func (s *ServerCacheFile) PrintCertInfo() {
	for _, cert := range s.entries {
		fmt.Printf("\nDomains:     %s\nRenewAt:     %s\nValidBefore: %s\n", strings.Join(cert.Domains, ", "), cert.Cert.RenewAt, cert.Cert.ValidBefore)
	}
}

func (s *ServerCacheFile) listenUpdate() {
	for fe := range s.update {
		logging.Info("Update domains cache to file")
		if err := s.updateCacheFileEntry(fe); err != nil {
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
	if !c.cert.IsNeedRenew() {
		newValidBefore := time.Now().Truncate(1 * time.Hour).Add(Config.ACME.CertLifeTimeDuration)

		acme := acme.GetACME()

		var fullchain, key []byte
		var err error
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
