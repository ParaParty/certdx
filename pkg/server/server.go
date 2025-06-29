package server

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"pkg.para.party/certdx/pkg/types"
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
	entries map[types.DomainKey]*ServerCacheFileEntry
	update  chan *ServerCacheFileEntry
}

type ServerCertCacheEntry struct {
	domains []string
	cert    CertT
	mutex   sync.Mutex

	Subscribing atomic.Uint64
	Updated     atomic.Pointer[chan struct{}]
	Stop        atomic.Pointer[chan struct{}]
}

type ServerCertCache struct {
	entries map[types.DomainKey]*ServerCertCacheEntry
	mutex   sync.Mutex
}

type CertDXServer struct {
	Config config.ServerConfig

	acme      *acme.ACME
	certCache ServerCertCache
	cacheFile ServerCacheFile
	stop      chan struct{}
}

func MakeCertDXServer() *CertDXServer {
	ret := &CertDXServer{
		certCache: makeServerCertCache(),
		cacheFile: MakeServerCacheFile(),
		stop:      make(chan struct{}),
	}
	ret.Config.SetDefault()

	return ret
}

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func makeServerCertCache() ServerCertCache {
	return ServerCertCache{
		entries: make(map[types.DomainKey]*ServerCertCacheEntry),
	}
}

func (s *CertDXServer) Init() error {
	var err error

	s.acme, err = acme.MakeACME(&s.Config)
	if err != nil {
		return fmt.Errorf("initailizing ACME failed, err: %s", err)
	}

	if err = s.loadCacheFile(); err != nil {
		// It's okay that previous saved cert can not be loaded, just log and continue to run
		logging.Warn("load cache file failed, err: %s", err)
	}
	go s.cacheFile.listenUpdate()

	return nil
}

func MakeServerCacheFile() ServerCacheFile {
	cachePath := utils.GetServerCacheSavePath()

	return ServerCacheFile{
		path:    cachePath,
		entries: make(map[types.DomainKey]*ServerCacheFileEntry),
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
			entry.mutex.Lock()
			entry.cert = cache.Cert
			entry.mutex.Unlock()
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
	s.entries[utils.DomainsAsKey(fe.Domains)] = fe

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

func (s *CertDXServer) getCertCacheEntryNoLock(domains []string) *ServerCertCacheEntry {
	entryKey := utils.DomainsAsKey(domains)
	entry, ok := s.certCache.entries[entryKey]
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

	s.certCache.entries[entryKey] = entry
	return entry
}

func (s *CertDXServer) GetCertCacheEntry(domains []string) *ServerCertCacheEntry {
	s.certCache.mutex.Lock()
	defer s.certCache.mutex.Unlock()
	return s.getCertCacheEntryNoLock(domains)
}

func (c *ServerCertCacheEntry) Cert() CertT {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cert
}

func (s *CertDXServer) Renew(c *ServerCertCacheEntry, retry bool) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	logging.Info("Renew cert: %v", c.domains)
	if !c.cert.IsValid() {
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
		c.cert = newCert

		s.cacheFile.update <- &ServerCacheFileEntry{
			Domains: c.domains,
			Cert:    newCert,
		}

		logging.Info("Obtained cert: %v", c.domains)
		return true, nil
	}

	logging.Info("Cert: %v not expired", c.domains)
	return false, nil
}

func (s *CertDXServer) subscribeCertCacheEntry(c *ServerCertCacheEntry) {
	logging.Info("Start subscribing cert: %v", c.domains)
	defer logging.Info("Stopped subscribing cert: %v", c.domains)

	for {
		logging.Info("Server renew: %v", c.domains)
		changed, err := s.Renew(c, true)
		if err != nil {
			logging.Error("Failed to renew cert %s: %s", c.domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			logging.Notice("Notify cert %v updated", c.domains)
			close(*c.Updated.Swap(&newUpdated))
		}

		t := time.NewTimer(s.Config.ACME.RenewTimeLeftDuration / 4)
		select {
		case <-t.C:
			// Do next check
		case <-*c.Stop.Load():
			t.Stop()
			return
		}
	}
}

func (s *CertDXServer) Subscribe(c *ServerCertCacheEntry) {
	if c.Subscribing.Add(1) == 1 {
		go s.subscribeCertCacheEntry(c)
	}
}

func (s *CertDXServer) Release(c *ServerCertCacheEntry) {
	if c.Subscribing.Add(math.MaxUint64) == 0 {
		*c.Stop.Load() <- struct{}{}
	}
}

func (s *CertDXServer) IsSubcribing(c *ServerCertCacheEntry) bool {
	return c.Subscribing.Load() != 0
}

func (s *CertDXServer) Stop() {
	close(s.stop)
	s.stop = nil
}
