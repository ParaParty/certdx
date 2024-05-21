package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/utils"
)

type CertT struct {
	FullChain   []byte    `json:"fullChain"`
	Key         []byte    `json:"key"`
	ValidBefore time.Time `json:"validBefore"`
}

type ServerCacheFileEntry struct {
	Domains []string `json:"domains"`
	Cert    CertT    `json:"cert"`
}

type ServerCacheFile []*ServerCacheFileEntry

type ServerCertCacheEntry struct {
	domains []string
	cert    CertT
	mutex   sync.Mutex

	Listening atomic.Bool
	Updated   atomic.Pointer[chan struct{}]
	Stop      atomic.Pointer[chan struct{}]
}

type ServerCertCacheT struct {
	entrys []*ServerCertCacheEntry
	mutex  sync.Mutex
}

var serverCacheFile = ServerCacheFile{}
var ServerCertCache = ServerCertCacheT{}
var Config = &config.ServerConfigT{}
var UpdateCacheFileChan = make(chan *ServerCacheFileEntry, 1)

func (c *CertT) IsValid() bool {
	return time.Now().Before(c.ValidBefore)
}

func (s *ServerCacheFile) GetIndex(domains []string) int {
	for index, fe := range *s {
		if utils.SameCert(fe.Domains, domains) {
			return index
		}
	}
	return -1
}

func InitCache() error {
	if err := loadCacheFile(); err != nil {
		return err
	}

	go func() {
		for fe := range UpdateCacheFileChan {
			log.Printf("[INF] Update domains cache to file")
			if err := writeCacheFile(fe); err != nil {
				log.Printf("[WRN] Update domains cache to file failed: %s", err)
			}
		}
	}()

	return nil
}

func loadCacheFile() error {
	cachePath, exist := getCacheSavePath()
	if !exist {
		return nil
	}

	cfile, err := os.ReadFile(cachePath)
	if err != nil {
		return fmt.Errorf("open cache file failed: %w", err)
	}

	err = json.Unmarshal(cfile, &serverCacheFile)
	if err != nil {
		return fmt.Errorf("unmarshal cache file failed: %w", err)
	}

	for _, cache := range serverCacheFile {
		if cache.Cert.IsValid() {
			entry := ServerCertCache.GetEntry(cache.Domains)
			entry.mutex.Lock()
			entry.cert = cache.Cert
			entry.mutex.Unlock()
		}
	}

	log.Printf("[INF] Previous cache loaded.")
	return nil
}

func writeCacheFile(fe *ServerCacheFileEntry) error {
	index := serverCacheFile.GetIndex(fe.Domains)
	if index == -1 {
		serverCacheFile = append(serverCacheFile, fe)
	} else {
		serverCacheFile[index] = fe
	}

	jsonBytes, err := json.Marshal(serverCacheFile)
	if err != nil {
		return fmt.Errorf("failed marshal cache file: %w", err)
	}

	cachePath, _ := getCacheSavePath()
	err = os.WriteFile(cachePath, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed write cache file: %w", err)
	}

	return nil
}

func (s *ServerCertCacheT) GetEntry(domains []string) *ServerCertCacheEntry {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, entry := range s.entrys {
		if utils.SameCert(domains, entry.domains) {
			return entry
		}
	}

	entry := &ServerCertCacheEntry{
		domains: domains,
	}
	entry.Listening.Store(false)
	updated := make(chan struct{})
	entry.Updated.Store(&updated)
	stop := make(chan struct{})
	entry.Stop.Store(&stop)
	s.entrys = append(s.entrys, entry)
	return entry
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
			ValidBefore: newValidBefore,
			FullChain:   fullchain,
			Key:         key,
		}
		c.cert = newCert

		UpdateCacheFileChan <- &ServerCacheFileEntry{
			Domains: c.domains,
			Cert:    newCert,
		}

		log.Printf("[INF] Obtained cert: %v", c.domains)
		return true, nil
	}

	log.Printf("[INF] Cert: %v not expired", c.domains)
	return false, nil
}

func (c *ServerCertCacheEntry) CertWatchDog() {
	if c.Listening.Load() {
		return
	}

	c.Listening.Store(true)
	for {
		log.Printf("[INF] Server renew: %v", c.domains)
		changed, err := c.Renew(true)
		if err != nil {
			log.Printf("[ERR] Failed renew cert %s: %s", c.domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			log.Printf("[INF] Notify cert %s updated", c.domains)
			close(*c.Updated.Swap(&newUpdated))
		}

		t := time.NewTimer(Config.ACME.RenewTimeLeftDuration / 4)
		select {
		case <-t.C:
			// Do next check
		case <-*c.Stop.Load():
			t.Stop()
			c.Listening.Store(false)
			return
		}
	}
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
