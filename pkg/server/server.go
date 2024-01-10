package server

import (
	"log"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/utils"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type CertT struct {
	Cert, Key   []byte
	ValidBefore time.Time
}

type ServerCertCacheEntry struct {
	Domains []string

	cert  CertT
	Mutex sync.Mutex

	Listening atomic.Bool
	Updated   atomic.Pointer[chan struct{}]
	Stop      atomic.Pointer[chan struct{}]
}

type ServerCertCacheT struct {
	entrys []*ServerCertCacheEntry
	mutex  sync.Mutex
}

var ServerCertCache = &ServerCertCacheT{}
var Config = &config.ServerConfigT{}

func (s *ServerCertCacheT) GetEntry(domains []string) *ServerCertCacheEntry {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, entry := range s.entrys {
		if utils.SameCert(domains, entry.Domains) {
			return entry
		}
	}

	entry := &ServerCertCacheEntry{
		Domains: domains,
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
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return c.cert
}

func (c *ServerCertCacheEntry) Renew(retry bool) (bool, error) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()

	log.Printf("[INF] Renew cert: %v", c.Domains)
	if !time.Now().Before(c.cert.ValidBefore) {
		newValidBefore := time.Now().Truncate(1 * time.Hour).Add(Config.ACME.CertLifeTimeDuration)

		acme, err := GetACME()
		if err != nil {
			return false, err
		}

		var cert, key []byte
		if retry {
			cert, key, err = acme.RetryObtain(c.Domains, newValidBefore.Add(Config.ACME.RenewTimeLeftDuration))
		} else {
			cert, key, err = acme.Obtain(c.Domains, newValidBefore.Add(Config.ACME.RenewTimeLeftDuration))
		}
		if err != nil {
			return false, err
		}

		c.cert = CertT{
			ValidBefore: newValidBefore,
			Cert:        cert,
			Key:         key,
		}

		log.Printf("[INF] Obtained cert: %v", c.Domains)
		return true, nil
	}

	log.Printf("[INF] Cert: %v not expired", c.Domains)
	return false, nil
}

func (c *ServerCertCacheEntry) CertWatchDog() {
	if c.Listening.Load() {
		return
	}

	c.Listening.Store(true)
	for {
		log.Printf("[INF] Server renew: %v", c.Domains)
		changed, err := c.Renew(true)
		if err != nil {
			log.Printf("[ERR] Failed renew cert %s: %s", c.Domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			log.Printf("[INF] Notify cert %s updated", c.Domains)
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

func domainsAllowed(domains []string) bool {
	for _, i := range domains {
		domainParts := strings.Split(i, ".")
		tld := strings.Join(domainParts[len(domainParts)-2:], ".")
		if !slices.Contains(Config.ACME.AllowedDomains, tld) {
			return false
		}
	}
	return true
}
