package common

import (
	"log"
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

func sameCert(arr1, arr2 []string) bool {
	if len(arr1) != len(arr2) {
		return false
	}

	if len(arr1) == 0 {
		return true
	}

Next:
	for _, i := range arr1 {
		for _, j := range arr2 {
			if i == j {
				continue Next
			}
		}

		return false
	}

	return true
}

func (s *ServerCertCacheT) GetServerCacheEntry(domains []string) *ServerCertCacheEntry {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, entry := range s.entrys {
		if sameCert(domains, entry.Domains) {
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
		newValidBefore := time.Now().Truncate(1 * time.Minute).Add(ServerConfig.ACME.CertLifeTimeDuration)

		acme, err := GetACME()
		if err != nil {
			return false, err
		}

		var cert, key []byte
		if retry {
			cert, key, err = acme.RetryObtain(c.Domains, newValidBefore.Add(ServerConfig.ACME.RenewTimeLeftDuration))
		} else {
			cert, key, err = acme.Obtain(c.Domains, newValidBefore.Add(ServerConfig.ACME.RenewTimeLeftDuration))
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
		changed, err := c.Renew(true)
		if err != nil {
			log.Printf("[ERR] Failed renew cert %s: %s", c.Domains, err)
		} else if changed {
			newUpdated := make(chan struct{})
			log.Printf("[INF] Notify cert %s updated", c.Domains)
			close(*c.Updated.Swap(&newUpdated))
		}

		t := time.NewTimer(ServerConfig.ACME.RenewTimeLeftDuration / 4)
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
		for _, j := range ServerConfig.ACME.AllowedDomains {
			if tld != j {
				return false
			}
		}
	}
	return true
}
