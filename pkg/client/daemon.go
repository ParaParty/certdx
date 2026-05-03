// Package client implements the consumer side of certdx: the standalone
// daemon, the in-process Caddy plugin, and the one-shot Tencent Cloud /
// Kubernetes updaters all build on the types declared here.
//
// File layout:
//
//   - daemon.go        — daemon lifecycle, config loading, watcher
//                        registration, and the cert-change fan-out.
//   - http_poller.go   — HTTP-mode polling loop.
//   - grpc_streamer.go — gRPC SDS failover state machine.
//   - http.go / sds.go / mtls.go / handler.go — protocol clients and
//                        the on-disk write/reload handler.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"pkg.para.party/certdx/pkg/cli"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
)

// CertDXClientDaemon is the long-lived coordinator on the client side.
// Construct it with MakeCertDXClientDaemon, load configuration with
// LoadConfigurationAndValidate, finalise with ClientInit, then drive
// it with HttpMain or GRPCMain depending on the configured mode. Stop
// signals graceful shutdown via the daemon's root context.
type CertDXClientDaemon struct {
	Config    *config.ClientConfig
	ClientOpt []CertDXHttpClientOption

	certs map[domain.Key]*watchingCert
	wg    sync.WaitGroup

	// rootCtx is the lifecycle parent for every daemon subgoroutine
	// (watchers, pollers, the gRPC failover state machine). Stop cancels
	// it exactly once via stopOnce. There is no separate stop chan —
	// context cancellation is the single signal.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	stopOnce   sync.Once
}

// certData is an immutable snapshot of one cert's current material plus
// its domain set. Distributed to per-cert handlers via watchUpdate.
type certData struct {
	Domains        []string
	Fullchain, Key []byte
}

// watchingCert holds the per-certificate state that survives across
// individual fetch attempts: the current snapshot, the channel that
// poll/stream loops feed updates into, the registered handlers, and
// the canonical config.
type watchingCert struct {
	Data           atomic.Pointer[certData]
	Config         config.ClientCertification
	UpdateHandlers []CertificateUpdateHandler
	UpdateChan     chan certData
}

// WatchingCertsOption customises an AddCertToWatchOpt registration.
type WatchingCertsOption func(*watchingCert)

// WithCertificateHandlerOption registers an additional handler invoked
// when the certificate's fullchain or key change.
func WithCertificateHandlerOption(handler CertificateUpdateHandler) WatchingCertsOption {
	return func(wc *watchingCert) {
		wc.UpdateHandlers = append(wc.UpdateHandlers, handler)
	}
}

// watchUpdate consumes UpdateChan for a single watchingCert and fans
// changes out to every registered handler. It exits when the daemon's
// rootCtx is done. Callers must Add(1) on the wait group BEFORE
// spawning watchUpdate; the parent goroutine could otherwise race a
// concurrent Wait and miss the worker.
func (r *CertDXClientDaemon) watchUpdate(c *watchingCert) {
	defer r.wg.Done()
	for {
		select {
		case <-r.rootCtx.Done():
			return
		case newCert := <-c.UpdateChan:
			currentCert := c.Data.Load()
			if !bytes.Equal(currentCert.Fullchain, newCert.Fullchain) || !bytes.Equal(currentCert.Key, newCert.Key) {
				logging.Notice("Notify cert %v changed", newCert.Domains)
				c.Data.Swap(&newCert)
				for _, handleFunc := range c.UpdateHandlers {
					handleFunc(newCert.Fullchain, newCert.Key, &c.Config)
				}
			} else {
				logging.Info("Cert %v not changed", newCert.Domains)
			}
		}
	}
}

// MakeCertDXClientDaemon constructs a daemon with default config and a
// fresh root context.
func MakeCertDXClientDaemon() *CertDXClientDaemon {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ret := &CertDXClientDaemon{
		Config:     &config.ClientConfig{},
		ClientOpt:  make([]CertDXHttpClientOption, 0),
		certs:      make(map[domain.Key]*watchingCert),
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
	}
	ret.Config.SetDefault()
	return ret
}

// loadSavedCert reads any previously-persisted cert/key for this
// certification off disk so the daemon can serve stale-but-valid
// material until the first fresh fetch lands.
func (r *CertDXClientDaemon) loadSavedCert(c *config.ClientCertification) (fullchan, key []byte, err error) {
	fullchanPath, keyPath, err := c.GetFullChainAndKeyPath()
	if err != nil {
		return nil, nil, err
	}
	if paths.FileExists(fullchanPath) && paths.FileExists(keyPath) {
		fullchan, err = os.ReadFile(fullchanPath)
		if err != nil {
			return
		}

		key, err = os.ReadFile(keyPath)
		if err != nil {
			return
		}
	} else {
		err = os.ErrNotExist
	}
	return
}

// ClientInit prepares one watchingCert per Certifications entry and
// seeds it with any cert previously written to disk. Watcher goroutines
// are not launched until HttpMain or GRPCMain runs (they own rootCtx).
func (r *CertDXClientDaemon) ClientInit() {
	for _, c := range r.Config.Certifications {
		cd := certData{
			Domains: c.Domains,
		}

		fullchan, key, err := r.loadSavedCert(&c)
		if err == nil {
			cd.Fullchain, cd.Key = fullchan, key
		}

		cert := &watchingCert{
			Config:         c,
			UpdateHandlers: []CertificateUpdateHandler{writeCertAndDoCommand},
			UpdateChan:     make(chan certData, 1),
		}
		cert.Data.Store(&cd)

		r.certs[domain.AsKey(c.Domains)] = cert
	}
}

// AddCertToWatchOpt registers an additional cert + handler set to be
// watched. Must be called before HttpMain / GRPCMain runs; the watcher
// goroutine is launched there with rootCtx.
func (r *CertDXClientDaemon) AddCertToWatchOpt(name string, domains []string, options []WatchingCertsOption) error {
	cd := certData{
		Domains: domains,
	}

	cert := &watchingCert{
		Config:         config.ClientCertification{Name: name, Domains: domains},
		UpdateHandlers: []CertificateUpdateHandler{},
		UpdateChan:     make(chan certData, 1),
	}
	for _, it := range options {
		it(cert)
	}

	cert.Data.Store(&cd)

	r.certs[domain.AsKey(domains)] = cert

	return nil
}

// AddCertToWatch is the no-options form of AddCertToWatchOpt.
func (r *CertDXClientDaemon) AddCertToWatch(name string, domains []string) error {
	return r.AddCertToWatchOpt(name, domains, []WatchingCertsOption{})
}

// startWatchers launches one watchUpdate goroutine per registered cert.
// Each watcher exits when the daemon's rootCtx fires.
func (r *CertDXClientDaemon) startWatchers() {
	for _, c := range r.certs {
		r.wg.Add(1)
		go r.watchUpdate(c)
	}
}

// LoadConfigurationAndValidateOpt parses the TOML file at path into the
// daemon's config and runs Validate with the supplied options.
func (r *CertDXClientDaemon) LoadConfigurationAndValidateOpt(path string, options []config.ValidatingOption) error {
	if err := cli.LoadTOML(path, r.Config); err != nil {
		return err
	}
	return r.Config.Validate(options)
}

// LoadConfigurationAndValidate is the no-options form of
// LoadConfigurationAndValidateOpt.
func (r *CertDXClientDaemon) LoadConfigurationAndValidate(path string) error {
	return r.LoadConfigurationAndValidateOpt(path, []config.ValidatingOption{})
}

// Stop signals every daemon goroutine to wind down. Idempotent and safe
// to call from any caller.
func (r *CertDXClientDaemon) Stop() {
	r.stopOnce.Do(r.rootCancel)
}

// GetCertificate returns the cached TLS cert for the given domain key.
// Used by the Caddy plugin's get_certificate hook.
func (r *CertDXClientDaemon) GetCertificate(ctx context.Context, certHash domain.Key) (*tls.Certificate, error) {
	cert, exists := r.certs[certHash]
	if exists {
		certData := cert.Data.Load()
		tlsCert, err := tls.X509KeyPair(certData.Fullchain, certData.Key)
		if err == nil {
			return &tlsCert, nil
		}
	}
	return nil, fmt.Errorf("no certificate found")
}
