package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/retry"
)

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

type certData struct {
	Domains        []string
	Fullchain, Key []byte
}

type watchingCert struct {
	Data           atomic.Pointer[certData]
	Config         config.ClientCertification
	UpdateHandlers []CertificateUpdateHandler
	UpdateChan     chan certData
}

type WatchingCertsOption func(*watchingCert)

func WithCertificateHandlerOption(handler CertificateUpdateHandler) WatchingCertsOption {
	return func(wc *watchingCert) {
		wc.UpdateHandlers = append(wc.UpdateHandlers, handler)
	}
}

// watchUpdate runs in its own goroutine and forwards cert updates to any
// registered handlers until the daemon's rootCtx is done. Callers must
// Add(1) on the wait group BEFORE spawning watchUpdate; otherwise the
// parent goroutine could race a concurrent Wait and miss the worker.
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

// ClientInit prepares one watchingCert per Certifications entry and seeds
// it with any cert previously written to disk. Watcher goroutines are not
// launched until HttpMain or GRPCMain runs (they own the rootCtx).
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

func (r *CertDXClientDaemon) httpRequestCert(domains []string) *api.HttpCertResp {
	var resp *api.HttpCertResp
	err := retry.Do(r.Config.Common.RetryCount, func() error {
		certdxClient := MakeCertDXHttpClient(append(r.ClientOpt, WithCertDXServerInfo(&r.Config.Http.MainServer))...)
		var err error
		resp, err = certdxClient.GetCertCtx(r.rootCtx, domains)
		return err
	})
	if err == nil {
		return resp
	}
	logging.Warn("Failed to get cert %v from MainServer, err: %s", domains, err)

	if r.Config.Http.StandbyServer.Url != "" {
		certdxClient := MakeCertDXHttpClient(append(r.ClientOpt, WithCertDXServerInfo(&r.Config.Http.StandbyServer))...)
		err = retry.Do(r.Config.Common.RetryCount, func() error {
			var err error
			resp, err = certdxClient.GetCertCtx(r.rootCtx, domains)
			return err
		})
		if err == nil {
			return resp
		}
		logging.Warn("Failed to get cert %v from StandbyServer, err: %s", domains, err)
	}
	return nil
}

func (r *CertDXClientDaemon) httpPollingCert(cert *watchingCert) {
	sleepTime := 1 * time.Hour // default sleep time
	for {
		logging.Info("Requesting cert %v", cert.Config.Domains)
		resp := r.httpRequestCert(cert.Config.Domains)
		if resp != nil {
			if resp.Err != "" {
				logging.Error("Failed to request cert, err: %s", resp.Err)
			} else {
				sleepTime = resp.RenewTimeLeft / 4
				select {
				case cert.UpdateChan <- certData{
					Domains:   cert.Config.Domains,
					Fullchain: resp.FullChain,
					Key:       resp.Key,
				}:
				case <-r.rootCtx.Done():
					return
				}
			}
		} else {
			logging.Error("Failed to request cert, retry next round.")
		}
		t := time.NewTimer(sleepTime)
		select {
		case <-t.C:
			// continue
		case <-r.rootCtx.Done():
			t.Stop()
			return
		}
	}
}

// HttpMain runs the HTTP polling client until Stop is called.
func (r *CertDXClientDaemon) HttpMain() {
	r.startWatchers()

	for _, c := range r.certs {
		r.wg.Add(1)
		go func(_c *watchingCert) {
			defer r.wg.Done()
			r.httpPollingCert(_c)
		}(c)
	}

	<-r.rootCtx.Done()

	logging.Info("Stopping Http client")
	r.wg.Wait()
}

func (r *CertDXClientDaemon) LoadConfigurationAndValidateOpt(path string, options []config.ValidatingOption) error {
	cfile, err := os.Open(path)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
		return err
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, r.Config); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshalling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	return r.Config.Validate(options)
}

func (r *CertDXClientDaemon) LoadConfigurationAndValidate(path string) error {
	return r.LoadConfigurationAndValidateOpt(path, []config.ValidatingOption{})
}

type GRPC_CLIENT_STATE int

const (
	GRPC_STATE_STOP = GRPC_CLIENT_STATE(iota)
	GRPC_STATE_MAIN
	GRPC_STATE_FAILOVER
	GRPC_STATE_TRY_FALLBACK
	GRPC_STATE_RESTART_MAIN
)

// GRPCMain runs the gRPC SDS client (with failover) until Stop is called.
//
// The five-state failover machine itself is preserved verbatim; slice 6
// rewrites its mechanics. Only the lifecycle plumbing (rootCtx, watchers)
// changes here.
func (r *CertDXClientDaemon) GRPCMain() {
	r.startWatchers()

	var standByClient *CertDXgRPCClient
	standByExists := r.Config.GRPC.StandbyServer.Server != ""

	mainClient := MakeCertDXgRPCClient(&r.Config.GRPC.MainServer, r.certs)
	if standByExists {
		standByClient = MakeCertDXgRPCClient(&r.Config.GRPC.StandbyServer, r.certs)
	}
	stateChan := make(chan GRPC_CLIENT_STATE, 1)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		mainRetryCount := 0
		StandByActive := atomic.Bool{}
		StandByActive.Store(false)
		resetChan_ := make(chan struct{})
		resetChan := atomic.Pointer[chan struct{}]{}
		resetChan.Store(&resetChan_)

		resetFunc := func() {
			newReset := make(chan struct{})
			close(*resetChan.Swap(&newReset))
		}

		for {
			state := <-stateChan
			logging.Debug("Process grpc client state: %d", state)
			switch state {
			case GRPC_STATE_STOP:
				resetFunc()
				return
			case GRPC_STATE_MAIN:
				r.wg.Add(1)
				go func() {
					defer func() {
						r.wg.Done()
						logging.Debug("Main stream gorountine exit")
					}()
					logging.Info("Starting gRPC main stream")
					startTime := time.Now()
					err := mainClient.Stream()
					logging.Info("gRPC main stream stopped: %s", err)
					if _, ok := err.(*killed); ok {
						stateChan <- GRPC_STATE_STOP
						return
					}

					if time.Now().Before(startTime.Add(5 * time.Minute)) {
						mainRetryCount += 1
					} else {
						mainRetryCount = 0
						stateChan <- GRPC_STATE_MAIN
						return
					}

					logging.Info("Current main server retry count: %d", mainRetryCount)
					if mainRetryCount < r.Config.Common.RetryCount {
						select {
						case <-time.After(15 * time.Second):
							stateChan <- GRPC_STATE_MAIN
							return
						case <-r.rootCtx.Done():
							return
						}
					}

					logging.Info("Retry limite for main stream reached")
					mainRetryCount = 0
					if standByExists && !StandByActive.Load() {
						logging.Info("Start trying standby stream")
						stateChan <- GRPC_STATE_FAILOVER
					} else {
						logging.Info("Sleep %s", r.Config.Common.ReconnectInterval)
						stateChan <- GRPC_STATE_RESTART_MAIN
					}
				}()
			case GRPC_STATE_FAILOVER:
				StandByActive.Store(true)
				r.wg.Add(1)
				go func() {
					defer func() {
						r.wg.Done()
						StandByActive.Store(false)
						logging.Debug("Standby goroutine exit")
					}()
					standbyRetryCount := 0
					for {
						select {
						case <-*resetChan.Load():
							return
						default:
						}
						logging.Info("Starting gRPC standby stream")
						startTime := time.Now()
						err := standByClient.Stream()
						logging.Info("gRPC standby stream stopped: %s", err)
						if _, ok := err.(*killed); ok {
							return
						}

						if time.Now().Before(startTime.Add(5 * time.Minute)) {
							standbyRetryCount += 1
						} else {
							standbyRetryCount = 0
							continue
						}

						logging.Info("Current standby server retry count: %d", standbyRetryCount)
						if standbyRetryCount < r.Config.Common.RetryCount {
							select {
							case <-time.After(15 * time.Second):
								continue
							case <-*resetChan.Load():
								logging.Debug("Standby goroutine reset")
								return
							}
						}

						logging.Info("Retry limite for standby stream reached, sleep %s", r.Config.Common.ReconnectInterval)
						standbyRetryCount = 0
						select {
						case <-time.After(r.Config.Common.ReconnectDuration):
							continue
						case <-*resetChan.Load():
							logging.Debug("Standby goroutine reset")
							return
						}
					}
				}()
				stateChan <- GRPC_STATE_TRY_FALLBACK
			case GRPC_STATE_TRY_FALLBACK:
				r.wg.Add(1)
				go func() {
					defer func() {
						r.wg.Done()
						logging.Debug("Fallback goroutine exit")
					}()
					select {
					case <-*mainClient.Received.Load():
						standByClient.Kill()
						resetFunc()
					case <-*resetChan.Load():
						logging.Debug("Fallback goroutine reset")
						return
					}
				}()
				stateChan <- GRPC_STATE_RESTART_MAIN
			case GRPC_STATE_RESTART_MAIN:
				r.wg.Add(1)
				go func() {
					defer func() {
						r.wg.Done()
						logging.Debug("Restart goroutine exit")
					}()
					logging.Debug("Reconnect duration is: %s", r.Config.Common.ReconnectDuration)
					select {
					case <-time.After(r.Config.Common.ReconnectDuration):
						stateChan <- GRPC_STATE_MAIN
					case <-*resetChan.Load():
						logging.Debug("Restart goroutine reset")
						return
					}
				}()
			}
		}
	}()

	stateChan <- GRPC_STATE_MAIN

	<-r.rootCtx.Done()

	stateChan <- GRPC_STATE_STOP

	logging.Info("Stopping gRPC client")
	mainClient.Kill()
	if standByClient != nil {
		standByClient.Kill()
	}
	r.wg.Wait()
}

// Stop signals every daemon goroutine to wind down. Idempotent and safe
// to call from any caller.
func (r *CertDXClientDaemon) Stop() {
	r.stopOnce.Do(r.rootCancel)
}

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
