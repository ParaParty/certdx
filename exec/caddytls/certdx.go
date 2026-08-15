package caddytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
)

func init() {
	caddy.RegisterModule(&CertDXCaddyDaemon{})
}

// Defaults applied to every field the user left unset. They mirror
// config.ClientConfig.SetDefault so the plugin and the standalone client
// behave the same.
const (
	defaultRetryCount        = 5
	defaultReconnectInterval = "10m"
)

// errNoCertYet is returned while a cert pack has never produced usable
// material — neither carried over from a previous config nor fetched by
// the running daemon.
var errNoCertYet = errors.New("no certificate material available yet")

// sharedCerts keeps the material of a cert pack alive across Caddy config
// reloads, keyed by domain.Key. Provision takes one reference per
// certificate definition and Cleanup releases it, so the entry outlives
// the app instance that created it: Caddy provisions the new config
// before stopping the old one. Without it every reload would start from
// an empty cache and blackout TLS until the first poll round lands, since
// certmagic does not cache manager-provided certificates.
var sharedCerts = caddy.NewUsagePool()

// sharedCert is one entry of sharedCerts: the parsed keypair for a single
// cert pack. The keypair is parsed once per renewal rather than per
// handshake, which is also what keeps the real parse error around to hand
// back to callers.
type sharedCert struct {
	mu      sync.RWMutex
	cert    *tls.Certificate
	lastErr error
}

// Destruct satisfies caddy.Destructor. The entry owns no OS resources, so
// dropping it from the pool is all the cleanup needed.
func (s *sharedCert) Destruct() error { return nil }

// store parses freshly fetched material and makes it the served keypair.
// Material that fails to parse is recorded but does not evict the last
// good certificate — serving a stale-but-valid cert beats serving none.
func (s *sharedCert) store(fullchain, key []byte) error {
	cert, err := tls.X509KeyPair(fullchain, key)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err
		return err
	}
	s.cert, s.lastErr = &cert, nil
	return nil
}

// certificate returns the current keypair, or the reason there is none.
func (s *sharedCert) certificate() (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert != nil {
		return s.cert, nil
	}
	if s.lastErr != nil {
		return nil, s.lastErr
	}
	return nil, errNoCertYet
}

// updateHandler adapts store to the daemon's cert-change fan-out.
func (s *sharedCert) updateHandler(certID string) client.CertificateUpdateHandler {
	return func(fullchain, key []byte, _ *config.ClientCertification) {
		if err := s.store(fullchain, key); err != nil {
			logging.Error("Failed to load certificate %s: %s", certID, err)
		}
	}
}

// CertificateDef maps a user-defined cert id to the list of domains it should cover.
type CertificateDef map[string][]string

func (d CertificateDef) Add(id string, domains []string) error {
	if id == "" {
		return fmt.Errorf("certificate id must not be empty")
	}
	if len(domains) == 0 {
		return fmt.Errorf("certificate %q has no domains", id)
	}
	if _, ok := d[id]; ok {
		return fmt.Errorf("certificate %q already defined", id)
	}
	d[id] = domains
	return nil
}

func (d CertificateDef) Lookup(id string) ([]string, bool) {
	domains, ok := d[id]
	return domains, ok
}

type CertDXCaddyConfig struct {
	config.ClientCommonConfig

	Http struct {
		MainServer    config.ClientHttpServer `json:"main_server,omitempty"`
		StandbyServer config.ClientHttpServer `json:"standby_server,omitempty"`
	} `json:"http,omitempty"`

	GRPC struct {
		MainServer    config.ClientGRPCServer `json:"main_server,omitempty"`
		StandbyServer config.ClientGRPCServer `json:"standby_server,omitempty"`
	} `json:"GRPC,omitempty"`

	CertificateDefs CertificateDef `json:"certificates"`
}

// SetDefaultConfig fills in every field the user left unset. It runs both
// from the Caddyfile adapter (on a blank module) and at the top of
// Provision, so a native-JSON config that omits these fields gets the same
// defaults instead of zero values — an empty AuthMethod in particular
// would send unauthenticated requests. Empty is therefore treated as
// unset; it is not a way to ask for the zero value.
func (c *CertDXCaddyConfig) SetDefaultConfig() {
	if c.RetryCount == 0 {
		c.RetryCount = defaultRetryCount
	}
	if c.Mode == "" {
		c.Mode = config.CLIENT_MODE_HTTP
	}
	if c.ReconnectInterval == "" {
		c.ReconnectInterval = defaultReconnectInterval
	}

	if c.Http.MainServer.AuthMethod == "" {
		c.Http.MainServer.AuthMethod = config.HTTP_AUTH_TOKEN
	}
	if c.Http.StandbyServer.AuthMethod == "" {
		c.Http.StandbyServer.AuthMethod = config.HTTP_AUTH_TOKEN
	}
}

// validateConfig mirrors config.ClientConfig's mode validation. The plugin
// assembles its client config in memory instead of loading a TOML file, so
// nothing else runs these checks: without them a missing mTLS bundle would
// only surface at request time, long after Caddy could still roll the
// config back.
func (c *CertDXCaddyConfig) validateConfig() error {
	switch c.Mode {
	case config.CLIENT_MODE_HTTP:
		if c.Http.MainServer.Url == "" {
			return fmt.Errorf("http %s url is required", dirMainServer)
		}
		if err := validateHttpServer(&c.Http.MainServer); err != nil {
			return fmt.Errorf("http %s: %w", dirMainServer, err)
		}
		if c.Http.StandbyServer.Url != "" {
			if err := validateHttpServer(&c.Http.StandbyServer); err != nil {
				return fmt.Errorf("http %s: %w", dirStandbyServer, err)
			}
		}
	case config.CLIENT_MODE_GRPC:
		if c.GRPC.MainServer.Server == "" {
			return fmt.Errorf("grpc %s server is required", dirMainServer)
		}
		if err := c.GRPC.MainServer.Validate(); err != nil {
			return fmt.Errorf("grpc %s: %w", dirMainServer, err)
		}
		if c.GRPC.StandbyServer.Server != "" {
			if err := c.GRPC.StandbyServer.Validate(); err != nil {
				return fmt.Errorf("grpc %s: %w", dirStandbyServer, err)
			}
		}
	default:
		return fmt.Errorf("unsupported %s %q", dirMode, c.Mode)
	}

	return nil
}

// validateHttpServer rejects an unrecognised auth method — silently
// falling back to "no auth" is how a typo turns into unauthenticated
// requests — and then runs the config package's own check, which is what
// verifies the mTLS bundle exists.
func validateHttpServer(s *config.ClientHttpServer) error {
	switch s.AuthMethod {
	case config.HTTP_AUTH_TOKEN, config.HTTP_AUTH_MTLS:
	default:
		return fmt.Errorf("invalid %s %q, expected %q or %q",
			dirAuthMethod, s.AuthMethod, config.HTTP_AUTH_TOKEN, config.HTTP_AUTH_MTLS)
	}
	return s.Validate()
}

type CertDXCaddyDaemon struct {
	CertDXCaddyConfig

	certDXDaemon *client.CertDXClientDaemon
	logger       *zap.Logger
	wg           sync.WaitGroup

	// certs holds this instance's view of the shared cert packs, and
	// poolRefs the sharedCerts keys it must release on Cleanup (one entry
	// per successful LoadOrNew, duplicates included).
	certs    map[domain.Key]*sharedCert
	poolRefs []domain.Key
}

func MakeCertDXCaddyDaemon() *CertDXCaddyDaemon {
	d := &CertDXCaddyDaemon{}
	d.CertificateDefs = make(CertificateDef)
	d.SetDefaultConfig()
	return d
}

func (*CertDXCaddyDaemon) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "certdx",
		New: func() caddy.Module { return new(CertDXCaddyDaemon) },
	}
}

// acquireSharedCert takes a reference on the pool entry for one domain
// set, creating it if this is the first config to ask for it, and records
// the reference for Cleanup to release.
func (m *CertDXCaddyDaemon) acquireSharedCert(key domain.Key) (*sharedCert, error) {
	val, _, err := sharedCerts.LoadOrNew(key, func() (caddy.Destructor, error) {
		return &sharedCert{}, nil
	})
	if err != nil {
		return nil, err
	}
	m.poolRefs = append(m.poolRefs, key)
	return val.(*sharedCert), nil
}

func (m *CertDXCaddyDaemon) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	logging.SetLogger(zap.NewStdLog(m.logger))

	// A native-JSON config never goes through the Caddyfile adapter, so
	// this is the only place its defaults get applied.
	m.SetDefaultConfig()

	if err := m.validateConfig(); err != nil {
		return err
	}
	m.warnInsecure()

	m.certDXDaemon = client.MakeCertDXClientDaemon()
	m.certDXDaemon.Config.Common = m.ClientCommonConfig
	m.certDXDaemon.Config.Http.MainServer = m.Http.MainServer
	m.certDXDaemon.Config.Http.StandbyServer = m.Http.StandbyServer
	m.certDXDaemon.Config.GRPC.MainServer = m.GRPC.MainServer
	m.certDXDaemon.Config.GRPC.StandbyServer = m.GRPC.StandbyServer

	d, err := time.ParseDuration(m.ReconnectInterval)
	if err != nil {
		return fmt.Errorf("parse %s %q: %w", dirReconnectInterval, m.ReconnectInterval, err)
	}
	m.certDXDaemon.Config.Common.ReconnectDuration = d

	m.certs = make(map[domain.Key]*sharedCert, len(m.CertificateDefs))
	for certID, domains := range m.CertificateDefs {
		key := domain.AsKey(domains)
		cert, err := m.acquireSharedCert(key)
		if err != nil {
			return fmt.Errorf("certificate %q: %w", certID, err)
		}
		m.certs[key] = cert

		if err := m.certDXDaemon.AddCertToWatchOpt(certID, domains, []client.WatchingCertsOption{
			client.WithCertificateHandlerOption(cert.updateHandler(certID)),
		}); err != nil {
			return fmt.Errorf("watch certificate %q: %w", certID, err)
		}
	}
	return nil
}

// warnInsecure shouts about configurations that reach the server without
// any credentials. It is not a hard error: a server may legitimately be
// reachable only over a trusted network, and refusing to load would take
// a running deployment down on upgrade.
func (m *CertDXCaddyDaemon) warnInsecure() {
	if m.Mode != config.CLIENT_MODE_HTTP {
		return
	}
	for name, s := range map[string]*config.ClientHttpServer{
		dirMainServer:    &m.Http.MainServer,
		dirStandbyServer: &m.Http.StandbyServer,
	} {
		if s.Url == "" {
			continue
		}
		if s.AuthMethod == config.HTTP_AUTH_TOKEN && s.Token == "" {
			logging.Warn("INSECURE: http %s has %s %q but no %s, requests will be unauthenticated",
				name, dirAuthMethod, config.HTTP_AUTH_TOKEN, dirToken)
		}
	}
}

// Cleanup releases this instance's references to the shared cert packs.
// Caddy calls it on every config unload, including a failed Provision.
func (m *CertDXCaddyDaemon) Cleanup() error {
	var errs []error
	for _, key := range m.poolRefs {
		if _, err := sharedCerts.Delete(key); err != nil {
			errs = append(errs, err)
		}
	}
	m.poolRefs = nil
	return errors.Join(errs...)
}

func (m *CertDXCaddyDaemon) Start() error {
	mode := m.certDXDaemon.Config.Common.Mode
	switch mode {
	case config.CLIENT_MODE_HTTP:
		m.wg.Go(func() {
			m.certDXDaemon.HttpMain()
		})
	case config.CLIENT_MODE_GRPC:
		m.wg.Go(func() {
			m.certDXDaemon.GRPCMain()
		})
	default:
		return fmt.Errorf("unsupported %s %q", dirMode, mode)
	}
	return nil
}

func (m *CertDXCaddyDaemon) Stop() error {
	if m.certDXDaemon == nil {
		return nil
	}
	m.certDXDaemon.Stop()
	m.wg.Wait()
	return nil
}

// GetCertificate returns the material of one cert pack. It reads the
// shared pool rather than the daemon, so a just-reloaded config keeps
// serving the previous certificate until its own first poll round lands.
func (m *CertDXCaddyDaemon) GetCertificate(_ context.Context, certHash domain.Key) (*tls.Certificate, error) {
	cert, ok := m.certs[certHash]
	if !ok {
		return nil, fmt.Errorf("no certificate definition for domain set %d", certHash)
	}
	return cert.certificate()
}

var (
	_ caddy.Provisioner  = (*CertDXCaddyDaemon)(nil)
	_ caddy.CleanerUpper = (*CertDXCaddyDaemon)(nil)
	_ caddy.App          = (*CertDXCaddyDaemon)(nil)
)
