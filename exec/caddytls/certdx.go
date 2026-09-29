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

// errNoCertYet is returned until the first certificate for a cert pack has
// been fetched. Every config load, reload included, starts from empty.
var errNoCertYet = errors.New("no certificate material available yet")

// servedCert is the parsed keypair of one cert pack. certmagic does not
// cache certificates handed out by a get_certificate manager, so the
// keypair is parsed once per renewal here rather than once per handshake,
// which also keeps the real parse error around to hand back to callers.
type servedCert struct {
	mu      sync.RWMutex
	cert    *tls.Certificate
	lastErr error
}

// store parses freshly fetched material and makes it the served keypair.
// Material that fails to parse is recorded but does not evict the last
// good certificate — serving a stale-but-valid cert beats serving none.
func (s *servedCert) store(fullchain, key []byte) error {
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
func (s *servedCert) certificate() (*tls.Certificate, error) {
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
func (s *servedCert) updateHandler(certID string) client.CertificateUpdateHandler {
	return func(fullchain, key []byte, _ *config.ClientCertificate) {
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

// SetDefaultConfig initialises a blank config with the defaults. The
// Caddyfile adapter calls it before parsing the user's directives.
func (c *CertDXCaddyConfig) SetDefaultConfig() {
	c.RetryCount = defaultRetryCount
	c.fillUnsetDefaults()
}

// fillUnsetDefaults defaults every string field left empty. Provision runs
// it too, since a native-JSON config never goes through the adapter. None
// of these fields has a meaningful empty value — an empty AuthMethod in
// particular would send unauthenticated requests. RetryCount is left
// alone: 0 (a single attempt) is a legitimate value that JSON's omitempty
// cannot tell apart from unset.
func (c *CertDXCaddyConfig) fillUnsetDefaults() {
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

// validateAuthMethod rejects an unrecognised auth method: silently
// falling back to "no auth" is how a typo turns into unauthenticated
// requests.
func validateAuthMethod(method string) error {
	switch method {
	case config.HTTP_AUTH_TOKEN, config.HTTP_AUTH_MTLS:
		return nil
	default:
		return fmt.Errorf("invalid %s %q, expected %q or %q",
			dirAuthMethod, method, config.HTTP_AUTH_TOKEN, config.HTTP_AUTH_MTLS)
	}
}

// validateHttpServer checks the auth method and then runs the config
// package's own check, which is what verifies the mTLS bundle exists.
func validateHttpServer(s *config.ClientHttpServer) error {
	if err := validateAuthMethod(s.AuthMethod); err != nil {
		return err
	}
	return s.Validate()
}

type CertDXCaddyDaemon struct {
	CertDXCaddyConfig

	certDXDaemon *client.CertDXClientDaemon
	logger       *zap.Logger
	wg           sync.WaitGroup

	// certs holds this instance's parsed keypair per cert pack. It is
	// built empty by Provision and deliberately not carried across config
	// reloads: re-fetching from the server is cheap.
	certs map[domain.Key]*servedCert
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

func (m *CertDXCaddyDaemon) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	logging.SetLogger(zap.NewStdLog(m.logger))

	// A native-JSON config never goes through the Caddyfile adapter, so
	// this is the only place its defaults get applied.
	m.fillUnsetDefaults()

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

	m.certs = make(map[domain.Key]*servedCert, len(m.CertificateDefs))
	for certID, domains := range m.CertificateDefs {
		// Cert ids over the same domain set share one watcher in the
		// daemon, so they share one parsed keypair as well.
		key := domain.AsKey(domains)
		if _, ok := m.certs[key]; ok {
			continue
		}
		cert := &servedCert{}
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
	servers := []struct {
		name   string
		server *config.ClientHttpServer
	}{
		{dirMainServer, &m.Http.MainServer},
		{dirStandbyServer, &m.Http.StandbyServer},
	}
	for _, it := range servers {
		if it.server.Url == "" {
			continue
		}
		if it.server.AuthMethod == config.HTTP_AUTH_TOKEN && it.server.Token == "" {
			logging.Warn("INSECURE: http %s has %s %q but no %s, requests will be unauthenticated",
				it.name, dirAuthMethod, config.HTTP_AUTH_TOKEN, dirToken)
		}
	}
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

// GetCertificate returns the parsed keypair of one cert pack, or the
// reason there is none yet.
func (m *CertDXCaddyDaemon) GetCertificate(_ context.Context, certHash domain.Key) (*tls.Certificate, error) {
	cert, ok := m.certs[certHash]
	if !ok {
		return nil, fmt.Errorf("no certificate definition for domain set %d", certHash)
	}
	return cert.certificate()
}

var (
	_ caddy.Provisioner = (*CertDXCaddyDaemon)(nil)
	_ caddy.App         = (*CertDXCaddyDaemon)(nil)
)
