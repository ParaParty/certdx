package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/mtls"
)

func init() {
	caddy.RegisterModule(&CertDXCaddyDaemon{})
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

func (c *CertDXCaddyConfig) SetDefaultConfig() {
	c.RetryCount = 5
	c.Mode = config.CLIENT_MODE_HTTP
	c.ReconnectInterval = "10m"

	c.Http.MainServer.AuthMethod = config.HTTP_AUTH_TOKEN
	c.Http.StandbyServer.AuthMethod = config.HTTP_AUTH_TOKEN
}

type CertDXCaddyDaemon struct {
	CertDXCaddyConfig

	certDXDaemon *client.CertDXClientDaemon
	logger       *zap.Logger
	wg           sync.WaitGroup
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
		New: func() caddy.Module { return MakeCertDXCaddyDaemon() },
	}
}

func (m *CertDXCaddyDaemon) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	logging.SetLogger(zap.NewStdLog(m.logger))

	m.certDXDaemon = client.MakeCertDXClientDaemon()
	cfg := m.certDXDaemon.Config
	cfg.Common = m.ClientCommonConfig
	cfg.Http.MainServer = m.Http.MainServer
	cfg.Http.StandbyServer = m.Http.StandbyServer
	cfg.GRPC.MainServer = m.GRPC.MainServer
	cfg.GRPC.StandbyServer = m.GRPC.StandbyServer

	// Certificates are registered below via AddCertToWatch, not cfg.Certificates.
	if err := cfg.Validate([]config.ValidatingOption{config.WithAcceptEmptyCertificatesList(true)}); err != nil {
		return err
	}
	if err := loadMtlsBundles(cfg); err != nil {
		return err
	}

	for certID, domains := range m.CertificateDefs {
		domains = domain.Canonical(domains)
		if len(domains) == 0 {
			return fmt.Errorf("certificate %q has no domains", certID)
		}
		// CertDXTls derives its lookup key from the stored domains.
		m.CertificateDefs[certID] = domains
		if err := m.certDXDaemon.AddCertToWatch(certID, domains); err != nil {
			return fmt.Errorf("watch certificate %q: %w", certID, err)
		}
	}
	return nil
}

// loadMtlsBundles fails provisioning on an unloadable bundle instead of
// leaving the client to fail after Caddy has started.
func loadMtlsBundles(c *config.ClientConfig) error {
	switch c.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		for _, s := range []config.ClientHttpServer{c.Http.MainServer, c.Http.StandbyServer} {
			if s.Url == "" || s.AuthMethod != config.HTTP_AUTH_MTLS {
				continue
			}
			if _, err := mtls.LoadClient(s.PEM); err != nil {
				return fmt.Errorf("http server %s: %w", s.Url, err)
			}
		}
	case config.CLIENT_MODE_GRPC:
		for _, s := range []config.ClientGRPCServer{c.GRPC.MainServer, c.GRPC.StandbyServer} {
			if s.Server == "" {
				continue
			}
			if _, err := mtls.LoadClient(s.PEM); err != nil {
				return fmt.Errorf("grpc server %s: %w", s.Server, err)
			}
		}
	}
	return nil
}

func (m *CertDXCaddyDaemon) Start() error {
	run := m.certDXDaemon.HttpMain
	if m.certDXDaemon.Config.Common.Mode == config.CLIENT_MODE_GRPC {
		run = m.certDXDaemon.GRPCMain
	}
	m.wg.Go(func() {
		if err := run(); err != nil {
			m.logger.Error("certdx client stopped", zap.Error(err))
		}
	})
	return nil
}

func (m *CertDXCaddyDaemon) Stop() error {
	m.certDXDaemon.Stop()
	m.wg.Wait()
	return nil
}

func (m *CertDXCaddyDaemon) GetCertificate(ctx context.Context, certHash domain.Key) (*tls.Certificate, error) {
	return m.certDXDaemon.GetCertificate(ctx, certHash)
}

var (
	_ caddy.Provisioner = (*CertDXCaddyDaemon)(nil)
	_ caddy.App         = (*CertDXCaddyDaemon)(nil)
)
