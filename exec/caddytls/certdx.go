package caddytls

import (
	"context"
	"crypto/tls"
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
		New: func() caddy.Module { return new(CertDXCaddyDaemon) },
	}
}

func (m *CertDXCaddyDaemon) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	logging.SetLogger(zap.NewStdLog(m.logger))

	m.certDXDaemon = client.MakeCertDXClientDaemon()
	m.certDXDaemon.Config.Common = m.ClientCommonConfig
	m.certDXDaemon.Config.Http.MainServer = m.Http.MainServer
	m.certDXDaemon.Config.Http.StandbyServer = m.Http.StandbyServer
	m.certDXDaemon.Config.GRPC.MainServer = m.GRPC.MainServer
	m.certDXDaemon.Config.GRPC.StandbyServer = m.GRPC.StandbyServer

	d, err := time.ParseDuration(m.ReconnectInterval)
	if err != nil {
		return fmt.Errorf("parse reconnect_interval %q: %w", m.ReconnectInterval, err)
	}
	m.certDXDaemon.Config.Common.ReconnectDuration = d

	for certID, domains := range m.CertificateDefs {
		if err := m.certDXDaemon.AddCertToWatch(certID, domains); err != nil {
			return fmt.Errorf("watch certificate %q: %w", certID, err)
		}
	}
	return nil
}

func (m *CertDXCaddyDaemon) Start() error {
	mode := m.certDXDaemon.Config.Common.Mode
	switch mode {
	case config.CLIENT_MODE_HTTP:
		if m.certDXDaemon.Config.Http.MainServer.Url == "" {
			return fmt.Errorf("http main_server url is required")
		}
		m.wg.Go(func() {
			if err := m.certDXDaemon.HttpMain(); err != nil {
				caddy.Log().Named("certdx").Error("http daemon exited with error", zap.Error(err))
			}
		})
	case config.CLIENT_MODE_GRPC:
		if m.certDXDaemon.Config.GRPC.MainServer.Server == "" {
			return fmt.Errorf("grpc main_server is required")
		}
		m.wg.Go(func() {
			if err := m.certDXDaemon.GRPCMain(); err != nil {
				caddy.Log().Named("certdx").Error("grpc daemon exited with error", zap.Error(err))
			}
		})
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
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
