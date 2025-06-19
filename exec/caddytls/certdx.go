package caddytls

import (
	"context"
	"crypto/tls"
	"pkg.para.party/certdx/pkg/types"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

func init() {
	caddy.RegisterModule(CertDXCaddyDaemon{})
}

// key: cert-id
// value: domains
type CertificateDef map[string][]string

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
}

func MakeCertDXCaddyDaemon() *CertDXCaddyDaemon {
	ret := &CertDXCaddyDaemon{}
	ret.CertificateDefs = make(CertificateDef, 0)
	ret.SetDefaultConfig()

	return ret
}

func (CertDXCaddyDaemon) CaddyModule() caddy.ModuleInfo {
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

	var err error
	m.certDXDaemon.Config.Common.ReconnectDuration, err = time.ParseDuration(m.ReconnectInterval)
	if err != nil {
		m.logger.Fatal("failed to parse interval", zap.Error(err))
		return err
	}

	for certID, domains := range m.CertificateDefs {
		if err := m.certDXDaemon.AddCertToWatch(certID, domains); err != nil {
			return err
		}
	}

	return nil
}

func (m *CertDXCaddyDaemon) Start() error {
	switch m.certDXDaemon.Config.Common.Mode {
	case "http":
		if m.certDXDaemon.Config.Http.MainServer.Url == "" {
			m.logger.Fatal("http main server url should not be empty")
		}
		go m.certDXDaemon.HttpMain()
	case "grpc":
		if m.certDXDaemon.Config.GRPC.MainServer.Server == "" {
			m.logger.Fatal("GRPC main server url should not be empty")
		}
		go m.certDXDaemon.GRPCMain()
	default:
		m.logger.Fatal("not supported mode", zap.String("mode", m.certDXDaemon.Config.Common.Mode))
	}
	return nil
}

func (m *CertDXCaddyDaemon) Stop() error {
	m.certDXDaemon.Stop()
	return nil
}

func (m *CertDXCaddyDaemon) GetCertificate(ctx context.Context, certHash types.DomainKey) (*tls.Certificate, error) {
	return m.certDXDaemon.GetCertificate(ctx, certHash)
}

var (
	_ caddy.Provisioner = (*CertDXCaddyDaemon)(nil)
	_ caddy.App         = (*CertDXCaddyDaemon)(nil)
)
