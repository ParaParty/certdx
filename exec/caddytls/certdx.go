package caddytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/caddyserver/caddy/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"io"
	"os"
	"pkg.para.party/certdx/pkg/client"
	"time"
)

func init() {
	caddy.RegisterModule(CertDXCaddyDaemon{})
}

type CertDXCaddyDaemon struct {
	ConfigPath   *string `json:"config_path,omitempty"`
	certDXDaemon *client.CertDXClientDaemon
	cache        *expirable.LRU[string, *tls.Certificate]
}

func (CertDXCaddyDaemon) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "certdx",
		New: func() caddy.Module { return new(CertDXCaddyDaemon) },
	}
}

func (m *CertDXCaddyDaemon) Provision(ctx caddy.Context) error {
	if m.ConfigPath == nil || *m.ConfigPath == "" {
		return errors.New("config_path is required")
	}

	if _, err := os.Stat(*m.ConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found at path: %s", m.ConfigPath)
	}

	m.certDXDaemon = client.MakeCertDXClientDaemon()

	cfile, err := os.Open(*m.ConfigPath)
	if err != nil {
		caddy.Log().Fatal("failed to open config file", zap.Error(err))
		return err
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, m.certDXDaemon.Config); err == nil {
			caddy.Log().Info("config loaded")
		} else {
			caddy.Log().Fatal("fail to unmarshal config", zap.Error(err))
			return err
		}
	} else {
		caddy.Log().Fatal("failed to read config file", zap.Error(err))
		return err
	}

	m.certDXDaemon.Config.Server.ReconnectDuration, err = time.ParseDuration(m.certDXDaemon.Config.Server.ReconnectInterval)
	if err != nil {
		caddy.Log().Fatal("failed to parse interval", zap.Error(err))
		return err
	}

	if len(m.certDXDaemon.Config.Certifications) == 0 {
		caddy.Log().Fatal("no certification configured", zap.Error(err))
		return err
	}

	for idx, _ := range m.certDXDaemon.Config.Certifications {
		c := &m.certDXDaemon.Config.Certifications[idx]
		if len(c.Domains) == 0 || c.Name == "" || c.SavePath == "" {
			caddy.Log().Fatal("invalid certification configuration", zap.Error(err))
			return err
		}
		c.ReloadCommand = ""
	}

	m.cache = expirable.NewLRU[string, *tls.Certificate](1<<16, nil, time.Minute*60)

	return nil
}

func (m *CertDXCaddyDaemon) Start() error {
	switch m.certDXDaemon.Config.Server.Mode {
	case "http":
		if m.certDXDaemon.Config.Http.MainServer.Url == "" {
			caddy.Log().Fatal("http main server url should not be empty")
		}
		go m.certDXDaemon.HttpMain()
	case "grpc":
		if m.certDXDaemon.Config.GRPC.MainServer.Server == "" {
			caddy.Log().Fatal("GRPC main server url should not be empty")
		}
		go m.certDXDaemon.GRPCMain()
	default:
		caddy.Log().Fatal("not supported mode", zap.String("mode", m.certDXDaemon.Config.Server.Mode))
	}
	return nil
}

func (m *CertDXCaddyDaemon) Stop() error {
	return nil
}

func (m *CertDXCaddyDaemon) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := m.cache.Get(hello.ServerName)
	if ok {
		return cert, nil
	}

	caddy.Log().Info("get certificate from certdx", zap.String("server_name", hello.ServerName))
	cert, err := m.certDXDaemon.GetCertificate(ctx, hello)
	if err != nil {
		return nil, err
	}
	m.cache.Add(hello.ServerName, cert)
	return cert, nil
}

var (
	_ caddy.Provisioner = (*CertDXCaddyDaemon)(nil)
	_ caddy.App         = (*CertDXCaddyDaemon)(nil)
)
