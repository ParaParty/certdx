package caddytls

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"pkg.para.party/certdx/pkg/config"
)

const (
	dirCertDX            = "certdx"
	dirRetryCount        = "retry_count"
	dirMode              = "mode"
	dirReconnectInterval = "reconnect_interval"
	dirHTTP              = "http"
	dirGRPC              = "GRPC"
	dirCertificate       = "certificate"

	dirMainServer    = "main_server"
	dirStandbyServer = "standby_server"

	dirURL        = "url"
	dirAuthMethod = "authMethod"
	dirToken      = "token"
	dirCA         = "ca"
	dirCertFile   = "certificate"
	dirKey        = "key"
	dirServerAddr = "server"
)

func init() {
	httpcaddyfile.RegisterGlobalOption(dirCertDX, parseCertDXGlobalOptions)
}

func expectArg1(d *caddyfile.Dispenser) (string, error) {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return "", d.Errf("expected 1 argument for %s, got %d", d.Val(), len(args))
	}
	return args[0], nil
}

// parseCertDXGlobalOptions configures the "certdx" global option.
func parseCertDXGlobalOptions(d *caddyfile.Dispenser, _ any) (any, error) {
	module := MakeCertDXCaddyDaemon()

	for d.Next() {
		if d.NextArg() {
			return nil, d.Errf("no argument expected for %s", dirCertDX)
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case dirRetryCount:
				v, err := expectArg1(d)
				if err != nil {
					return nil, err
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, d.Errf("invalid value for %s: %v", dirRetryCount, v)
				}
				module.RetryCount = n
			case dirMode:
				v, err := expectArg1(d)
				if err != nil {
					return nil, err
				}
				module.Mode = v
			case dirReconnectInterval:
				v, err := expectArg1(d)
				if err != nil {
					return nil, err
				}
				module.ReconnectInterval = v
			case dirHTTP:
				if d.NextArg() {
					return nil, d.Errf("no argument expected for %s", dirHTTP)
				}
				if err := module.UnmarshalHttpBlock(d.NewFromNextSegment()); err != nil {
					return nil, d.Errf("failed unmarshaling %s block: %v", dirHTTP, err)
				}
			case dirGRPC:
				if d.NextArg() {
					return nil, d.Errf("no argument expected for %s", dirGRPC)
				}
				if err := module.UnmarshalGRPCBlock(d.NewFromNextSegment()); err != nil {
					return nil, d.Errf("failed unmarshaling %s block: %v", dirGRPC, err)
				}
			case dirCertificate:
				certID, err := expectArg1(d)
				if err != nil {
					return nil, err
				}
				if err := module.UnmarshalCertificateBlock(certID, d.NewFromNextSegment()); err != nil {
					return nil, d.Errf("failed unmarshaling %s block: %v", dirCertificate, err)
				}
			default:
				return nil, d.Errf("unrecognized subdirective for %s: %s", dirCertDX, d.Val())
			}
		}
	}

	return httpcaddyfile.App{
		Name:  dirCertDX,
		Value: caddyconfig.JSON(module, nil),
	}, nil
}

// UnmarshalHttpBlock parses the http { ... } sub-block.
func (c *CertDXCaddyDaemon) UnmarshalHttpBlock(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case dirMainServer:
				if err := c.unmarshalHttpServerBlock(&c.Http.MainServer, d.NewFromNextSegment()); err != nil {
					return err
				}
			case dirStandbyServer:
				if err := c.unmarshalHttpServerBlock(&c.Http.StandbyServer, d.NewFromNextSegment()); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective for %s: %s", dirHTTP, d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) unmarshalHttpServerBlock(s *config.ClientHttpServer, d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			v, err := expectArg1(d)
			if err != nil {
				return err
			}
			switch d.Val() {
			case dirURL:
				s.Url = v
			case dirAuthMethod:
				s.AuthMethod = v
			case dirToken:
				s.Token = v
			case dirCA:
				s.CA = v
			case dirCertFile:
				s.Certificate = v
			case dirKey:
				s.Key = v
			default:
				return d.Errf("unrecognized subdirective for http server: %s", d.Val())
			}
		}
	}
	return nil
}

// UnmarshalGRPCBlock parses the GRPC { ... } sub-block.
func (c *CertDXCaddyDaemon) UnmarshalGRPCBlock(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case dirMainServer:
				if err := c.unmarshalGRPCServerBlock(&c.GRPC.MainServer, d.NewFromNextSegment()); err != nil {
					return err
				}
			case dirStandbyServer:
				if err := c.unmarshalGRPCServerBlock(&c.GRPC.StandbyServer, d.NewFromNextSegment()); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective for grpc: %s", d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) unmarshalGRPCServerBlock(s *config.ClientGRPCServer, d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			v, err := expectArg1(d)
			if err != nil {
				return err
			}
			switch d.Val() {
			case dirServerAddr:
				s.Server = v
			case dirCA:
				s.CA = v
			case dirCertFile:
				s.Certificate = v
			case dirKey:
				s.Key = v
			default:
				return d.Errf("unrecognized subdirective for grpc server: %s", d.Val())
			}
		}
	}
	return nil
}

// UnmarshalCertificateBlock collects the domain list under one certificate block.
func (c *CertDXCaddyDaemon) UnmarshalCertificateBlock(certID string, d *caddyfile.Dispenser) error {
	var domains []string
	for d.Next() {
		for d.NextBlock(0) {
			domains = append(domains, d.Val())
		}
	}
	if err := c.CertificateDefs.Add(certID, domains); err != nil {
		return d.Err(err.Error())
	}
	return nil
}
