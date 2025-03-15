package caddytls

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"pkg.para.party/certdx/pkg/config"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("certdx", parseCertDXGlobalOptions)
}

// parseCertDXGlobalOptions configures the "certdx" global option from Caddyfile.
func parseCertDXGlobalOptions(d *caddyfile.Dispenser, existingVal any) (any, error) {
	module := MakeCertDXClientDaemon()

	for d.Next() {
		if d.NextArg() {
			return nil, d.Err("no argument excepted for certdx")
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "retry_count":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, d.Errf("expected 1 argument for retry_count, got %v", len(args))
				}
				v := args[0]
				var err error
				module.RetryCount, err = strconv.Atoi(v)
				if err != nil {
					return nil, d.Errf("unexcepted value for retry_count: %v", v)
				}
			case "mode":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, d.Errf("expected 1 argument for mode, got %v", len(args))
				}
				v := args[0]
				module.Mode = v
			case "reconnect_interval":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, d.Errf("expected 1 argument for reconnect_interval, got %v", len(args))
				}
				v := args[0]
				module.ReconnectInterval = v
			case "http":
				if d.NextArg() {
					return nil, d.Err("no argument expected for http")
				}
				err := module.UnmarshalHttpBlock(d.NewFromNextSegment())
				if err != nil {
					return nil, d.Errf("unexpected unmarshaling error for http: %w", err)
				}
			case "GRPC":
				if d.NextArg() {
					return nil, d.Err("no argument expected for GRPC")
				}
				err := module.UnmarshalGRPCBlock(d.NewFromNextSegment())
				if err != nil {
					return nil, d.Errf("unexpected unmarshaling error for GRPC: %w", err)
				}
			case "certificate":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, d.Errf("expected 1 argument for certificate, got %v", len(args))
				}
				cert_id := args[0]
				err := module.UnmarshalCertificateBlock(cert_id, d.NewFromNextSegment())
				if err != nil {
					return nil, d.Errf("unexpected unmarshaling error for certificate: %w", err)
				}
			default:
				return nil, d.Errf("unrecognized subdirective for certdx: %s", d.Val())
			}
		}
	}

	return httpcaddyfile.App{
		Name:  "certdx",
		Value: caddyconfig.JSON(module, nil),
	}, nil
}

func (c *CertDXCaddyDaemon) UnmarshalHttpBlock(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "main_server":
				err := c.UnmarshalHttpServerBlock(&c.Http.MainServer, d.NewFromNextSegment())
				if err != nil {
					return err
				}
			case "standby_server":
				err := c.UnmarshalHttpServerBlock(&c.Http.StandbyServer, d.NewFromNextSegment())
				if err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective for http: %s", d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) UnmarshalHttpServerBlock(s *config.ClientHttpServer, d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "url":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for url, got %v", len(args))
				}
				v := args[0]
				s.Url = v
			case "token":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for token, got %v", len(args))
				}
				v := args[0]
				s.Token = v
			default:
				return d.Errf("unrecognized subdirective for http server: %s", d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) UnmarshalGRPCBlock(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "main_server":
				err := c.UnmarshalGRPCServerBlock(&c.GRPC.MainServer, d.NewFromNextSegment())
				if err != nil {
					return err
				}
			case "standby_server":
				err := c.UnmarshalGRPCServerBlock(&c.GRPC.StandbyServer, d.NewFromNextSegment())
				if err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective for grpc: %s", d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) UnmarshalGRPCServerBlock(s *config.ClientGRPCServer, d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "server":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for server, got %v", len(args))
				}
				v := args[0]
				s.Server = v
			case "ca":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for ca, got %v", len(args))
				}
				v := args[0]
				s.CA = v
			case "certificate":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for certificate, got %v", len(args))
				}
				v := args[0]
				s.Certificate = v
			case "key":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return d.Errf("expected 1 argument for key, got %v", len(args))
				}
				v := args[0]
				s.Key = v
			default:
				return d.Errf("unrecognized subdirective for grpc server: %s", d.Val())
			}
		}
	}
	return nil
}

func (c *CertDXCaddyDaemon) UnmarshalCertificateBlock(cert_id string, d *caddyfile.Dispenser) error {
	var domains []string

	for d.Next() {
		for d.NextBlock(0) {
			domains = append(domains, d.Val())
		}
	}

	if len(domains) <= 0 {
		return d.Err("no domains present in certificate definition")
	}

	c.CertificateDefs[cert_id] = domains
	return nil
}
