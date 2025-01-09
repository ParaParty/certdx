package caddytls

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("certdx", parseCertDXGlobalOptions)
}

// parseCertDXGlobalOptions configures the "certdx" global option from Caddyfile.
// Syntax:
//
//	certdx {
//		config_path /path/to/config
//	}
func parseCertDXGlobalOptions(d *caddyfile.Dispenser, existingVal any) (any, error) {
	module := &CertDXCaddyDaemon{}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "config_path":
				args := d.RemainingArgs()
				if len(args) != 1 {
					return nil, d.Errf("expected 1 argument for config_path, got %v", len(args))
				}
				v := args[0]
				module.ConfigPath = &v
			default:
				return nil, d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}

	if module.ConfigPath == nil || *module.ConfigPath == "" {
		return nil, d.Err("missing required subdirective: config_path")
	}

	return httpcaddyfile.App{
		Name:  "certdx",
		Value: caddyconfig.JSON(module, nil),
	}, nil
}
