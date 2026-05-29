//go:build e2e

package harness

import (
	"testing"
)

// CaddyfileHTTPServer mirrors a single http main_server / standby_server entry
// in the certdx caddytls global block.
type CaddyfileHTTPServer struct {
	URL        string
	AuthMethod string // "token" or "mtls"
	Token      string
	PEM        string
}

// CaddyfileGRPCServer mirrors a single GRPC main_server entry.
type CaddyfileGRPCServer struct {
	Server string
	PEM    string
}

// CaddyfileCertEntry is one "certificate <id> { domains... }" block.
type CaddyfileCertEntry struct {
	ID      string
	Domains []string
}

// CaddyfileSite is one site block: bound to https://<Domain>:<Port>, using
// the named certdx cert id.
type CaddyfileSite struct {
	Domain string
	Port   int
	CertID string
}

// CaddyfileOpts captures the knobs needed to render a Caddyfile that
// exercises the certdx caddytls plugin.
type CaddyfileOpts struct {
	// Mode is "http" or "GRPC" (case-sensitive — matches the plugin
	// directive).
	Mode string

	// RetryCount sets retry_count in the certdx block. Default 3.
	RetryCount int

	// ReconnectInterval is rendered only when non-empty (gRPC mode).
	ReconnectInterval string

	// HTTP / GRPC: exactly one should be non-nil per Mode.
	HTTP *CaddyfileHTTPServer
	GRPC *CaddyfileGRPCServer

	Certificates []CaddyfileCertEntry
	Sites        []CaddyfileSite
}

const caddyfileTpl = `{
	auto_https off
	admin off
	log {
		level INFO
	}
	certdx {
		retry_count {{.RetryCount}}
		mode {{.Mode}}
{{- if .ReconnectInterval}}
		reconnect_interval {{.ReconnectInterval}}
{{- end}}
{{if .HTTP}}
		http {
			main_server {
				url {{.HTTP.URL}}
				authMethod {{.HTTP.AuthMethod}}
{{- if .HTTP.Token}}
				token {{.HTTP.Token}}
{{- end}}
{{- if .HTTP.PEM}}
				pem {{.HTTP.PEM}}
{{- end}}
			}
		}
{{end}}
{{- if .GRPC}}
		GRPC {
			main_server {
				server {{.GRPC.Server}}
				pem {{.GRPC.PEM}}
			}
		}
{{end}}
{{- range .Certificates}}
		certificate {{.ID}} {
{{- range .Domains}}
			{{.}}
{{- end}}
		}
{{- end}}
	}
}

{{range .Sites}}
https://{{.Domain}}:{{.Port}} {
	tls {
		get_certificate certdx {{.CertID}}
	}
	respond "ok"
}
{{end}}
`

// WriteCaddyfile renders a Caddyfile at <dir>/Caddyfile and returns its path.
func WriteCaddyfile(tb testing.TB, dir string, opts CaddyfileOpts) string {
	tb.Helper()
	if opts.RetryCount == 0 {
		opts.RetryCount = 3
	}
	return renderTo(tb, dir, "Caddyfile", caddyfileTpl, opts)
}
