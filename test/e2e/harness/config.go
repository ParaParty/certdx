//go:build e2e

package harness

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"
)

// ServerOpts captures the knobs needed to render a server config TOML.
type ServerOpts struct {
	// AllowedDomains is the ACME.allowedDomains list. Required.
	AllowedDomains []string

	// CertLifetime / RenewTimeLeft control mock-provider validity and
	// renewal cadence (renewal interval = RenewTimeLeft/4).
	// Defaults: 168h / 24h.
	CertLifetime  time.Duration
	RenewTimeLeft time.Duration

	// HTTP knobs.
	HTTPEnabled bool
	HTTPListen  string // e.g. ":12345"
	HTTPApiPath string // default "/e2e"
	HTTPAuth    string // "token" or "mtls"; default "token"
	HTTPSecure  bool
	HTTPNames   []string
	HTTPToken   string

	// gRPC SDS knobs.
	GRPCEnabled bool
	GRPCListen  string
	GRPCNames   []string
}

const serverTOMLTpl = `[ACME]
provider = "mock"
email = "e2e@certdx.test"
challengeType = "dns"
certLifeTime = "{{.CertLifeTime}}"
renewTimeLeft = "{{.RenewTimeLeft}}"
retryCount = 1
allowedDomains = [{{range $i, $d := .AllowedDomains}}{{if $i}}, {{end}}"{{$d}}"{{end}}]

[HttpServer]
enabled = {{.HTTPEnabled}}
listen = "{{.HTTPListen}}"
apiPath = "{{.HTTPApiPath}}"
authMethod = "{{.HTTPAuth}}"
secure = {{.HTTPSecure}}
names = [{{range $i, $d := .HTTPNames}}{{if $i}}, {{end}}"{{$d}}"{{end}}]
token = "{{.HTTPToken}}"

[gRPCSDSServer]
enabled = {{.GRPCEnabled}}
listen = "{{.GRPCListen}}"
names = [{{range $i, $d := .GRPCNames}}{{if $i}}, {{end}}"{{$d}}"{{end}}]
`

// WriteServerConfig renders <dir>/server.toml and seeds an empty cache.json
// so the server's path-resolver does not fall through to a shared executable
// directory and pick up another test's cache.
func WriteServerConfig(tb testing.TB, dir string, opts ServerOpts) string {
	tb.Helper()

	if opts.CertLifetime == 0 {
		opts.CertLifetime = 168 * time.Hour
	}
	if opts.RenewTimeLeft == 0 {
		opts.RenewTimeLeft = 24 * time.Hour
	}
	if opts.HTTPApiPath == "" {
		opts.HTTPApiPath = "/e2e"
	}
	if opts.HTTPAuth == "" {
		opts.HTTPAuth = "token"
	}

	data := struct {
		ServerOpts
		CertLifeTime  string
		RenewTimeLeft string
	}{
		ServerOpts:    opts,
		CertLifeTime:  opts.CertLifetime.String(),
		RenewTimeLeft: opts.RenewTimeLeft.String(),
	}

	PrepareServerCwd(tb, dir)
	return renderTo(tb, dir, "server.toml", serverTOMLTpl, data)
}

// PrepareServerCwd isolates a server's working directory: ensures it exists
// and seeds an empty cache.json so the path-resolver does not fall through
// and pick up another test's cache. WriteServerConfig calls this for you.
func PrepareServerCwd(tb testing.TB, dir string) {
	tb.Helper()
	EnsureDir(tb, dir)
	cachePath := filepath.Join(dir, "cache.json")
	if _, err := os.Stat(cachePath); err == nil {
		return
	}
	if err := os.WriteFile(cachePath, []byte("{}"), 0o600); err != nil {
		tb.Fatalf("seed cache.json: %s", err)
	}
}

// HTTPClientServer captures one main/standby HTTP client server entry.
type HTTPClientServer struct {
	URL        string
	AuthMethod string // "token" or "mtls"
	Token      string
	CA         string
	Cert       string
	Key        string
}

// ClientCert mirrors a [[Certifications]] entry.
type ClientCert struct {
	Name          string
	SavePath      string
	Domains       []string
	ReloadCommand string
}

// HTTPClientOpts holds knobs for an HTTP-mode client config.
type HTTPClientOpts struct {
	Main         HTTPClientServer
	Standby      *HTTPClientServer // optional
	RetryCount   int               // default 2
	ReconnectInt string            // default "10s"
	Certs        []ClientCert
}

const httpClientTOMLTpl = `[Common]
mode = "http"
retryCount = {{.RetryCount}}
reconnectInterval = "{{.ReconnectInt}}"

[Http.MainServer]
url = "{{.Main.URL}}"
authMethod = "{{.Main.AuthMethod}}"
token = "{{.Main.Token}}"
ca = "{{.Main.CA}}"
certificate = "{{.Main.Cert}}"
key = "{{.Main.Key}}"

{{if .Standby}}
[Http.StandbyServer]
url = "{{.Standby.URL}}"
authMethod = "{{.Standby.AuthMethod}}"
token = "{{.Standby.Token}}"
ca = "{{.Standby.CA}}"
certificate = "{{.Standby.Cert}}"
key = "{{.Standby.Key}}"
{{end}}

{{range .Certs}}
[[Certifications]]
name = "{{.Name}}"
savePath = "{{.SavePath}}"
domains = [{{range $i, $d := .Domains}}{{if $i}}, {{end}}"{{$d}}"{{end}}]
reloadCommand = "{{.ReloadCommand}}"
{{end}}
`

// WriteHTTPClientConfig renders an HTTP-mode client config at <dir>/client.toml.
func WriteHTTPClientConfig(tb testing.TB, dir string, opts HTTPClientOpts) string {
	tb.Helper()
	if opts.RetryCount == 0 {
		opts.RetryCount = 2
	}
	if opts.ReconnectInt == "" {
		opts.ReconnectInt = "10s"
	}
	return renderTo(tb, dir, "client.toml", httpClientTOMLTpl, opts)
}

// GRPCClientServer mirrors GRPC.MainServer / GRPC.StandbyServer.
type GRPCClientServer struct {
	Server string
	CA     string
	Cert   string
	Key    string
}

// GRPCClientOpts holds knobs for a gRPC-mode client config.
type GRPCClientOpts struct {
	Main         GRPCClientServer
	Standby      *GRPCClientServer
	RetryCount   int
	ReconnectInt string
	Certs        []ClientCert
}

const grpcClientTOMLTpl = `[Common]
mode = "grpc"
retryCount = {{.RetryCount}}
reconnectInterval = "{{.ReconnectInt}}"

[GRPC.MainServer]
server = "{{.Main.Server}}"
ca = "{{.Main.CA}}"
certificate = "{{.Main.Cert}}"
key = "{{.Main.Key}}"

{{if .Standby}}
[GRPC.StandbyServer]
server = "{{.Standby.Server}}"
ca = "{{.Standby.CA}}"
certificate = "{{.Standby.Cert}}"
key = "{{.Standby.Key}}"
{{end}}

{{range .Certs}}
[[Certifications]]
name = "{{.Name}}"
savePath = "{{.SavePath}}"
domains = [{{range $i, $d := .Domains}}{{if $i}}, {{end}}"{{$d}}"{{end}}]
reloadCommand = "{{.ReloadCommand}}"
{{end}}
`

// WriteGRPCClientConfig renders a gRPC-mode client config at <dir>/client.toml.
func WriteGRPCClientConfig(tb testing.TB, dir string, opts GRPCClientOpts) string {
	tb.Helper()
	if opts.RetryCount == 0 {
		opts.RetryCount = 2
	}
	if opts.ReconnectInt == "" {
		opts.ReconnectInt = "10s"
	}
	return renderTo(tb, dir, "client.toml", grpcClientTOMLTpl, opts)
}

func renderTo(tb testing.TB, dir, name, tpl string, data any) string {
	tb.Helper()
	t, err := template.New(name).Parse(tpl)
	if err != nil {
		tb.Fatalf("parse template %s: %s", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		tb.Fatalf("execute template %s: %s", name, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		tb.Fatalf("write %s: %s", path, err)
	}
	return path
}

// EnsureDir creates dir (and parents) and fails the test on error.
func EnsureDir(tb testing.TB, dir string) {
	tb.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("mkdir %s: %s", dir, err)
	}
}

// JoinHostPort builds a host:port string with the given numeric port.
func JoinHostPort(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
