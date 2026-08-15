package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"

	"pkg.para.party/certdx/pkg/domain"
)

func init() {
	caddy.RegisterModule(CertDXTls{})
}

// CertDXTls is the certmagic.Manager implementation that delegates certificate
// retrieval to the certdx daemon.
type CertDXTls struct {
	ctx       caddy.Context
	certDXApp *CertDXCaddyDaemon
	CertId    string `json:"cert_id"`
	certHash  domain.Key
	domains   []string
}

func (CertDXTls) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.certdx",
		New: func() caddy.Module { return new(CertDXTls) },
	}
}

func (certdx *CertDXTls) Provision(ctx caddy.Context) error {
	certdx.ctx = ctx
	return nil
}

func (certdx *CertDXTls) Validate() error {
	app, err := certdx.ctx.App("certdx")
	if err != nil {
		return fmt.Errorf("certdx app is not configured: %w (add a `certdx { ... }` global options block to your Caddyfile)", err)
	}

	var ok bool
	certdx.certDXApp, ok = app.(*CertDXCaddyDaemon)
	if !ok {
		return fmt.Errorf("certdx app has unexpected type %T", app)
	}

	domains, ok := certdx.certDXApp.CertificateDefs.Lookup(certdx.CertId)
	if !ok {
		return fmt.Errorf("no certificate definition for cert-id %q", certdx.CertId)
	}
	certdx.domains = domains
	certdx.certHash = domain.AsKey(domains)
	return nil
}

// certPackCovers reports whether the cert pack's domain list contains a
// name that a TLS peer would accept for serverName: an exact match, or a
// wildcard entry matching exactly one label below its base.
//
// This is deliberately stricter than domain.CertCovers, which also treats
// a literal entry as covering its subdomains — right for the server's
// allow-list gate and the Kubernetes updater, wrong here, where a
// certificate for "example.com" does not serve "foo.example.com".
func certPackCovers(domains []string, serverName string) bool {
	name := normalizeName(serverName)
	if name == "" {
		return false
	}
	for _, entry := range domains {
		e := normalizeName(entry)
		if name == e {
			return true
		}
		base, isWildcard := strings.CutPrefix(e, "*.")
		if !isWildcard {
			continue
		}
		if label, ok := strings.CutSuffix(name, "."+base); ok && label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// GetCertificate serves the cert pack bound to this manager's cert-id.
// certmagic consults every configured manager in turn, so a ServerName
// this pack does not cover must come back as (nil, nil): an error would
// be recorded by certmagic's single-flight and fail handshakes another
// manager could have served. A client that sent no SNI at all gets the
// pack's certificate, as before.
func (certdx *CertDXTls) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && hello.ServerName != "" && !certPackCovers(certdx.domains, hello.ServerName) {
		return nil, nil
	}

	cert, err := certdx.certDXApp.GetCertificate(ctx, certdx.certHash)
	if err != nil {
		return nil, fmt.Errorf("certdx certificate %q: %w", certdx.CertId, err)
	}
	return cert, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens.
//
//	... certdx <cert-id>
func (certdx *CertDXTls) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		if len(args) != 1 {
			return d.Errf("expected 1 argument for certdx, got %d", len(args))
		}
		certdx.CertId = args[0]

		for d.NextBlock(0) {
			return d.Errf("no block expected for certdx")
		}
	}
	return nil
}

var (
	_ certmagic.Manager     = (*CertDXTls)(nil)
	_ caddy.Provisioner     = (*CertDXTls)(nil)
	_ caddy.Validator       = (*CertDXTls)(nil)
	_ caddyfile.Unmarshaler = (*CertDXTls)(nil)
)
