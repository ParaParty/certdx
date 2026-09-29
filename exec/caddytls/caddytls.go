package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"

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
	certdx.certHash = domain.AsKey(domains)
	return nil
}

// GetCertificate serves the cert pack bound to this manager's cert-id.
// The ServerName is deliberately not checked against the pack's domains:
// Caddy only consults this manager for names matching the automation
// policy it is configured on, so a mismatch is a configuration error, and
// a peer rejects a certificate that does not cover its name anyway.
func (certdx *CertDXTls) GetCertificate(ctx context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
