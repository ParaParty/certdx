package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"pkg.para.party/certdx/pkg/types"

	"github.com/caddyserver/certmagic"
	"pkg.para.party/certdx/pkg/utils"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(CertDXTls{})
}

// CertDXTls can get a certificate via HTTP(S) request.
type CertDXTls struct {
	ctx       caddy.Context
	certDXApp *CertDXCaddyDaemon
	CertId    string `json:"cert_id"`
	certHash  types.DomainKey
}

// CaddyModule returns the Caddy module information.
func (certdx CertDXTls) CaddyModule() caddy.ModuleInfo {
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
		return fmt.Errorf("failed to get certdx app: %v", err)
	}

	ok := false
	certdx.certDXApp, ok = app.(*CertDXCaddyDaemon)
	if !ok {
		return fmt.Errorf("certdx app has an unexpected type: %T", app)
	}

	domains, exists := certdx.certDXApp.CertificateDefs[certdx.CertId]
	if !exists {
		return fmt.Errorf("cert definition for cert-id: %v not exists", certdx.CertId)
	}
	certdx.certHash = utils.DomainsAsKey(domains)

	return nil
}

func (certdx CertDXTls) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return certdx.certDXApp.GetCertificate(ctx, certdx.certHash)
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... certdx [cert-id]
func (certdx *CertDXTls) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		if len(args) != 1 {
			return d.Errf("expected 1 argument for certdx, got %v", len(args))
		}

		certdx.CertId = args[0]

		for d.NextBlock(0) {
			return d.Errf("no block excepted for certdx")
		}
	}
	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*CertDXTls)(nil)
	_ caddy.Provisioner     = (*CertDXTls)(nil)
	_ caddy.Validator       = (*CertDXTls)(nil)
	_ caddyfile.Unmarshaler = (*CertDXTls)(nil)
)
