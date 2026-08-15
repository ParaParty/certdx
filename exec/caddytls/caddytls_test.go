package caddytls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
)

// makeKeyPair mints a throwaway self-signed leaf so the tests can
// exercise the parse path without touching the network or an ACME server.
func makeKeyPair(t *testing.T, cn string) (fullchain, key []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
}

func TestCertPackCovers(t *testing.T) {
	domains := []string{"example.com", "*.wild.com"}

	cases := []struct {
		name string
		sni  string
		want bool
	}{
		{"exact", "example.com", true},
		{"exact case insensitive", "EXAMPLE.COM", true},
		{"exact trailing dot", "example.com.", true},
		{"literal entry does not cover subdomain", "foo.example.com", false},
		{"wildcard one label", "foo.wild.com", true},
		{"wildcard two labels", "foo.bar.wild.com", false},
		{"wildcard base", "wild.com", false},
		{"wildcard literal", "*.wild.com", true},
		{"unrelated", "other.net", false},
		{"empty", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := certPackCovers(domains, c.sni); got != c.want {
				t.Fatalf("certPackCovers(%q) = %v, want %v", c.sni, got, c.want)
			}
		})
	}
}

func TestGetCertificateSNIMismatchFallsThrough(t *testing.T) {
	fullchain, key := makeKeyPair(t, "example.com")

	domains := []string{"example.com"}
	certHash := domain.AsKey(domains)
	shared := &sharedCert{}
	if err := shared.store(fullchain, key); err != nil {
		t.Fatalf("store: %v", err)
	}

	app := &CertDXCaddyDaemon{certs: map[domain.Key]*sharedCert{certHash: shared}}
	m := &CertDXTls{CertId: "web", certDXApp: app, certHash: certHash, domains: domains}

	got, err := m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || got == nil {
		t.Fatalf("matching SNI: got (%v, %v), want a certificate", got, err)
	}

	// A name this pack does not cover must not be an error: certmagic
	// caches the failure and would poison unrelated handshakes.
	got, err = m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "other.net"})
	if got != nil || err != nil {
		t.Fatalf("non-matching SNI: got (%v, %v), want (nil, nil)", got, err)
	}

	// No SNI at all keeps the previous behaviour of serving the pack.
	got, err = m.GetCertificate(t.Context(), &tls.ClientHelloInfo{})
	if err != nil || got == nil {
		t.Fatalf("empty SNI: got (%v, %v), want a certificate", got, err)
	}
}

func TestGetCertificatePropagatesParseError(t *testing.T) {
	domains := []string{"example.com"}
	certHash := domain.AsKey(domains)
	shared := &sharedCert{}
	if err := shared.store([]byte("not a pem"), []byte("neither is this")); err == nil {
		t.Fatal("store: expected an error for garbage material")
	}

	app := &CertDXCaddyDaemon{certs: map[domain.Key]*sharedCert{certHash: shared}}
	m := &CertDXTls{CertId: "web", certDXApp: app, certHash: certHash, domains: domains}

	_, err := m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "web") || strings.Contains(err.Error(), "no certificate found") {
		t.Fatalf("error %q swallows the cause", err)
	}
}

func TestSharedCertKeepsLastGoodMaterial(t *testing.T) {
	fullchain, key := makeKeyPair(t, "example.com")

	shared := &sharedCert{}
	if _, err := shared.certificate(); err == nil {
		t.Fatal("expected an error before any material is stored")
	}
	if err := shared.store(fullchain, key); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := shared.store(fullchain, []byte("broken")); err == nil {
		t.Fatal("expected an error for a broken key")
	}
	if cert, err := shared.certificate(); err != nil || cert == nil {
		t.Fatalf("certificate() = (%v, %v), want the last good keypair", cert, err)
	}
}

// TestSharedCertsSurviveReload walks the reference dance Caddy performs on
// a config reload: the new app provisions (and so acquires) before the old
// one is cleaned up, which is what keeps the material alive.
func TestSharedCertsSurviveReload(t *testing.T) {
	fullchain, key := makeKeyPair(t, "example.com")
	certHash := domain.AsKey([]string{"example.com"})

	old := &CertDXCaddyDaemon{}
	shared, err := old.acquireSharedCert(certHash)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = old.Cleanup() })
	if err := shared.store(fullchain, key); err != nil {
		t.Fatalf("store: %v", err)
	}

	fresh := &CertDXCaddyDaemon{}
	reloaded, err := fresh.acquireSharedCert(certHash)
	if err != nil {
		t.Fatalf("acquire after reload: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Cleanup() })

	if err := old.Cleanup(); err != nil {
		t.Fatalf("cleanup old: %v", err)
	}
	if cert, err := reloaded.certificate(); err != nil || cert == nil {
		t.Fatalf("after reload: (%v, %v), want the carried-over keypair", cert, err)
	}

	// Once the last config referencing it goes away the entry is dropped.
	if err := fresh.Cleanup(); err != nil {
		t.Fatalf("cleanup fresh: %v", err)
	}
	if _, ok := sharedCerts.References(certHash); ok {
		t.Fatal("shared cert entry outlived its last reference")
	}
}

func TestSetDefaultConfigFillsOnlyUnsetFields(t *testing.T) {
	var c CertDXCaddyConfig
	c.Mode = config.CLIENT_MODE_GRPC
	c.Http.MainServer.AuthMethod = config.HTTP_AUTH_MTLS

	c.SetDefaultConfig()

	if c.RetryCount != defaultRetryCount {
		t.Fatalf("RetryCount = %d, want %d", c.RetryCount, defaultRetryCount)
	}
	if c.ReconnectInterval != defaultReconnectInterval {
		t.Fatalf("ReconnectInterval = %q, want %q", c.ReconnectInterval, defaultReconnectInterval)
	}
	if c.Mode != config.CLIENT_MODE_GRPC {
		t.Fatalf("Mode = %q, want it left alone", c.Mode)
	}
	if c.Http.MainServer.AuthMethod != config.HTTP_AUTH_MTLS {
		t.Fatalf("MainServer.AuthMethod = %q, want it left alone", c.Http.MainServer.AuthMethod)
	}
	// A native-JSON config that omits authMethod must not end up sending
	// unauthenticated requests.
	if c.Http.StandbyServer.AuthMethod != config.HTTP_AUTH_TOKEN {
		t.Fatalf("StandbyServer.AuthMethod = %q, want %q",
			c.Http.StandbyServer.AuthMethod, config.HTTP_AUTH_TOKEN)
	}
}

func TestValidateConfig(t *testing.T) {
	pem := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(pem, []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	newHTTP := func(mutate func(*CertDXCaddyConfig)) *CertDXCaddyConfig {
		c := &CertDXCaddyConfig{}
		c.SetDefaultConfig()
		c.Http.MainServer.Url = "https://certdx.example.com"
		c.Http.MainServer.Token = "secret"
		if mutate != nil {
			mutate(c)
		}
		return c
	}

	cases := []struct {
		name    string
		cfg     *CertDXCaddyConfig
		wantErr bool
	}{
		{"http token", newHTTP(nil), false},
		{"http missing url", newHTTP(func(c *CertDXCaddyConfig) { c.Http.MainServer.Url = "" }), true},
		{"http bad auth method", newHTTP(func(c *CertDXCaddyConfig) { c.Http.MainServer.AuthMethod = "mTLS" }), true},
		{"http mtls missing pem", newHTTP(func(c *CertDXCaddyConfig) {
			c.Http.MainServer.AuthMethod = config.HTTP_AUTH_MTLS
			c.Http.MainServer.PEM = filepath.Join(t.TempDir(), "absent.pem")
		}), true},
		{"http mtls present pem", newHTTP(func(c *CertDXCaddyConfig) {
			c.Http.MainServer.AuthMethod = config.HTTP_AUTH_MTLS
			c.Http.MainServer.PEM = pem
		}), false},
		{"http standby bad pem", newHTTP(func(c *CertDXCaddyConfig) {
			c.Http.StandbyServer.Url = "https://standby.example.com"
			c.Http.StandbyServer.AuthMethod = config.HTTP_AUTH_MTLS
			c.Http.StandbyServer.PEM = filepath.Join(t.TempDir(), "absent.pem")
		}), true},
		{"grpc missing pem", newHTTP(func(c *CertDXCaddyConfig) {
			c.Mode = config.CLIENT_MODE_GRPC
			c.GRPC.MainServer.Server = "certdx.example.com:1443"
			c.GRPC.MainServer.PEM = filepath.Join(t.TempDir(), "absent.pem")
		}), true},
		{"grpc ok", newHTTP(func(c *CertDXCaddyConfig) {
			c.Mode = config.CLIENT_MODE_GRPC
			c.GRPC.MainServer.Server = "certdx.example.com:1443"
			c.GRPC.MainServer.PEM = pem
		}), false},
		{"unknown mode", newHTTP(func(c *CertDXCaddyConfig) { c.Mode = "quic" }), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.validateConfig()
			if (err != nil) != c.wantErr {
				t.Fatalf("validateConfig() = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestUnmarshalHttpServerBlockRejectsUnknownAuthMethod(t *testing.T) {
	c := MakeCertDXCaddyDaemon()
	d := caddyfile.NewTestDispenser(`main_server {
	url https://certdx.example.com
	authMethod mTLS
	token secret
}`)

	err := c.unmarshalHttpServerBlock(&c.Http.MainServer, d)
	if err == nil {
		t.Fatal("expected a typo'd auth method to fail the adapt")
	}
	if !strings.Contains(err.Error(), dirAuthMethod) {
		t.Fatalf("error %q does not mention %s", err, dirAuthMethod)
	}
}

func TestUnmarshalHttpServerBlockAcceptsKnownAuthMethods(t *testing.T) {
	for _, method := range []string{config.HTTP_AUTH_TOKEN, config.HTTP_AUTH_MTLS} {
		c := MakeCertDXCaddyDaemon()
		d := caddyfile.NewTestDispenser("main_server {\n\tauthMethod " + method + "\n}")
		if err := c.unmarshalHttpServerBlock(&c.Http.MainServer, d); err != nil {
			t.Fatalf("authMethod %q: %v", method, err)
		}
		if c.Http.MainServer.AuthMethod != method {
			t.Fatalf("AuthMethod = %q, want %q", c.Http.MainServer.AuthMethod, method)
		}
	}
}

func TestExpectArg1NamesTheDirective(t *testing.T) {
	d := caddyfile.NewTestDispenser("retry_count 3 4\n")
	d.Next()

	_, err := expectArg1(d)
	if err == nil {
		t.Fatal("expected an error for two arguments")
	}
	if !strings.Contains(err.Error(), dirRetryCount) {
		t.Fatalf("error %q names an argument instead of the directive", err)
	}
}
