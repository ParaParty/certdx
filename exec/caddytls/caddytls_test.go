package caddytls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

func newManager(certID string, domains []string, cert *servedCert) *CertDXTls {
	certHash := domain.AsKey(domains)
	app := &CertDXCaddyDaemon{certs: map[domain.Key]*servedCert{certHash: cert}}
	return &CertDXTls{CertId: certID, certDXApp: app, certHash: certHash}
}

func TestGetCertificateServesPack(t *testing.T) {
	fullchain, key := makeKeyPair(t, "example.com")
	cert := &servedCert{}
	if err := cert.store(fullchain, key); err != nil {
		t.Fatalf("store: %v", err)
	}
	m := newManager("web", []string{"example.com"}, cert)

	got, err := m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || got == nil {
		t.Fatalf("GetCertificate = (%v, %v), want a certificate", got, err)
	}
}

// TestGetCertificateStartsEmpty: every config load, reloads included,
// starts without material and says so until the first fetch lands.
func TestGetCertificateStartsEmpty(t *testing.T) {
	m := newManager("web", []string{"example.com"}, &servedCert{})

	_, err := m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if !errors.Is(err, errNoCertYet) {
		t.Fatalf("GetCertificate error = %v, want %v", err, errNoCertYet)
	}
}

func TestGetCertificatePropagatesParseError(t *testing.T) {
	cert := &servedCert{}
	if err := cert.store([]byte("not a pem"), []byte("neither is this")); err == nil {
		t.Fatal("store: expected an error for garbage material")
	}
	m := newManager("web", []string{"example.com"}, cert)

	_, err := m.GetCertificate(t.Context(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), `"web"`) || errors.Is(err, errNoCertYet) {
		t.Fatalf("error %q swallows the cause", err)
	}
}

func TestServedCertKeepsLastGoodMaterial(t *testing.T) {
	fullchain, key := makeKeyPair(t, "example.com")

	cert := &servedCert{}
	if err := cert.store(fullchain, key); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := cert.store(fullchain, []byte("broken")); err == nil {
		t.Fatal("expected an error for a broken key")
	}
	if got, err := cert.certificate(); err != nil || got == nil {
		t.Fatalf("certificate() = (%v, %v), want the last good keypair", got, err)
	}
}

func TestFillUnsetDefaultsFillsOnlyUnsetFields(t *testing.T) {
	var c CertDXCaddyConfig
	c.Mode = config.CLIENT_MODE_GRPC
	c.Http.MainServer.AuthMethod = config.HTTP_AUTH_MTLS

	c.fillUnsetDefaults()

	if c.RetryCount != 0 {
		t.Fatalf("RetryCount = %d, want 0 (a single attempt is a valid choice)", c.RetryCount)
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

func TestSetDefaultConfig(t *testing.T) {
	var c CertDXCaddyConfig
	c.SetDefaultConfig()

	if c.RetryCount != defaultRetryCount {
		t.Fatalf("RetryCount = %d, want %d", c.RetryCount, defaultRetryCount)
	}
	if c.Mode != config.CLIENT_MODE_HTTP {
		t.Fatalf("Mode = %q, want %q", c.Mode, config.CLIENT_MODE_HTTP)
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
