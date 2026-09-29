package mtls

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
	"testing"
	"time"
)

// testChain is an in-memory CA + leaf pair used to assemble bundles.
type testChain struct {
	caCert   *x509.Certificate
	caPEM    []byte
	leafPEM  []byte
	leafKey  []byte
	leafCert *x509.Certificate
}

func newTestChain(t *testing.T) *testChain {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test leaf"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	return &testChain{
		caCert:   caCert,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		leafKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		leafCert: leafCert,
	}
}

// writeBundle writes the concatenated PEM blocks to a temp file and
// returns its path.
func writeBundle(t *testing.T, blocks ...[]byte) string {
	t.Helper()
	var buf []byte
	for _, b := range blocks {
		buf = append(buf, b...)
	}
	p := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p
}

// expectedPool is the pool a well-formed bundle must produce.
func expectedPool(c *testChain) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.caCert)
	return pool
}

func TestParseBundleWellFormed(t *testing.T) {
	c := newTestChain(t)
	path := writeBundle(t, c.leafPEM, c.leafKey, c.caPEM)

	cert, pool, err := parseBundle(path)
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no leaf certificate in tls.Certificate")
	}
	if string(cert.Certificate[0]) != string(c.leafCert.Raw) {
		t.Fatal("tls.Certificate leaf is not the first CERTIFICATE block")
	}
	if !pool.Equal(expectedPool(c)) {
		t.Fatal("peer pool does not contain exactly the CA certificate")
	}
	if _, err := c.leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("leaf does not verify against the parsed pool: %v", err)
	}
}

func TestParseBundleKeyFirst(t *testing.T) {
	c := newTestChain(t)
	// The key may sit in any position; the first CERTIFICATE block is
	// still the entity cert and the rest form the peer pool.
	path := writeBundle(t, c.leafKey, c.leafPEM, c.caPEM)

	cert, pool, err := parseBundle(path)
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if string(cert.Certificate[0]) != string(c.leafCert.Raw) {
		t.Fatal("leaf mismatch when the key comes first")
	}
	if !pool.Equal(expectedPool(c)) {
		t.Fatal("peer pool does not contain exactly the CA certificate")
	}
}

func TestParseBundleMissingCA(t *testing.T) {
	c := newTestChain(t)
	path := writeBundle(t, c.leafPEM, c.leafKey)

	if _, _, err := parseBundle(path); err == nil {
		t.Fatal("expected an error for a bundle with no CA section")
	}
}

func TestParseBundleReorderedCAFirst(t *testing.T) {
	c := newTestChain(t)
	// CA first means tls.X509KeyPair pairs the CA cert with the leaf
	// key, which must fail at load rather than at handshake time.
	path := writeBundle(t, c.caPEM, c.leafPEM, c.leafKey)

	if _, _, err := parseBundle(path); err == nil {
		t.Fatal("expected an error when the CA precedes the entity cert")
	}
}

func TestParseBundleIgnoresExtraPEMTypes(t *testing.T) {
	c := newTestChain(t)
	noise := pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte("ignored")})
	trust := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: c.caCert.Raw})
	path := writeBundle(t, noise, c.leafPEM, trust, c.leafKey, c.caPEM)

	_, pool, err := parseBundle(path)
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if !pool.Equal(expectedPool(c)) {
		t.Fatal("non-CERTIFICATE blocks must not enter the peer pool")
	}
}

func TestParseBundleMissingFile(t *testing.T) {
	if _, _, err := parseBundle(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Fatal("expected an error for a missing bundle file")
	}
}

func TestParseBundleGarbage(t *testing.T) {
	path := writeBundle(t, []byte("not pem at all\n"))
	if _, _, err := parseBundle(path); err == nil {
		t.Fatal("expected an error for a non-PEM bundle")
	}
}

func TestLoadServer(t *testing.T) {
	c := newTestChain(t)
	path := writeBundle(t, c.leafPEM, c.leafKey, c.caPEM)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("TLS version pinning: min=%x max=%x, want both TLS1.3", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil || !cfg.ClientCAs.Equal(expectedPool(c)) {
		t.Error("ClientCAs does not contain exactly the CA certificate")
	}
	if cfg.RootCAs != nil {
		t.Error("server config must not set RootCAs")
	}
}

func TestLoadClient(t *testing.T) {
	c := newTestChain(t)
	path := writeBundle(t, c.leafPEM, c.leafKey, c.caPEM)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("TLS version pinning: min=%x max=%x, want both TLS1.3", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil || !cfg.RootCAs.Equal(expectedPool(c)) {
		t.Error("RootCAs does not contain exactly the CA certificate")
	}
	if cfg.ClientCAs != nil {
		t.Error("client config must not set ClientCAs")
	}
}

func TestLoadServerAndClientRejectBundleWithoutCA(t *testing.T) {
	c := newTestChain(t)
	path := writeBundle(t, c.leafPEM, c.leafKey)

	if _, err := LoadServer(path); err == nil {
		t.Error("LoadServer accepted a bundle with no CA section")
	}
	if _, err := LoadClient(path); err == nil {
		t.Error("LoadClient accepted a bundle with no CA section")
	}
}
