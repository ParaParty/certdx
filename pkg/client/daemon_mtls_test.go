package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns the PEM leaf certificate and key for cn, signed by ca.
func (ca *testCA) issue(t *testing.T, cn string, serial int64, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
}

// writeClientBundle writes a certdx client bundle: leaf, key, then CA.
func (ca *testCA) writeClientBundle(t *testing.T, path, cn string, serial int64) {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, cn, serial, x509.ExtKeyUsageClientAuth)
	data := append(append(certPEM, keyPEM...), ca.pem...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

// TestHttpClientForPicksUpReplacedMTLSBundle: the HTTP client is cached
// across poll rounds, but a renewed client bundle on disk must still be
// the one presented on the next round.
func TestHttpClientForPicksUpReplacedMTLSBundle(t *testing.T) {
	ca := newTestCA(t)

	var (
		mu       sync.Mutex
		lastPeer string
	)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastPeer = r.TLS.PeerCertificates[0].Subject.CommonName
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{RenewTimeLeft: time.Hour})
	}))
	serverCert, serverKey := ca.issue(t, "server", 100, x509.ExtKeyUsageServerAuth)
	keyPair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	ts.StartTLS()
	defer ts.Close()

	bundle := filepath.Join(t.TempDir(), "client.pem")
	ca.writeClientBundle(t, bundle, "client-old", 2)

	d := MakeCertDXClientDaemon()
	d.Config.Common.RetryCount = 0
	d.Config.Http.MainServer = config.ClientHttpServer{
		Url:              ts.URL,
		AuthMethod:       config.HTTP_AUTH_MTLS,
		ClientMtlsConfig: config.ClientMtlsConfig{PEM: bundle},
	}

	request := func() string {
		t.Helper()
		if resp := d.httpRequestCert([]string{"example.com"}); resp == nil {
			t.Fatal("request failed")
		}
		mu.Lock()
		defer mu.Unlock()
		return lastPeer
	}

	if got := request(); got != "client-old" {
		t.Fatalf("first round presented %q, want client-old", got)
	}
	first, err := d.httpClientFor(&d.Config.Http.MainServer)
	if err != nil {
		t.Fatalf("httpClientFor: %v", err)
	}

	ca.writeClientBundle(t, bundle, "client-new", 3)
	if got := request(); got != "client-new" {
		t.Fatalf("after replacing the bundle presented %q, want client-new", got)
	}

	// The unchanged bundle keeps the rebuilt client.
	second, err := d.httpClientFor(&d.Config.Http.MainServer)
	if err != nil {
		t.Fatalf("httpClientFor: %v", err)
	}
	third, err := d.httpClientFor(&d.Config.Http.MainServer)
	if err != nil {
		t.Fatalf("httpClientFor: %v", err)
	}
	if second == first || second != third {
		t.Fatal("client must be rebuilt once per bundle change and reused otherwise")
	}
}
