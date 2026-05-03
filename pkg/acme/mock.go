package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// MockACMETagEnv, when set, is embedded into the Subject.OrganizationalUnit
// of every cert minted by MockACME. Tests use this to identify which
// mock-backed server produced a given cert without log scraping.
const MockACMETagEnv = "CERTDX_MOCK_TAG"

// MockACME is an in-process ACME stand-in used by the e2e test suite.
// Each call to Obtain/RetryObtain mints a fresh self-signed leaf cert
// covering the requested domains; no network calls are made.
type MockACME struct {
	lifetime time.Duration
	tag      string
	serial   atomic.Int64
}

// NewMockACME returns a MockACME issuing certs with the given validity
// duration. If lifetime is zero, defaults to 1h. The cert tag is read
// from MockACMETagEnv at construction time.
//
// The serial counter is seeded from the current time in microseconds so
// that distinct server processes (which each have their own MockACME
// instance) produce non-overlapping serial ranges. Without this, every
// freshly-spawned server would mint serial=1 on its first Obtain, which
// is misleading when reading test logs.
func NewMockACME(lifetime time.Duration) *MockACME {
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	m := &MockACME{lifetime: lifetime, tag: os.Getenv(MockACMETagEnv)}
	m.serial.Store(time.Now().UnixMicro())
	return m
}

func (m *MockACME) Obtain(ctx context.Context, domains []string, _ time.Time) (fullchain, key []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("mock acme: no domains")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	dnsNames := make([]string, 0, len(domains))
	ipAddresses := []net.IP{}
	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, d)
		}
	}

	now := time.Now()
	serial := m.serial.Add(1)
	subject := pkix.Name{
		Organization: []string{"CertDX Mock ACME"},
		CommonName:   domains[0],
	}
	if m.tag != "" {
		subject.OrganizationalUnit = []string{m.tag}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(m.lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	fullchain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return fullchain, key, nil
}

func (m *MockACME) RetryObtain(ctx context.Context, domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	return m.Obtain(ctx, domains, deadline)
}
