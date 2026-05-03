package tools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"pkg.para.party/certdx/pkg/paths"
)

const (
	permPrivateKey os.FileMode = 0o600
	permPublicCert os.FileMode = 0o644
	permCounter    os.FileMode = 0o644
)

// counter holds the serial number for the next certificate to be issued.
// It is persisted to disk in the mTLS directory and incremented after every
// successful signing.
var counter big.Int

// MakeCA creates a self-signed CA certificate/key pair at the default mTLS
// paths. Fails if files already exist to avoid clobbering an in-use CA.
func MakeCA(organization, commonName string) error {
	caPEMPath, caKeyPath, err := paths.MtlsCAPath()
	if err != nil {
		return err
	}
	caCounterPath, err := paths.CACounterPath()
	if err != nil {
		return err
	}

	if paths.FileExists(caPEMPath) {
		return fmt.Errorf("CA file already exists: %s", caPEMPath)
	}
	if paths.FileExists(caKeyPath) {
		return fmt.Errorf("CA key already exists: %s", caKeyPath)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Truncate(1 * time.Hour),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("self-signing CA: %w", err)
	}

	if err := writePEM(caPEMPath, "CERTIFICATE", caBytes, permPublicCert); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling CA key: %w", err)
	}
	if err := writePEM(caKeyPath, "PRIVATE KEY", keyDER, permPrivateKey); err != nil {
		return err
	}

	if err := os.WriteFile(caCounterPath, []byte(counter.String()), permCounter); err != nil {
		return fmt.Errorf("writing serial counter: %w", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	fmt.Println(string(caPEM))
	return nil
}

func loadCA() (*x509.Certificate, crypto.PrivateKey, error) {
	caPEMPath, caKeyPath, err := paths.MtlsCAPath()
	if err != nil {
		return nil, nil, err
	}
	caCounterPath, err := paths.CACounterPath()
	if err != nil {
		return nil, nil, err
	}

	caPEMData, err := os.ReadFile(caPEMPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA cert: %w", err)
	}
	caKeyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA key: %w", err)
	}
	caCounterData, err := os.ReadFile(caCounterPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading serial counter: %w", err)
	}

	caPEM, err := certcrypto.ParsePEMCertificate(caPEMData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA cert: %w", err)
	}
	caKey, err := certcrypto.ParsePEMPrivateKey(caKeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA key: %w", err)
	}
	if _, ok := counter.SetString(string(caCounterData), 10); !ok {
		return nil, nil, fmt.Errorf("invalid serial number counter in %s", caCounterPath)
	}

	return caPEM, caKey, nil
}

func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	sum := sha1.Sum(info.SubjectPublicKey.Bytes)
	return sum[:], nil
}

// splitIPsAndDNS separates literal IP addresses out of a mixed list of
// DNS names and addresses. Literal IPs remain in the SANs as IPAddresses
// rather than DNSNames, as required by RFC 5280.
func splitIPsAndDNS(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return
}

func makeCert(pemPath, keyPath, organization, commonName string,
	domains []string, extKeyUsage []x509.ExtKeyUsage) error {

	counterPath, err := paths.CACounterPath()
	if err != nil {
		return err
	}

	if paths.FileExists(pemPath) {
		return fmt.Errorf("cert file already exists: %s", pemPath)
	}
	if paths.FileExists(keyPath) {
		return fmt.Errorf("key file already exists: %s", keyPath)
	}

	caCert, caKey, err := loadCA()
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}

	dnsNames, ipAddresses := splitIPsAndDNS(domains)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	skid, err := generateSubjectKeyID(priv.Public())
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}

	cert := &x509.Certificate{
		SerialNumber: &counter,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now().Truncate(1 * time.Hour),
		NotAfter:     time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExtKeyUsage:  extKeyUsage,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: skid,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing certificate: %w", err)
	}

	if err := writePEM(pemPath, "CERTIFICATE", certBytes, permPublicCert); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, permPrivateKey); err != nil {
		return err
	}

	counter.Add(&counter, big.NewInt(1))
	if err := os.WriteFile(counterPath, []byte(counter.String()), permCounter); err != nil {
		return fmt.Errorf("writing serial counter: %w", err)
	}

	fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})))
	fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return nil
}

// writePEM PEM-encodes der under typ and installs it at path with the given
// permissions.
func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// MakeServerCert issues a server certificate signed by the local CA.
func MakeServerCert(organization, commonName string, domains []string) error {
	pemPath, keyPath, err := paths.MtlsServerCertPath()
	if err != nil {
		return err
	}
	return makeCert(pemPath, keyPath, organization, commonName, domains,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// MakeClientCert issues a named client certificate signed by the local CA.
func MakeClientCert(name, organization, commonName string, domains []string) error {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ca", "server":
		return fmt.Errorf("client name %q is reserved for mtls material", name)
	}

	clientPEMPath, clientKeyPath, err := paths.MtlsClientCertPath(name)
	if err != nil {
		return err
	}
	return makeCert(clientPEMPath, clientKeyPath, organization, commonName, domains,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}
