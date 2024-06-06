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
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"pkg.para.party/certdx/pkg/utils"
)

var counter big.Int = *big.NewInt(0)

func MakeCA(organization, commonName string) error {
	caPEMPath, caKeyPath, err := utils.GetSDSCAPath()
	if err != nil {
		return err
	}
	caCounterPath, err := utils.GetCACounterPath()
	if err != nil {
		return err
	}

	if utils.FileExists(caPEMPath) {
		return fmt.Errorf("CA file: %s already exists", caPEMPath)
	}
	if utils.FileExists(caKeyPath) {
		return fmt.Errorf("CA file: %s already exists", caKeyPath)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	SubjectOrganization := []string{organization}
	CASubject := pkix.Name{
		Organization: SubjectOrganization,
		CommonName:   commonName,
	}

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               CASubject,
		NotBefore:             time.Now().Truncate(1 * time.Hour),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	_ = os.WriteFile(caPEMPath, caPEM, 0o777)

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	caKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
	_ = os.WriteFile(caKeyPath, caKey, 0o600)

	_ = os.WriteFile(caCounterPath, []byte(counter.String()), 0o755)
	fmt.Println(string(caPEM))
	return nil
}

func loadCA() (*x509.Certificate, *crypto.PrivateKey, error) {
	caPEMPath, caKeyPath, err := utils.GetSDSCAPath()
	if err != nil {
		return nil, nil, err
	}
	caCounterPath, err := utils.GetCACounterPath()
	if err != nil {
		return nil, nil, err
	}

	caPEMData, err := os.ReadFile(caPEMPath)
	if err != nil {
		return nil, nil, err
	}
	caKeyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	caCounterData, err := os.ReadFile(caCounterPath)
	if err != nil {
		return nil, nil, err
	}

	caPEM, err := certcrypto.ParsePEMCertificate(caPEMData)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := certcrypto.ParsePEMPrivateKey(caKeyData)
	if err != nil {
		return nil, nil, err
	}
	_, ok := counter.SetString(string(caCounterData), 10)
	if !ok {
		return nil, nil, fmt.Errorf("bad counter")
	}

	return caPEM, &caKey, nil
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
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}

func makeCert(PEMPath, keyPath, organization, commonName string,
	domains []string, extKeyUseage []x509.ExtKeyUsage) error {

	counterPath, err := utils.GetCACounterPath()
	if err != nil {
		return err
	}

	if utils.FileExists(PEMPath) {
		return fmt.Errorf("file: %s already exists", PEMPath)
	}
	if utils.FileExists(keyPath) {
		return fmt.Errorf("file: %s already exists", keyPath)
	}

	caPEM, pcaKey, err := loadCA()
	if err != nil {
		return fmt.Errorf("failed load CA: %w", err)
	}
	caKey := *pcaKey

	ipAddresses := []net.IP{}
	for _, domain := range domains {
		addr := net.ParseIP(domain)
		if addr != nil {
			ipAddresses = append(ipAddresses, addr)
		}
	}

	SubjectOrganization := []string{organization}
	Subject := pkix.Name{
		Organization: SubjectOrganization,
		CommonName:   commonName,
	}

	cert := &x509.Certificate{
		SerialNumber: &counter,
		Subject:      Subject,
		DNSNames:     domains,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now().Truncate(1 * time.Hour),
		NotAfter:     time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExtKeyUsage:  extKeyUseage,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	cert.SubjectKeyId, err = generateSubjectKeyID(priv.Public())
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caPEM, &priv.PublicKey, caKey)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	_ = os.WriteFile(PEMPath, certPEM, 0o777)

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	certKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
	_ = os.WriteFile(keyPath, certKey, 0o777)

	counter.Add(&counter, big.NewInt(1))
	_ = os.WriteFile(counterPath, []byte(counter.String()), 0o755)

	fmt.Println(string(certPEM))
	fmt.Println(string(certKey))
	return nil
}

func MakeServerCert(organization, commonName string, domains []string) error {
	servPEMPath, servKeyPath, err := utils.GetSDSServerCertPath()
	if err != nil {
		return err
	}
	return makeCert(servPEMPath, servKeyPath, organization, commonName, domains, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func MakeClientCert(name, organization, commonName string, domains []string) error {
	clientPEMPath, clientKeyPath, err := utils.GetSDSClientCertPath(name)
	if err != nil {
		return err
	}
	return makeCert(clientPEMPath, clientKeyPath, organization, commonName, domains, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}
