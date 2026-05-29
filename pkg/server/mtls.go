package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// getMtlsConfig builds the gRPC SDS / HTTP mTLS server TLS config from a
// PEM bundle file containing the server certificate, private key, and CA
// certificate.
func getMtlsConfig(bundlePath string) (*tls.Config, error) {
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read mtls bundle %s: %w", bundlePath, err)
	}

	cert, err := tls.X509KeyPair(bundleData, bundleData)
	if err != nil {
		return nil, fmt.Errorf("parse cert+key from mtls bundle: %w", err)
	}

	// Extract the CA certificate: the CERTIFICATE block that is NOT the
	// leaf (entity) certificate. The leaf is always the first CERTIFICATE
	// block; subsequent ones are CA / intermediates.
	capool := x509.NewCertPool()
	rest := bundleData
	first := true
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if first {
			first = false
			continue // skip entity cert
		}
		capool.AppendCertsFromPEM(pem.EncodeToMemory(block))
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}
