package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"

	"pkg.para.party/certdx/pkg/logging"
)

func getMtlsConfig(bundlePath string) *tls.Config {
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		logging.Fatal("read mtls bundle %s: %s", bundlePath, err)
	}

	cert, err := tls.X509KeyPair(bundleData, bundleData)
	if err != nil {
		logging.Fatal("parse cert+key from mtls bundle: %s", err)
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
		Certificates: []tls.Certificate{cert},
		RootCAs:      capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}
