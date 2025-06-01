package client

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"pkg.para.party/certdx/pkg/logging"
)

func getMtlsConfig(CA, certificate, key string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		logging.Fatal("Invalid gRPC client cert, err: %s", err)
	}

	caPEM, err := os.ReadFile(CA)
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(caPEM) {
		logging.Fatal("Invalid ca cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}
