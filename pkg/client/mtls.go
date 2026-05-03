package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// getMtlsConfig builds the gRPC / HTTP mTLS client TLS config from the
// CA, certificate, and key on disk. Each step returns a wrapped error
// instead of `logging.Fatal`-ing so the daemon entry point can decide
// whether to abort, retry, or surface the failure to its caller.
func getMtlsConfig(CA, certificate, key string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return nil, fmt.Errorf("load mtls client certificate: %w", err)
	}

	caPEM, err := os.ReadFile(CA)
	if err != nil {
		return nil, fmt.Errorf("read mtls ca certificate: %w", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse mtls ca certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}
