package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"pkg.para.party/certdx/pkg/paths"
)

// getMtlsConfig builds the gRPC SDS / HTTP mTLS server TLS config from
// the on-disk material under the resolved mTLS directory. Each step
// returns a wrapped error so the daemon entry point can surface the
// failure to its caller instead of `logging.Fatal`-ing here.
func getMtlsConfig() (*tls.Config, error) {
	srvCertPath, srvKeyPath, err := paths.MtlsServerCertPath()
	if err != nil {
		return nil, fmt.Errorf("resolve mtls server certificate path: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(srvCertPath, srvKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mtls server certificate: %w", err)
	}

	caPEMPath, _, err := paths.MtlsCAPath()
	if err != nil {
		return nil, fmt.Errorf("resolve mtls ca path: %w", err)
	}
	caPEM, err := os.ReadFile(caPEMPath)
	if err != nil {
		return nil, fmt.Errorf("read mtls ca certificate: %w", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse mtls ca certificate")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}
