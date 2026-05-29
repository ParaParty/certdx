// Package mtls loads PEM bundle files used for certdx's mTLS endpoints
// and returns ready-to-use *tls.Config values for server and client
// roles.
//
// Bundle layout: the first CERTIFICATE block is the entity (leaf)
// certificate, followed by its PRIVATE KEY in any position, followed by
// one or more additional CERTIFICATE blocks that form the CA chain
// used to verify the peer.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func parseBundle(path string) (tls.Certificate, *x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read mtls bundle %s: %w", path, err)
	}

	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse cert+key from mtls bundle: %w", err)
	}

	pool := x509.NewCertPool()
	rest := data
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
			continue
		}
		pool.AppendCertsFromPEM(pem.EncodeToMemory(block))
	}

	return cert, pool, nil
}

// LoadServer builds the TLS config for gRPC SDS / HTTP mTLS server
// endpoints (RequireAndVerifyClientCert).
func LoadServer(bundlePath string) (*tls.Config, error) {
	cert, pool, err := parseBundle(bundlePath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClient builds the TLS config for mTLS clients.
func LoadClient(bundlePath string) (*tls.Config, error) {
	cert, pool, err := parseBundle(bundlePath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}
