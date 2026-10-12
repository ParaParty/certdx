package server

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// targetValidBefore aims certLifeTime past the top of the current hour. The
// truncation can land in the past for a sub-hour certLifeTime, in which case
// it aims from now instead.
func targetValidBefore(now time.Time, certLifeTime time.Duration) time.Time {
	target := now.Truncate(time.Hour).Add(certLifeTime)
	if !target.After(now) {
		return now.Add(certLifeTime)
	}
	return target
}

// leafNotAfter returns the NotAfter of the first certificate in a PEM chain.
func leafNotAfter(fullchain []byte) (time.Time, error) {
	rest := fullchain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return time.Time{}, fmt.Errorf("no certificate in fullchain")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
		}
		return cert.NotAfter, nil
	}
}
