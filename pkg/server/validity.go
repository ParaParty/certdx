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

// clampValidBefore shortens target to the issued leaf's notAfter minus
// renewTimeLeft. When that is already past (the CA issued a cert shorter
// than renewTimeLeft), the cert is kept until it really expires instead.
func clampValidBefore(now, target, notAfter time.Time, renewTimeLeft time.Duration) time.Time {
	renewBy := notAfter.Add(-renewTimeLeft)
	switch {
	case !renewBy.Before(target):
		return target
	case renewBy.After(now):
		return renewBy
	case notAfter.After(now) && notAfter.Before(target):
		return notAfter
	default:
		// The leaf is already expired; nothing better to derive from it.
		return target
	}
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
