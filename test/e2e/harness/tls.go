//go:build e2e

package harness

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"
)

// WaitForTLSCert dials addr with TLS, sending the given SNI, until either a
// handshake succeeds or timeout elapses. The peer's leaf certificate is
// returned. If roots is non-nil, the chain must verify against it; otherwise
// verification is skipped (caller is expected to verify the returned cert
// against a trusted CA via VerifyChain).
func WaitForTLSCert(tb testing.TB, addr, serverName string, roots *x509.CertPool, timeout time.Duration) *x509.Certificate {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	cfg := &tls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: roots == nil,
		MinVersion:         tls.VersionTLS12,
	}
	for time.Now().Before(deadline) {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err == nil {
			state := conn.ConnectionState()
			_ = conn.Close()
			if len(state.PeerCertificates) == 0 {
				lastErr = fmt.Errorf("no peer certificates")
			} else {
				return state.PeerCertificates[0]
			}
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	tb.Fatalf("timed out waiting for TLS handshake at %s (sni=%s): %v", addr, serverName, lastErr)
	return nil
}
