//go:build e2e

package harness

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"
)

// WaitForCertFile polls path until it parses as a PEM x509 certificate or
// timeout elapses. Returns the parsed cert.
func WaitForCertFile(tb testing.TB, path string, timeout time.Duration) *x509.Certificate {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		cert, err := tryLoadCert(path)
		if err == nil {
			return cert
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	tb.Fatalf("timed out waiting for cert at %s: %s", path, lastErr)
	return nil
}

// WaitForCertChange polls path until the cert there differs from prev (by
// raw DER) or timeout elapses. Returns the new cert.
func WaitForCertChange(tb testing.TB, path string, prev *x509.Certificate, timeout time.Duration) *x509.Certificate {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		cert, err := tryLoadCert(path)
		if err == nil && !bytes.Equal(cert.Raw, prev.Raw) {
			return cert
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	tb.Fatalf("timed out waiting for cert change at %s (last err: %v)", path, lastErr)
	return nil
}

// WaitForFile polls until path exists and is non-empty.
func WaitForFile(tb testing.TB, path string, timeout time.Duration) {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	tb.Fatalf("timed out waiting for file %s", path)
}

func tryLoadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}
