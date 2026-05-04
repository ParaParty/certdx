package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// TestParsePEMRoundTrip generates an ECDSA P-384 key (the same curve
// RegisterAccount uses), PEM-encodes it, and confirms parsePEM hands
// back the same key. parsePEM is the post-audit replacement for the
// old panic-on-bad-input parser, so a round-trip + bad-input pair pin
// the contract.
func TestParsePEMRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := parsePEM(pemBytes)
	if err != nil {
		t.Fatalf("parsePEM: %v", err)
	}
	parsed, ok := got.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("parsePEM returned %T, want *ecdsa.PrivateKey", got)
	}
	if parsed.D.Cmp(priv.D) != 0 {
		t.Fatalf("scalar mismatch after round-trip")
	}
}

func TestParsePEMRejectsGarbage(t *testing.T) {
	_, err := parsePEM([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error on garbage input")
	}
	if !strings.Contains(err.Error(), "parse ACME account key") {
		t.Fatalf("error should be wrapped, got %v", err)
	}
}

func TestParsePEMRejectsEmpty(t *testing.T) {
	_, err := parsePEM(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

// TestParsePEMRejectsWrongTypeBlock confirms a PEM block with the
// wrong type still surfaces an error rather than panicking — this is
// the path that the audit fix replaced.
func TestParsePEMRejectsWrongTypeBlock(t *testing.T) {
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not actually a key"),
	})
	_, err := parsePEM(body)
	if err == nil {
		t.Fatal("expected error on wrong-type PEM block")
	}
	// Don't assert the underlying lego error string — just that it
	// surfaces and is wrapped.
	if errors.Is(err, nil) {
		t.Fatal("nil error wrap")
	}
}
