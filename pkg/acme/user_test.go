package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

func TestParsePEMRejectsInvalid(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"garbage", []byte("not a pem block")},
		{"wrong type block", pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not actually a key"),
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePEM(tc.input)
			if err == nil {
				t.Fatal("expected error on invalid input")
			}
		})
	}
}
