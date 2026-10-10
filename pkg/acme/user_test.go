package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pkg.para.party/certdx/pkg/paths"
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

func TestRegisterAccountRefusesExistingKey(t *testing.T) {
	paths.SetDataDir(t.TempDir())
	t.Cleanup(func() { paths.SetDataDir("") })

	keyPath, err := paths.ACMEPrivateKey("me@example.com", "googletest")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = RegisterAccount("googletest", "me@example.com", "kid", "hmac", false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if got, _ := os.ReadFile(keyPath); string(got) != "old" {
		t.Fatalf("existing key was modified: %q", got)
	}
}

func TestWriteAccountKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")

	if err := writeAccountKey(path, []byte("first"), false); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := writeAccountKey(path, []byte("second"), false); err == nil {
		t.Fatal("expected an error overwriting without force")
	}
	if err := writeAccountKey(path, []byte("third"), true); err != nil {
		t.Fatalf("forced overwrite: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "third" {
		t.Fatalf("content = %q, want %q", got, "third")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", info.Mode().Perm(), err)
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
