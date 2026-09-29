package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"pkg.para.party/certdx/pkg/acme/acmeproviders"
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

// accountKeyPath points the state root at a temp dir and returns the
// account key path RegisterAccount would use for the mock provider. The
// mock provider has an empty directory URL, so lego fails to build a
// client without touching the network — which is exactly the failure
// path the key handling has to survive.
func accountKeyPath(t *testing.T) string {
	t.Helper()
	paths.SetDataDir(t.TempDir())
	t.Cleanup(func() { paths.SetDataDir("") })

	keyPath, err := paths.ACMEPrivateKey("u@example.com", acmeproviders.Mock)
	if err != nil {
		t.Fatalf("ACMEPrivateKey: %v", err)
	}
	return keyPath
}

// TestRegisterAccountKeepsExistingKey pins the data-loss fix: without
// force, an existing account key is never touched.
func TestRegisterAccountKeepsExistingKey(t *testing.T) {
	keyPath := accountKeyPath(t)
	existing := []byte("existing account key")
	if err := os.WriteFile(keyPath, existing, 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	if err := RegisterAccount(acmeproviders.Mock, "u@example.com", "", "", false); err == nil {
		t.Fatal("expected RegisterAccount to refuse overwriting an existing key")
	}

	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(got) != string(existing) {
		t.Fatalf("account key was modified: %q", got)
	}
}

// TestRegisterAccountForceRestoresKey checks that a forced re-register
// that fails puts the previous key back instead of leaving the account
// unrecoverable.
func TestRegisterAccountForceRestoresKey(t *testing.T) {
	keyPath := accountKeyPath(t)
	existing := []byte("existing account key")
	if err := os.WriteFile(keyPath, existing, 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	if err := RegisterAccount(acmeproviders.Mock, "u@example.com", "", "", true); err == nil {
		t.Fatal("expected RegisterAccount to fail against the mock directory")
	}

	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(got) != string(existing) {
		t.Fatalf("previous account key was not restored: %q", got)
	}
}

// TestRegisterAccountCleansUpNewKey keeps the old behaviour for the case
// there was nothing to lose: a failed first registration leaves no key.
func TestRegisterAccountCleansUpNewKey(t *testing.T) {
	keyPath := accountKeyPath(t)

	if err := RegisterAccount(acmeproviders.Mock, "u@example.com", "", "", false); err == nil {
		t.Fatal("expected RegisterAccount to fail against the mock directory")
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("stat %s: want not exist, got %v", keyPath, err)
	}
}
