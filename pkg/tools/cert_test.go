package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitIPsAndDNS(t *testing.T) {
	dns, ips := splitIPsAndDNS([]string{
		"example.com",
		"127.0.0.1",
		"api.example.com",
		"::1",
	})

	if got, want := len(dns), 2; got != want {
		t.Fatalf("dns count = %d, want %d: %v", got, want, dns)
	}
	if dns[0] != "example.com" || dns[1] != "api.example.com" {
		t.Fatalf("unexpected dns names: %v", dns)
	}

	wantIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if got, want := len(ips), len(wantIPs); got != want {
		t.Fatalf("ip count = %d, want %d: %v", got, want, ips)
	}
	for i := range wantIPs {
		if !ips[i].Equal(wantIPs[i]) {
			t.Fatalf("ip[%d] = %v, want %v", i, ips[i], wantIPs[i])
		}
	}
}

func TestSplitIPsAndDNSEmpty(t *testing.T) {
	dns, ips := splitIPsAndDNS(nil)
	if len(dns) != 0 || len(ips) != 0 {
		t.Fatalf("expected empty results, got dns=%v ips=%v", dns, ips)
	}
}

func TestGenerateSubjectKeyIDDeterministic(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	skid1, err := generateSubjectKeyID(priv.Public())
	if err != nil {
		t.Fatalf("generateSubjectKeyID: %v", err)
	}
	skid2, err := generateSubjectKeyID(priv.Public())
	if err != nil {
		t.Fatalf("generateSubjectKeyID: %v", err)
	}

	if len(skid1) != 20 {
		t.Fatalf("SKID length: got %d want 20 (SHA1)", len(skid1))
	}

	for i := range skid1 {
		if skid1[i] != skid2[i] {
			t.Fatal("SKID not deterministic for the same key")
		}
	}
}

func TestGenerateSubjectKeyIDDifferentKeys(t *testing.T) {
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	skid1, _ := generateSubjectKeyID(priv1.Public())
	skid2, _ := generateSubjectKeyID(priv2.Public())

	same := true
	for i := range skid1 {
		if skid1[i] != skid2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different keys should produce different SKIDs")
	}
}

func TestWritePEMPermissionsAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.pem")
	data := []byte("test-der-data")

	if err := writePEM(p, "CERTIFICATE", data, 0o644); err != nil {
		t.Fatalf("writePEM: %v", err)
	}

	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o644 {
		t.Fatalf("perm: got %o want 0644", mode)
	}

	content, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM type: got %q want CERTIFICATE", block.Type)
	}
	if string(block.Bytes) != string(data) {
		t.Fatalf("PEM data mismatch")
	}
}

func TestWritePEMPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key.pem")

	if err := writePEM(p, "PRIVATE KEY", []byte("key-data"), 0o600); err != nil {
		t.Fatalf("writePEM: %v", err)
	}

	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm: got %o want 0600", mode)
	}
}

func TestMakeClientCertReservedNames(t *testing.T) {
	for _, name := range []string{"ca", "CA", "server", "Server", " ca ", " SERVER "} {
		t.Run(name, func(t *testing.T) {
			err := MakeClientCert(name, "org", "cn", []string{"example.com"})
			if err == nil {
				t.Fatalf("expected error for reserved name %q", name)
			}
		})
	}
}
