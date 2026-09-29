package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/paths"
)

// withDataDir points paths at a fresh temp data root for the duration of
// the test and resets the package-level serial counter.
func withDataDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	paths.SetDataDir(dir)
	counter.SetInt64(0)
	t.Cleanup(func() {
		paths.SetDataDir("")
		counter.SetInt64(0)
	})
	return dir
}

// firstCertInBundle parses the leading CERTIFICATE block of a bundle.
func firstCertInBundle(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	certPEM, _ := splitCertAndKeyPEM(data)
	if certPEM == nil {
		t.Fatalf("no CERTIFICATE block in %s", path)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert in %s: %v", path, err)
	}
	return cert
}

func readCounter(t *testing.T) *big.Int {
	t.Helper()
	p, err := paths.CACounterPath()
	if err != nil {
		t.Fatalf("CACounterPath: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	n, ok := new(big.Int).SetString(strings.TrimSpace(string(data)), 10)
	if !ok {
		t.Fatalf("counter file is not a number: %q", data)
	}
	return n
}

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

func TestWriteBundlePermissionsAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.pem")
	certData := []byte("test-cert-data")
	keyData := []byte("test-key-data")

	if err := writeBundle(p,
		pemBlock{"CERTIFICATE", certData},
		pemBlock{"PRIVATE KEY", keyData},
	); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}

	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm: got %o want 0600", mode)
	}

	content, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	block, rest := pem.Decode(content)
	if block == nil {
		t.Fatal("failed to decode first PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("first block type: got %q want CERTIFICATE", block.Type)
	}
	if string(block.Bytes) != string(certData) {
		t.Fatalf("first block data mismatch")
	}

	block, _ = pem.Decode(rest)
	if block == nil {
		t.Fatal("failed to decode second PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		t.Fatalf("second block type: got %q want PRIVATE KEY", block.Type)
	}
	if string(block.Bytes) != string(keyData) {
		t.Fatalf("second block data mismatch")
	}
}

func TestMakeClientCertReservedNames(t *testing.T) {
	for _, name := range []string{"ca", "CA", " ca ", " CA "} {
		t.Run(name, func(t *testing.T) {
			err := MakeClientCert(name, "org", "cn", []string{"example.com"})
			if err == nil {
				t.Fatalf("expected error for reserved name %q", name)
			}
		})
	}
}

func TestMakeServerCertReservedNames(t *testing.T) {
	for _, name := range []string{"ca", "CA", " ca "} {
		t.Run(name, func(t *testing.T) {
			err := MakeServerCert(name, "org", "cn", []string{"example.com"})
			if err == nil {
				t.Fatalf("expected error for reserved name %q", name)
			}
		})
	}
}

func TestMakeClientCertServerNameAllowed(t *testing.T) {
	// "server" is no longer reserved; this should fail only because
	// there is no CA to sign against, not because the name is rejected.
	err := MakeClientCert("server", "org", "cn", []string{"example.com"})
	if err == nil {
		t.Fatal("expected error (no CA), got nil")
	}
	if err.Error() == `name "server" is reserved for CA material` {
		t.Fatal("'server' should no longer be reserved")
	}
}

func TestMakeCASerialAndConstraints(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}

	caPath, err := paths.MtlsCAPath()
	if err != nil {
		t.Fatalf("MtlsCAPath: %v", err)
	}
	ca := firstCertInBundle(t, caPath)

	if ca.SerialNumber.Sign() <= 0 {
		t.Errorf("CA serial = %s, want positive (RFC 5280)", ca.SerialNumber)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid {
		t.Error("CA is missing basic constraints")
	}
	if !ca.MaxPathLenZero || ca.MaxPathLen != 0 {
		t.Errorf("CA pathLen = %d (zero=%t), want 0/true", ca.MaxPathLen, ca.MaxPathLenZero)
	}
	if !ca.NotAfter.Equal(defaultNotAfter) {
		t.Errorf("CA NotAfter = %s, want default %s", ca.NotAfter, defaultNotAfter)
	}

	// The counter must be initialized to the first positive serial.
	if got, want := readCounter(t), big.NewInt(firstEntitySerial); got.Cmp(want) != 0 {
		t.Errorf("counter after MakeCA = %s, want %s", got, want)
	}
}

func TestEntitySerialsArePositiveAndUnique(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	caPath, _ := paths.MtlsCAPath()
	ca := firstCertInBundle(t, caPath)

	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}); err != nil {
		t.Fatalf("MakeServerCert: %v", err)
	}
	if err := MakeClientCert("client", "org", "cn", nil); err != nil {
		t.Fatalf("MakeClientCert: %v", err)
	}

	srvPath, _ := paths.MtlsBundlePath("server")
	cliPath, _ := paths.MtlsBundlePath("client")
	srv := firstCertInBundle(t, srvPath)
	cli := firstCertInBundle(t, cliPath)

	for name, c := range map[string]*x509.Certificate{"server": srv, "client": cli} {
		if c.SerialNumber.Sign() <= 0 {
			t.Errorf("%s serial = %s, want positive", name, c.SerialNumber)
		}
		if c.SerialNumber.Cmp(ca.SerialNumber) == 0 {
			t.Errorf("%s serial duplicates the CA serial %s", name, c.SerialNumber)
		}
	}
	if srv.SerialNumber.Cmp(cli.SerialNumber) == 0 {
		t.Errorf("server and client share serial %s", srv.SerialNumber)
	}
	if got, want := srv.SerialNumber, big.NewInt(1); got.Cmp(want) != 0 {
		t.Errorf("first entity serial = %s, want %s", got, want)
	}
	if got, want := readCounter(t), big.NewInt(3); got.Cmp(want) != 0 {
		t.Errorf("counter after two certs = %s, want %s", got, want)
	}
}

func TestEntityCertDefaultNotAfter(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}); err != nil {
		t.Fatalf("MakeServerCert: %v", err)
	}

	srvPath, _ := paths.MtlsBundlePath("server")
	srv := firstCertInBundle(t, srvPath)

	if !srv.NotAfter.Equal(defaultNotAfter) {
		t.Errorf("leaf NotAfter = %s, want default %s", srv.NotAfter, defaultNotAfter)
	}
}

func TestWithLifetimeOverride(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn", WithLifetime(48*time.Hour)); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeClientCert("client", "org", "cn", nil, WithLifetime(24*time.Hour)); err != nil {
		t.Fatalf("MakeClientCert: %v", err)
	}

	caPath, _ := paths.MtlsCAPath()
	cliPath, _ := paths.MtlsBundlePath("client")
	ca := firstCertInBundle(t, caPath)
	cli := firstCertInBundle(t, cliPath)

	// NotBefore is backdated by up to an hour, so the span is at least
	// the requested lifetime and less than an hour longer.
	for name, c := range map[string]struct {
		cert *x509.Certificate
		want time.Duration
	}{"CA": {ca, 48 * time.Hour}, "leaf": {cli, 24 * time.Hour}} {
		got := c.cert.NotAfter.Sub(c.cert.NotBefore)
		if got < c.want || got >= c.want+time.Hour {
			t.Errorf("%s lifetime = %s, want %s (+<1h backdating)", name, got, c.want)
		}
	}
}

func TestWithLifetimeRejectsNonPositive(t *testing.T) {
	withDataDir(t)

	for _, d := range []time.Duration{0, -1, -24 * time.Hour} {
		if err := MakeCA("org", "cn", WithLifetime(d)); err == nil {
			t.Fatalf("MakeCA with WithLifetime(%s): want error, got nil", d)
		}
	}
	caPath, _ := paths.MtlsCAPath()
	if paths.FileExists(caPath) {
		t.Fatal("rejected MakeCA still wrote a CA bundle")
	}

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}, WithLifetime(0)); err == nil {
		t.Fatal("MakeServerCert with WithLifetime(0): want error, got nil")
	}
	srvPath, _ := paths.MtlsBundlePath("server")
	if paths.FileExists(srvPath) {
		t.Fatal("rejected MakeServerCert still wrote a bundle")
	}
}

func TestLeafDefaultExpiryCappedAtCA(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn", WithLifetime(48*time.Hour)); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}); err != nil {
		t.Fatalf("MakeServerCert: %v", err)
	}

	caPath, _ := paths.MtlsCAPath()
	srvPath, _ := paths.MtlsBundlePath("server")
	ca := firstCertInBundle(t, caPath)
	srv := firstCertInBundle(t, srvPath)
	if !srv.NotAfter.Equal(ca.NotAfter) {
		t.Errorf("leaf NotAfter = %s, want capped at CA NotAfter %s", srv.NotAfter, ca.NotAfter)
	}
}

func TestLeafExplicitLifetimeBeyondCARejected(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn", WithLifetime(48*time.Hour)); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	before := readCounter(t)

	if err := MakeClientCert("client", "org", "cn", nil, WithLifetime(72*time.Hour)); err == nil {
		t.Fatal("MakeClientCert with a lifetime beyond the CA: want error, got nil")
	}
	cliPath, _ := paths.MtlsBundlePath("client")
	if paths.FileExists(cliPath) {
		t.Fatal("rejected MakeClientCert still wrote a bundle")
	}
	if got := readCounter(t); got.Cmp(before) != 0 {
		t.Errorf("counter = %s after rejected issuance, want unchanged %s", got, before)
	}

	// A lifetime inside the CA's validity is still accepted.
	if err := MakeClientCert("client", "org", "cn", nil, WithLifetime(24*time.Hour)); err != nil {
		t.Fatalf("MakeClientCert within CA validity: %v", err)
	}
}

// A lifetime shorter than the elapsed part of the current hour must still
// yield a certificate valid after issuance: NotAfter counts from the
// issuance time, not from the backdated NotBefore.
func TestShortLifetimeIsNotAlreadyExpired(t *testing.T) {
	withDataDir(t)

	issued := time.Date(2026, time.March, 1, 12, 45, 0, 0, time.UTC)
	now = func() time.Time { return issued }
	t.Cleanup(func() { now = time.Now })

	if err := MakeCA("org", "cn", WithLifetime(30*time.Minute)); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeClientCert("client", "org", "cn", nil, WithLifetime(30*time.Minute)); err != nil {
		t.Fatalf("MakeClientCert: %v", err)
	}

	caPath, _ := paths.MtlsCAPath()
	cliPath, _ := paths.MtlsBundlePath("client")
	wantNotBefore := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	wantNotAfter := time.Date(2026, time.March, 1, 13, 15, 0, 0, time.UTC)
	for name, path := range map[string]string{"CA": caPath, "leaf": cliPath} {
		c := firstCertInBundle(t, path)
		if !c.NotBefore.Equal(wantNotBefore) {
			t.Errorf("%s NotBefore = %s, want %s", name, c.NotBefore, wantNotBefore)
		}
		if !c.NotAfter.Equal(wantNotAfter) {
			t.Errorf("%s NotAfter = %s, want %s", name, c.NotAfter, wantNotAfter)
		}
		if !c.NotAfter.After(issued) {
			t.Errorf("%s already expired at issuance: NotAfter %s <= %s", name, c.NotAfter, issued)
		}
	}
}

func TestLegacyZeroCounterIsBumpedToPositive(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	// Simulate a CA created by a pre-fix version, whose counter file
	// holds the non-positive serial 0.
	counterPath, _ := paths.CACounterPath()
	if err := os.WriteFile(counterPath, []byte("0"), permCounter); err != nil {
		t.Fatalf("write counter: %v", err)
	}

	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}); err != nil {
		t.Fatalf("MakeServerCert: %v", err)
	}
	srvPath, _ := paths.MtlsBundlePath("server")
	srv := firstCertInBundle(t, srvPath)
	if srv.SerialNumber.Sign() <= 0 {
		t.Fatalf("leaf serial = %s, want positive", srv.SerialNumber)
	}
}

func TestCounterPersistedBeforeBundle(t *testing.T) {
	withDataDir(t)

	if err := MakeCA("org", "cn"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := MakeServerCert("server", "org", "cn", []string{"localhost"}); err != nil {
		t.Fatalf("MakeServerCert: %v", err)
	}

	srvPath, _ := paths.MtlsBundlePath("server")
	counterPath, _ := paths.CACounterPath()

	bundleInfo, err := os.Stat(srvPath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	counterInfo, err := os.Stat(counterPath)
	if err != nil {
		t.Fatalf("stat counter: %v", err)
	}
	if counterInfo.ModTime().After(bundleInfo.ModTime()) {
		t.Error("serial counter was written after the bundle; a crash in between would reuse a serial")
	}

	// The persisted counter must already be past the issued serial.
	srv := firstCertInBundle(t, srvPath)
	if readCounter(t).Cmp(srv.SerialNumber) <= 0 {
		t.Error("persisted counter is not greater than the issued serial")
	}
}
