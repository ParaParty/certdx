package domain

import "testing"

func TestIsSubdomainTreatsWildcardAsLiteralLabel(t *testing.T) {
	// The server allow-list gate relies on this literal behavior; CertCovers is
	// the wildcard-aware alternative.
	if IsSubdomain("foo.example.com", []string{"*.example.com"}) {
		t.Fatal("expected IsSubdomain to keep matching wildcard entries literally")
	}
}

func TestCertCoversWildcardEntry(t *testing.T) {
	covered := []string{
		"foo.example.com",
		"FOO.EXAMPLE.COM.",
		"*.example.com",
	}
	for _, name := range covered {
		if !CertCovers(name, "*.Example.COM.") {
			t.Fatalf("expected %q to be covered by *.example.com", name)
		}
	}

	notCovered := []string{
		// The apex is not a SAN of a "*.example.com"-only cert (RFC 6125),
		// so the wildcard entry must not claim to cover it.
		"example.com",
		"EXAMPLE.COM.",
		"foo.bar.example.com",
		"*.mm.example.com",
		"attackerexample.com",
		"example.com.attacker.net",
	}
	for _, name := range notCovered {
		if CertCovers(name, "*.example.com") {
			t.Fatalf("expected %q not to be covered by *.example.com", name)
		}
	}
}

func TestCertCoversLiteralEntryKeepsSubdomainBehavior(t *testing.T) {
	if !CertCovers("a.b.example.com", "example.com") {
		t.Fatal("expected literal entry to cover any subdomain")
	}
	if CertCovers("attackerevil.com", "evil.com") {
		t.Fatal("expected literal entry to require a label boundary")
	}
}

func TestAllCoveredMatchesWildcardOnlyCertificate(t *testing.T) {
	// The kubernetes example in docs/breaking-changes-v0.7.0.md uses this
	// wildcard-only domain list.
	certList := []string{"*.example.com", "*.mm.example.com"}

	for _, toCheck := range [][]string{
		{"foo.example.com"},
		{"*.example.com", "bar.example.com"},
		{"foo.mm.example.com", "bar.example.com"},
	} {
		if !AllCovered(certList, toCheck) {
			t.Fatalf("expected %v to be covered by %v", toCheck, certList)
		}
	}

	if AllCovered(certList, []string{"foo.example.com", "deep.nested.example.com"}) {
		t.Fatal("expected a two-label-deep name to fall outside the wildcard")
	}

	// A wildcard-only certificate does not carry the apex as a SAN, so it
	// must not claim to cover it.
	if AllCovered(certList, []string{"example.com"}) {
		t.Fatal("expected a wildcard-only certificate not to cover the apex")
	}
}

func TestAllCoveredApexNeedsExplicitEntry(t *testing.T) {
	// Certificates that serve the apex list it alongside the wildcard; the
	// exact-equality branch then matches it.
	certList := []string{"example.com", "*.example.com"}

	for _, name := range []string{"example.com", "EXAMPLE.COM.", "foo.example.com"} {
		if !CoveredByAny(certList, name) {
			t.Fatalf("expected %q to be covered by %v", name, certList)
		}
	}
}

func TestAllCoveredEmptyInputs(t *testing.T) {
	if !AllCovered([]string{"example.com"}, nil) {
		t.Fatal("expected an empty toCheck to be trivially covered")
	}
	if AllCovered(nil, []string{"example.com"}) {
		t.Fatal("expected an empty certList to cover nothing")
	}
}
