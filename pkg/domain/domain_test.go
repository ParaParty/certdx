package domain

import "testing"

func TestIsSubdomainNormalizesCaseAndRootDot(t *testing.T) {
	allowed := []string{"Example.COM."}

	for _, domain := range []string{
		"example.com",
		"EXAMPLE.com.",
		"api.example.com",
		"API.EXAMPLE.COM.",
	} {
		if !IsSubdomain(domain, allowed) {
			t.Fatalf("expected %q to be allowed by %v", domain, allowed)
		}
	}
}

func TestIsSubdomainRequiresLabelBoundary(t *testing.T) {
	allowed := []string{"evil.com"}

	for _, domain := range []string{
		"attackerevil.com",
		"sub.attackerevil.com",
		"evil.com.attacker.net",
	} {
		if IsSubdomain(domain, allowed) {
			t.Fatalf("expected %q to be rejected by %v", domain, allowed)
		}
	}
}

func TestAllAllowedUsesNormalizedSubdomainRules(t *testing.T) {
	allowed := []string{"Example.COM."}
	toCheck := []string{"example.com", "API.EXAMPLE.COM."}

	if !AllAllowed(allowed, toCheck) {
		t.Fatalf("expected %v to be allowed by %v", toCheck, allowed)
	}
}

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
		// so the wildcard entry must not claim to cover it. This mirrors
		// certPackCovers in exec/caddytls.
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

func TestAllCoveredMatchesShippedK8sConfigExample(t *testing.T) {
	// config/client_k8s.toml ships this cert-pack domain list, and docs/tools.md
	// documents secrets annotated with names under it.
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

	// A wildcard-only pack does not carry the apex as a SAN, so it must not
	// claim to cover it.
	if AllCovered(certList, []string{"example.com"}) {
		t.Fatal("expected a wildcard-only pack not to cover the apex")
	}
}

func TestAllCoveredApexNeedsExplicitEntry(t *testing.T) {
	// Packs that serve the apex list it alongside the wildcard; the
	// exact-equality branch then matches it.
	certList := []string{"example.com", "*.example.com"}

	for _, name := range []string{"example.com", "EXAMPLE.COM.", "foo.example.com"} {
		if !CoveredByAny(certList, name) {
			t.Fatalf("expected %q to be covered by %v", name, certList)
		}
	}
}

func TestAsKeyCanonicalizesDomainSets(t *testing.T) {
	first := AsKey([]string{"API.Example.COM.", "example.com", "api.example.com"})
	second := AsKey([]string{"example.com.", "api.example.com"})

	if first != second {
		t.Fatalf("expected equivalent domain sets to hash to the same key: %d != %d", first, second)
	}
}

func TestAsKeyKeepsDistinctDomainSetsDistinct(t *testing.T) {
	first := AsKey([]string{"a.example.com", "bc.example.com"})
	second := AsKey([]string{"ab.example.com", "c.example.com"})

	if first == second {
		t.Fatalf("expected distinct domain sets to hash to different keys: %d", first)
	}
}
