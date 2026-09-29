package domain

import (
	"slices"
	"testing"
)

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

func TestCanonicalNormalizesDedupesAndSorts(t *testing.T) {
	in := []string{"b.Example.COM.", "", "a.example.com", "B.example.com", "."}
	orig := slices.Clone(in)

	got := Canonical(in)
	want := []string{"a.example.com", "b.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("Canonical(%v) = %v, want %v", in, got, want)
	}
	if !slices.Equal(in, orig) {
		t.Fatalf("Canonical modified its input: %v, want %v", in, orig)
	}
	if got := Canonical(want); !slices.Equal(got, want) {
		t.Fatalf("Canonical is not idempotent: %v -> %v", want, got)
	}
}

func TestCanonicalOfEmptySetIsEmpty(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"", "."}} {
		if got := Canonical(in); len(got) != 0 {
			t.Fatalf("Canonical(%q) = %v, want empty", in, got)
		}
	}
}

func TestAsKeyMatchesKeyOfCanonicalForm(t *testing.T) {
	in := []string{"API.Example.COM.", "example.com", "api.example.com"}
	if AsKey(in) != AsKey(Canonical(in)) {
		t.Fatalf("AsKey(%v) differs from AsKey of its canonical form", in)
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
