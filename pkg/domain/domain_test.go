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

func TestCanonical(t *testing.T) {
	in := []string{"b.Example.COM.", "", "a.example.com", "B.example.com", "."}
	orig := slices.Clone(in)

	got := Canonical(in)
	want := []string{"a.example.com", "b.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("Canonical(%q) = %q, want %q", in, got, want)
	}
	if !slices.Equal(in, orig) {
		t.Fatalf("Canonical modified its input: %q", in)
	}
	if again := Canonical(got); !slices.Equal(again, got) {
		t.Fatalf("Canonical is not idempotent: %q -> %q", got, again)
	}

	for _, empty := range [][]string{nil, {}, {"", "."}} {
		if got := Canonical(empty); len(got) != 0 {
			t.Fatalf("Canonical(%q) = %q, want empty", empty, got)
		}
	}
}

func TestAsKeyOfCanonicalDomainSets(t *testing.T) {
	first := AsKey(Canonical([]string{"API.Example.COM.", "example.com", "api.example.com"}))
	second := AsKey(Canonical([]string{"example.com.", "api.example.com"}))

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
