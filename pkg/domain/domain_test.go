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
