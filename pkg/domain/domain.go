// Package domain provides helpers for working with the set of fully-qualified
// domain names that flow through certdx — matching against allow-lists,
// hashing a domain bundle into a stable key for cache lookups, and so on.
//
// All functions here are pure and have no I/O.
package domain

import (
	"hash/fnv"
	"strings"
)

// Key is a stable, order-insensitive hash of a set of domain names. Two slices
// containing the same domains in any order produce the same Key, so it is safe
// to use as a map key for cert-cache lookups.
type Key uint64

// AsKey hashes a slice of domain names into a Key. The hash is order-
// insensitive: AsKey([]string{"a", "b"}) == AsKey([]string{"b", "a"}).
func AsKey(domains []string) Key {
	var h uint64 = 0
	for _, d := range domains {
		hf := fnv.New64a()
		hf.Write([]byte(d))
		h += hf.Sum64()
	}
	return Key(h)
}

// IsSubdomain reports whether domain is one of allowedDomains, or a subdomain
// of any of them. Exact matches and dot-prefixed suffix matches both count.
func IsSubdomain(domain string, allowedDomains []string) bool {
	for _, allowedDomain := range allowedDomains {
		if allowedDomain == domain {
			return true
		}
		if strings.HasSuffix(domain, "."+allowedDomain) {
			return true
		}
	}
	return false
}

// AllAllowed reports whether every domain in toCheck is allowed by allowedList
// according to IsSubdomain. An empty toCheck is trivially allowed.
func AllAllowed(allowedList []string, toCheck []string) bool {
	for _, i := range toCheck {
		if !IsSubdomain(i, allowedList) {
			return false
		}
	}
	return true
}

// Allowed reports whether toCheck is allowed by allowedList according to
// IsSubdomain.
func Allowed(allowedList []string, toCheck string) bool {
	return IsSubdomain(toCheck, allowedList)
}
