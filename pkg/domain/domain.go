// Package domain provides helpers for working with the set of fully-qualified
// domain names that flow through certdx — matching against allow-lists,
// hashing a domain bundle into a stable key for cache lookups, and so on.
//
// All functions here are pure and have no I/O.
package domain

import (
	"errors"
	"hash/fnv"
	"sort"
	"strings"
)

// ErrNotAllowed is returned (or wrapped) when a domain or set of domains is
// outside the configured allow-list. Callers can branch with errors.Is to
// distinguish allow-list rejection from other failures.
var ErrNotAllowed = errors.New("domain not allowed")

// Key is a stable, order-insensitive hash of a set of domain names. Two slices
// containing the same domains in any order produce the same Key, so it is safe
// to use as a map key for cert-cache lookups.
type Key uint64

// AsKey hashes a slice of domain names into a Key. The input is canonicalized
// before hashing, so case, trailing root dots, duplicates, and input order do
// not affect the result.
func AsKey(domains []string) Key {
	canon := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = normalizeName(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		canon = append(canon, d)
	}
	sort.Strings(canon)

	h := fnv.New64a()
	h.Write([]byte(strings.Join(canon, "\x00")))
	return Key(h.Sum64())
}

// IsSubdomain reports whether domain is one of allowedDomains, or a subdomain
// of any of them. Matching is case-insensitive and ignores a trailing root dot.
func IsSubdomain(domain string, allowedDomains []string) bool {
	d := normalizeName(domain)
	for _, allowedDomain := range allowedDomains {
		parent := normalizeName(allowedDomain)
		if d == parent {
			return true
		}
		if strings.HasSuffix(d, "."+parent) {
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

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}
