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

// CertCovers reports whether a certificate issued for the single name entry
// covers the domain name. Matching is case-insensitive and ignores a trailing
// root dot. Unlike IsSubdomain, which treats every entry as a literal label
// sequence, entry may be a wildcard:
//
//   - a literal entry ("example.com") covers itself and any subdomain of it,
//     exactly as IsSubdomain does;
//   - a wildcard entry ("*.example.com") covers the literal string itself and
//     any name exactly one label below the base ("foo.example.com", but not
//     "foo.bar.example.com"). It does NOT cover the base ("example.com"):
//     certdx requests exactly the names a cert pack lists, so a pack of only
//     ["*.example.com"] yields a certificate whose sole SAN is "*.example.com",
//     which per RFC 6125 does not match the apex. Packs that serve the apex
//     list it explicitly, and the exact-equality branch matches it.
//
// This agrees with certPackCovers in exec/caddytls for wildcard entries; the
// literal-entry subdomain rule is the one deliberate difference (see the
// comment there). IsSubdomain keeps its literal semantics for the server
// allow-list gate; this helper is for callers matching against a configured
// cert-pack domain list, where wildcards are meaningful.
func CertCovers(name, entry string) bool {
	n := normalizeName(name)
	e := normalizeName(entry)
	if n == e {
		return true
	}

	base, isWildcard := strings.CutPrefix(e, "*.")
	if !isWildcard {
		return strings.HasSuffix(n, "."+e)
	}
	label, ok := strings.CutSuffix(n, "."+base)
	return ok && label != "" && !strings.Contains(label, ".")
}

// CoveredByAny reports whether name is covered by at least one entry of
// certList according to CertCovers.
func CoveredByAny(certList []string, name string) bool {
	for _, entry := range certList {
		if CertCovers(name, entry) {
			return true
		}
	}
	return false
}

// AllCovered reports whether every name in toCheck is covered by certList
// according to CertCovers. An empty toCheck is trivially covered.
func AllCovered(certList []string, toCheck []string) bool {
	for _, name := range toCheck {
		if !CoveredByAny(certList, name) {
			return false
		}
	}
	return true
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}
