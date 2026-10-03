package domain

import "strings"

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
//     certdx requests exactly the names a certificate lists, so a certificate
//     of only ["*.example.com"] has "*.example.com" as its sole SAN, which per
//     RFC 6125 does not match the apex. Certificates that serve the apex list
//     it explicitly, and the exact-equality branch matches it.
//
// IsSubdomain keeps its literal semantics for the server allow-list gate; this
// helper is for callers matching against a configured certificate's domain
// list, where wildcards are meaningful.
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
