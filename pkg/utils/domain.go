package utils

import (
	"hash/fnv"
	"strings"
)

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

func DomainsAllowed(allowedList []string, toCheck []string) bool {
	for _, i := range toCheck {
		if !IsSubdomain(i, allowedList) {
			return false
		}
	}
	return true
}

func DomainAllowed(allowedList []string, toCheck string) bool {
	return IsSubdomain(toCheck, allowedList)
}

func DomainsAsKey(domains []string) uint64 {
	var h uint64 = 0
	for _, d := range domains {
		hf := fnv.New64a()
		hf.Write([]byte(d))
		h += hf.Sum64()
	}
	return h
}
