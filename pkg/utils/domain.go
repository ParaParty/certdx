package utils

import "strings"

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
