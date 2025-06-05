package acmeprovider

import "strings"

var acmeProvidersMap = map[string]string{
	"google":     "https://dv.acme-v02.api.pki.goog/directory",
	"googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
	"r3":         "https://acme-v02.api.letsencrypt.org/directory",
	"r3test":     "https://acme-staging-v02.api.letsencrypt.org/directory",
}

func ACMEProviderSupported(provider string) bool {
	_, ok := acmeProvidersMap[provider]
	return ok
}

func IsACMEProviderGoogle(provider string) bool {
	return strings.HasPrefix(provider, "google")
}

func GetACMEURL(provider string) string {
	return acmeProvidersMap[provider]
}
