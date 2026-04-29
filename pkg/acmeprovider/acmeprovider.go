package acmeprovider

import "strings"

var acmeProvidersMap = map[string]string{
	"google":     "https://dv.acme-v02.api.pki.goog/directory",
	"googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
	"r3":         "https://acme-v02.api.letsencrypt.org/directory",
	"r3test":     "https://acme-staging-v02.api.letsencrypt.org/directory",
	// "mock" is a hermetic provider used by the e2e test suite; it produces
	// self-signed certs in-process and does not contact any ACME server.
	"mock": "",
}

// ProviderMock is the provider key for the in-process mock ACME used in tests.
const ProviderMock = "mock"

// IsACMEProviderMock reports whether the provider is the in-process mock.
func IsACMEProviderMock(provider string) bool {
	return provider == ProviderMock
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
