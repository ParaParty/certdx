package acmeproviders

import "strings"

var providerURLs = map[string]string{
	"google":     "https://dv.acme-v02.api.pki.goog/directory",
	"googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
	"r3":         "https://acme-v02.api.letsencrypt.org/directory",
	"r3test":     "https://acme-staging-v02.api.letsencrypt.org/directory",
	// "mock" is a hermetic provider used by the e2e test suite; it produces
	// self-signed certs in-process and does not contact any ACME server.
	"mock": "",
}

// Mock is the provider key for the in-process mock ACME used in tests.
const Mock = "mock"

// Supported reports whether provider has a known ACME directory.
func Supported(provider string) bool {
	_, ok := providerURLs[provider]
	return ok
}

// IsMock reports whether the provider is the in-process mock.
func IsMock(provider string) bool {
	return provider == Mock
}

// IsGoogle reports whether provider uses Google's ACME directory.
func IsGoogle(provider string) bool {
	return strings.HasPrefix(provider, "google")
}

// URL returns the ACME directory URL for provider.
func URL(provider string) string {
	return providerURLs[provider]
}
