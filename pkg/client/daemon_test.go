package client

import (
	"path/filepath"
	"testing"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
)

func TestAddCertToWatchOptKeepsHandlersForDuplicateDomains(t *testing.T) {
	daemon := MakeCertDXClientDaemon()
	domains := []string{"newtest.campuses.cn", "*.newtest.campuses.cn"}

	firstCalls := 0
	secondCalls := 0
	if err := daemon.AddCertToWatchOpt("namespace/first", domains, []WatchingCertsOption{
		WithCertificateHandlerOption(func([]byte, []byte, *config.ClientCertification) {
			firstCalls++
		}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddCertToWatchOpt("namespace/second", domains, []WatchingCertsOption{
		WithCertificateHandlerOption(func([]byte, []byte, *config.ClientCertification) {
			secondCalls++
		}),
	}); err != nil {
		t.Fatal(err)
	}

	if len(daemon.certs) != 1 {
		t.Fatalf("watched certificates = %d, want 1", len(daemon.certs))
	}
	registered := daemon.certs[domain.AsKey(domains)]
	for _, handler := range registered.UpdateHandlers {
		handler([]byte("cert"), []byte("key"), &registered.Config)
	}

	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("one certificate notification should reach both registrations; calls = first:%d second:%d", firstCalls, secondCalls)
	}
}

// TestHttpClientForReusesClient pins the transport-leak fix: the
// config-derived client is built once and reused by every poll round,
// instead of a fresh http.Transport per attempt.
func TestHttpClientForReusesClient(t *testing.T) {
	d := MakeCertDXClientDaemon()
	d.Config.Http.MainServer = config.ClientHttpServer{
		Url:        "https://example.com",
		AuthMethod: config.HTTP_AUTH_TOKEN,
		Token:      "tok",
	}

	first, err := d.httpClientFor(&d.Config.Http.MainServer)
	if err != nil {
		t.Fatalf("httpClientFor: %v", err)
	}
	second, err := d.httpClientFor(&d.Config.Http.MainServer)
	if err != nil {
		t.Fatalf("httpClientFor: %v", err)
	}
	if first != second {
		t.Fatal("httpClientFor built a second client for the same server")
	}
}

// TestHttpClientForReturnsErrorOnBadMTLS: a broken mTLS bundle must be
// a plain error, never a process exit.
func TestHttpClientForReturnsErrorOnBadMTLS(t *testing.T) {
	d := MakeCertDXClientDaemon()
	d.Config.Http.MainServer = config.ClientHttpServer{
		Url:              "https://example.com",
		AuthMethod:       config.HTTP_AUTH_MTLS,
		ClientMtlsConfig: config.ClientMtlsConfig{PEM: filepath.Join(t.TempDir(), "does-not-exist.pem")},
	}

	if _, err := d.httpClientFor(&d.Config.Http.MainServer); err == nil {
		t.Fatal("expected error for unreadable mtls bundle")
	}
	if _, cached := d.httpClients[&d.Config.Http.MainServer]; cached {
		t.Fatal("failed client must not be cached")
	}
}
