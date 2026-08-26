package client

import (
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
		WithCertificateHandlerOption(func([]byte, []byte, *config.ClientCertificate) {
			firstCalls++
		}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddCertToWatchOpt("namespace/second", domains, []WatchingCertsOption{
		WithCertificateHandlerOption(func([]byte, []byte, *config.ClientCertificate) {
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
