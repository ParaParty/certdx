package client

import (
	"context"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
)

func TestWatchUpdateDropsInvalidCert(t *testing.T) {
	daemon := MakeCertDXClientDaemon()
	domains := []string{"example.com"}

	got := make(chan []byte, 2)
	if err := daemon.AddCertToWatchOpt("example", domains, []WatchingCertsOption{
		WithCertificateHandlerOption(func(fullchain, _ []byte, _ *config.ClientCertificate) {
			got <- fullchain
		}),
	}); err != nil {
		t.Fatal(err)
	}
	cert := daemon.certs[domain.AsKey(domains)]

	daemon.wg.Add(1)
	go daemon.watchUpdate(cert)
	defer func() {
		daemon.Stop()
		daemon.wg.Wait()
	}()

	fullchain, key, err := acme.NewMockACME(time.Hour).Obtain(context.Background(), domains, time.Time{})
	if err != nil {
		t.Fatalf("mock obtain: %v", err)
	}

	cert.UpdateChan <- certData{Domains: domains}
	cert.UpdateChan <- certData{Domains: domains, Fullchain: []byte("garbage"), Key: []byte("garbage")}
	cert.UpdateChan <- certData{Domains: domains, Fullchain: fullchain, Key: key}

	select {
	case delivered := <-got:
		if string(delivered) != string(fullchain) {
			t.Fatalf("invalid cert reached the handler: %q", delivered)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid cert was not delivered")
	}
}

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
