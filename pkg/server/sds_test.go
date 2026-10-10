package server

import (
	"context"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

func TestHandleCertVersionMismatchWithoutErrorDetail(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	entry := mustGet(t, &s.certCache, []string{"example.com"})
	entry.cert = CertT{
		FullChain:   []byte("PEM-chain"),
		Key:         []byte("PEM-key"),
		ValidBefore: time.Now().Add(time.Hour),
	}
	sds := &MySDS{cdxsrv: s}

	ctx, cancel := context.WithCancel(context.Background())
	req := make(chan *discoveryv3.DiscoveryRequest)
	resp := make(chan *discoveryv3.DiscoveryResponse, 1)
	errChan := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sds.handleCert(ctx, "pack", entry, req, resp, errChan, "test-peer")
	}()

	select {
	case <-resp:
	case <-time.After(2 * time.Second):
		t.Fatal("no offer")
	}
	req <- &discoveryv3.DiscoveryRequest{VersionInfo: "other"}

	cancel()
	<-done
	select {
	case err := <-errChan:
		t.Fatalf("stream error: %v", err)
	default:
	}
}
