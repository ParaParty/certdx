package server

import (
	"context"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

// makeTestSDS builds an SDS server whose cert cache already holds a valid
// cert for domains, so the per-entry renewer never reaches ACME.
func makeTestSDS(t *testing.T, domains []string) (*MySDS, *certEntry) {
	t.Helper()
	s := makeTestServer("", "/", domains)
	entry, err := s.certCache.get(domains)
	if err != nil {
		t.Fatalf("cert cache get: %v", err)
	}
	entry.stateMu.Lock()
	entry.cert = CertT{
		FullChain:   []byte("PEM-chain"),
		Key:         []byte("PEM-key"),
		ValidBefore: time.Now().Add(time.Hour),
		RenewAt:     time.Now(),
	}
	entry.stateMu.Unlock()
	return &MySDS{cdxsrv: s}, entry
}

func recvResp(t *testing.T, resp chan *discoveryv3.DiscoveryResponse) *discoveryv3.DiscoveryResponse {
	t.Helper()
	select {
	case r := <-resp:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an SDS response")
		return nil
	}
}

func expectNoResp(t *testing.T, resp chan *discoveryv3.DiscoveryResponse, errChan chan error) {
	t.Helper()
	select {
	case r := <-resp:
		t.Fatalf("unexpected extra SDS response: version %q", r.VersionInfo)
	case err := <-errChan:
		t.Fatalf("unexpected stream error: %s", err)
	case <-time.After(200 * time.Millisecond):
	}
}

// A request whose version doesn't match the offer carries no ErrorDetail
// unless it is a NACK. Reading Code/Message unconditionally used to panic
// in a plain goroutine and take the whole process with it.
func TestHandleCertVersionMismatchWithoutErrorDetail(t *testing.T) {
	sds, entry := makeTestSDS(t, []string{"example.com"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := make(chan *discoveryv3.DiscoveryRequest, 1)
	resp := make(chan *discoveryv3.DiscoveryResponse, 4)
	errChan := make(chan error, 1)

	go sds.handleCert(ctx, "pack", entry, req, resp, errChan, "test-peer")

	offer := recvResp(t, resp)
	if len(offer.Resources) != 1 {
		t.Fatalf("first offer should carry one resource, got %d", len(offer.Resources))
	}

	// Stale ack / re-subscription: no error detail, mismatching version.
	req <- &discoveryv3.DiscoveryRequest{VersionInfo: "not-the-offered-version"}

	reoffer := recvResp(t, resp)
	if reoffer.VersionInfo != offer.VersionInfo {
		t.Fatalf("re-offer version: got %q want %q", reoffer.VersionInfo, offer.VersionInfo)
	}

	// Only one re-offer per version, otherwise two packs on one stream
	// ping-pong forever.
	req <- &discoveryv3.DiscoveryRequest{VersionInfo: "not-the-offered-version"}
	expectNoResp(t, resp, errChan)
}

// A NACK must be logged, not answered with an immediate re-send of the
// very cert that was just rejected.
func TestHandleCertNackDoesNotResend(t *testing.T) {
	sds, entry := makeTestSDS(t, []string{"example.com"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := make(chan *discoveryv3.DiscoveryRequest, 1)
	resp := make(chan *discoveryv3.DiscoveryResponse, 4)
	errChan := make(chan error, 1)

	go sds.handleCert(ctx, "pack", entry, req, resp, errChan, "test-peer")

	offer := recvResp(t, resp)
	req <- &discoveryv3.DiscoveryRequest{
		VersionInfo: offer.VersionInfo,
		ErrorDetail: &rpcstatus.Status{Code: 13, Message: "bad cert"},
	}
	expectNoResp(t, resp, errChan)
}

// An ack is not required before the next renewal is offered: a client that
// never acks must not park the pack forever.
func TestHandleCertOffersRenewalWithoutAck(t *testing.T) {
	sds, entry := makeTestSDS(t, []string{"example.com"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := make(chan *discoveryv3.DiscoveryRequest, 1)
	resp := make(chan *discoveryv3.DiscoveryResponse, 4)
	errChan := make(chan error, 1)

	go sds.handleCert(ctx, "pack", entry, req, resp, errChan, "test-peer")

	offer := recvResp(t, resp)

	// Renew without any ack for the first offer.
	entry.stateMu.Lock()
	entry.cert = CertT{
		FullChain:   []byte("PEM-chain-2"),
		Key:         []byte("PEM-key-2"),
		ValidBefore: time.Now().Add(2 * time.Hour),
		RenewAt:     time.Now().Add(time.Minute),
	}
	entry.version++
	close(entry.updated)
	entry.updated = make(chan struct{})
	entry.stateMu.Unlock()

	next := recvResp(t, resp)
	if next.VersionInfo == offer.VersionInfo {
		t.Fatalf("renewal was not offered: still at version %q", next.VersionInfo)
	}
}

// The receive loop must never block on a pack handler that is parked
// waiting for a renewal, and the newest request wins.
func TestDispatchRequestNeverBlocks(t *testing.T) {
	reqChan := make(chan *discoveryv3.DiscoveryRequest, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			dispatchRequest(reqChan, &discoveryv3.DiscoveryRequest{VersionInfo: string(rune('a' + i))})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatchRequest blocked with no handler reading")
	}

	got := <-reqChan
	if got.VersionInfo != "e" {
		t.Fatalf("stale request served: got %q want %q", got.VersionInfo, "e")
	}
}
