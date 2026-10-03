package server

import (
	"context"
	"io"
	"slices"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
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

// fakeSecretsStream is an in-memory StreamSecrets stream. The embedded
// grpc.ServerStream is nil: StreamSecrets only uses Context, Recv and Send.
type fakeSecretsStream struct {
	grpc.ServerStream
	ctx  context.Context
	recv chan *discoveryv3.DiscoveryRequest
	sent chan *discoveryv3.DiscoveryResponse
}

func (f *fakeSecretsStream) Context() context.Context { return f.ctx }

func (f *fakeSecretsStream) Recv() (*discoveryv3.DiscoveryRequest, error) {
	select {
	case r := <-f.recv:
		return r, nil
	case <-f.ctx.Done():
		return nil, io.EOF
	}
}

func (f *fakeSecretsStream) Send(r *discoveryv3.DiscoveryResponse) error {
	select {
	case f.sent <- r:
		return nil
	case <-f.ctx.Done():
		return f.ctx.Err()
	}
}

// Domain packs from node metadata are canonicalized before they reach the
// cert cache, so the pack is issued for and cached under its canonical set.
func TestStreamSecretsCanonicalizesPackDomains(t *testing.T) {
	s := newTestServer(t)
	s.Config.ACME.AllowedDomains = []string{"example.com"}
	s.Config.ACME.CertLifeTimeDuration = 168 * time.Hour
	s.Config.ACME.RenewTimeLeftDuration = time.Hour
	fake, asked := recordingObtainer(t)
	s.acme = fake
	sds := &MySDS{cdxsrv: s}
	defer s.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	stream := &fakeSecretsStream{
		ctx:  ctx,
		recv: make(chan *discoveryv3.DiscoveryRequest, 1),
		sent: make(chan *discoveryv3.DiscoveryResponse, 1),
	}
	done := make(chan error, 1)
	go func() { done <- sds.StreamSecrets(stream) }()
	defer func() {
		cancel()
		<-done
	}()

	metadata, err := structpb.NewStruct(map[string]any{
		domainKey: map[string]any{
			"pack": []any{"WWW.Example.COM.", "example.com", "www.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	stream.recv <- &discoveryv3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		Node:          &corev3.Node{Metadata: metadata},
		ResourceNames: []string{"pack"},
	}

	offer := recvResp(t, stream.sent)
	if len(offer.Resources) != 1 {
		t.Fatalf("offer should carry one resource, got %d", len(offer.Resources))
	}

	canonical := []string{"example.com", "www.example.com"}
	if got := asked(); len(got) != 1 || !slices.Equal(got[0], canonical) {
		t.Fatalf("obtained for %v, want exactly one obtain for %v", got, canonical)
	}
	entries := cacheEntries(s)
	if len(entries) != 1 {
		t.Fatalf("cache entries = %d, want 1", len(entries))
	}
	if !slices.Equal(entries[0].domains, canonical) {
		t.Fatalf("entry domains: got %v want %v", entries[0].domains, canonical)
	}
}
