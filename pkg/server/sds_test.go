package server

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"pkg.para.party/certdx/pkg/domain"
)

// fakeSecretsStream is an in-memory StreamSecrets stream; StreamSecrets only
// uses Context, Recv and Send.
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

// blockingObtainer never issues; it stands in for an ACME order in flight.
type blockingObtainer struct{}

func (blockingObtainer) Obtain(ctx context.Context, _ []string, _ time.Time) ([]byte, []byte, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (b blockingObtainer) RetryObtain(ctx context.Context, d []string, t time.Time) ([]byte, []byte, error) {
	return b.Obtain(ctx, d, t)
}

func newSDSTestServer(t *testing.T) *CertDXServer {
	t.Helper()
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.acme = blockingObtainer{}
	t.Cleanup(s.Stop)
	return s
}

func withCert(t *testing.T, s *CertDXServer, domains []string, renewAt time.Time) *certEntry {
	t.Helper()
	entry := mustGet(t, &s.certCache, domains)
	publishCert(entry, CertT{
		FullChain:   []byte("PEM-chain"),
		Key:         []byte("PEM-key"),
		ValidBefore: time.Now().Add(time.Hour),
		RenewAt:     renewAt,
	})
	return entry
}

func startStream(t *testing.T, s *CertDXServer) (*fakeSecretsStream, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &fakeSecretsStream{
		ctx:  ctx,
		recv: make(chan *discoveryv3.DiscoveryRequest),
		sent: make(chan *discoveryv3.DiscoveryResponse, 4),
	}
	done := make(chan error, 1)
	go func() { done <- (&MySDS{cdxsrv: s}).StreamSecrets(stream) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return stream, done
}

func subscribeRequest(t *testing.T, packs map[string][]string) *discoveryv3.DiscoveryRequest {
	t.Helper()
	sets := map[string]any{}
	var names []string
	for name, domains := range packs {
		items := make([]any, len(domains))
		for i, d := range domains {
			items[i] = d
		}
		sets[name] = items
		names = append(names, name)
	}
	md, err := structpb.NewStruct(map[string]any{domainKey: sets})
	if err != nil {
		t.Fatal(err)
	}
	return &discoveryv3.DiscoveryRequest{TypeUrl: typeUrl, ResourceNames: names, Node: &corev3.Node{Metadata: md}}
}

func recvOffer(t *testing.T, stream *fakeSecretsStream) (name, version string) {
	t.Helper()
	select {
	case r := <-stream.sent:
		var secret tlsv3.Secret
		if err := r.Resources[0].UnmarshalTo(&secret); err != nil {
			t.Fatal(err)
		}
		return secret.Name, r.VersionInfo
	case <-time.After(2 * time.Second):
		t.Fatal("no offer")
		return "", ""
	}
}

func expectNoOffer(t *testing.T, stream *fakeSecretsStream, done chan error) {
	t.Helper()
	select {
	case r := <-stream.sent:
		t.Fatalf("unexpected offer, version %q", r.VersionInfo)
	case err := <-done:
		t.Fatalf("stream ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestStreamSecretsOnlyLogsResponses(t *testing.T) {
	s := newSDSTestServer(t)
	withCert(t, s, []string{"example.com"}, time.Now())
	stream, done := startStream(t, s)

	stream.recv <- subscribeRequest(t, map[string][]string{"pack": {"example.com"}})
	_, version := recvOffer(t, stream)

	for _, req := range []*discoveryv3.DiscoveryRequest{
		{TypeUrl: typeUrl, ResourceNames: []string{"pack"}, VersionInfo: version},
		{TypeUrl: typeUrl, ResourceNames: []string{"pack"}, VersionInfo: "other"},
		{TypeUrl: typeUrl, ResourceNames: []string{"pack"}, VersionInfo: version,
			ErrorDetail: &rpcstatus.Status{Code: 13, Message: "bad cert"}},
	} {
		stream.recv <- req
	}
	expectNoOffer(t, stream, done)
}

func TestStreamSecretsPushesRenewalWithoutAck(t *testing.T) {
	s := newSDSTestServer(t)
	entry := withCert(t, s, []string{"example.com"}, time.Now())
	stream, _ := startStream(t, s)

	stream.recv <- subscribeRequest(t, map[string][]string{"pack": {"example.com"}})
	_, first := recvOffer(t, stream)

	publishCert(entry, CertT{
		FullChain:   []byte("PEM-chain-2"),
		Key:         []byte("PEM-key-2"),
		ValidBefore: time.Now().Add(2 * time.Hour),
		RenewAt:     time.Now().Add(time.Minute),
	})
	if _, second := recvOffer(t, stream); second == first {
		t.Fatalf("renewal not offered, still at version %q", second)
	}
}

func TestStreamSecretsPendingPackDoesNotBlockOthers(t *testing.T) {
	s := newSDSTestServer(t)
	withCert(t, s, []string{"b.example.com"}, time.Now())
	stream, _ := startStream(t, s)

	stream.recv <- subscribeRequest(t, map[string][]string{
		"a": {"a.example.com"},
		"b": {"b.example.com"},
	})
	if name, _ := recvOffer(t, stream); name != "b" {
		t.Fatalf("first offer for %q, want b", name)
	}

	withCert(t, s, []string{"a.example.com"}, time.Now())
	if name, _ := recvOffer(t, stream); name != "a" {
		t.Fatalf("second offer for %q, want a", name)
	}
}

func TestStreamSecretsRejectsDisallowedDomains(t *testing.T) {
	s := newSDSTestServer(t)
	stream, done := startStream(t, s)

	stream.recv <- subscribeRequest(t, map[string][]string{"pack": {"evil.com"}})
	select {
	case err := <-done:
		if !errors.Is(err, domain.ErrNotAllowed) {
			t.Fatalf("err = %v, want ErrNotAllowed", err)
		}
		done <- err
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end")
	}
}
