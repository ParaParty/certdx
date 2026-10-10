package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/anypb"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/mtls"
)

const typeUrl = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
const domainKey = "domains"

type MySDS struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
	cdxsrv *CertDXServer
}

// peerAddr returns a printable peer address from the stream's context,
// or "unknown" if no peer info is available.
func peerAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.Addr == nil {
		return "unknown"
	}
	return p.Addr.String()
}

// sdsPack is one cert pack served on a stream.
type sdsPack struct {
	name  string
	entry *certEntry

	offered     bool
	sentSeq     uint64 // entry version of the last offer
	sentVersion string // VersionInfo of the last offer
}

// sdsStream holds the state of one StreamSecrets call. Only the event loop in
// StreamSecrets touches it, so it needs no locking.
type sdsStream struct {
	sds    *MySDS
	stream secretv3.SecretDiscoveryService_StreamSecretsServer
	ctx    context.Context
	peer   string

	domainSets map[string]any
	packs      map[string]*sdsPack
	updates    chan *sdsPack
}

// StreamSecrets serves one SDS stream. A receive goroutine and one watcher
// goroutine per pack feed a single loop, which is the only caller of Send.
// Packs are offered when first requested and on every renewal; ACKs and NACKs
// are only logged, never answered with a re-send.
func (sds *MySDS) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) (err error) {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	defer context.AfterFunc(sds.cdxsrv.rootCtx, cancel)()

	s := &sdsStream{
		sds:     sds,
		stream:  stream,
		ctx:     ctx,
		peer:    peerAddr(ctx),
		packs:   map[string]*sdsPack{},
		updates: make(chan *sdsPack),
	}
	logging.Info("New gRPC connection from: %s", s.peer)
	defer func() {
		if r := recover(); r != nil {
			logging.Error("Panic in SDS stream from %s: %v\n%s", s.peer, r, debug.Stack())
			err = fmt.Errorf("internal error serving %s", s.peer)
		}
		for _, p := range s.packs {
			sds.cdxsrv.release(p.entry)
		}
		logging.Info("gRPC connection from %s closed: %v", s.peer, err)
	}()

	reqs := make(chan *discoveryv3.DiscoveryRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case reqs <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return fmt.Errorf("receive from %s: %w", s.peer, err)
		case req := <-reqs:
			if err := s.handleRequest(req); err != nil {
				return err
			}
		case p := <-s.updates:
			if err := s.offer(p); err != nil {
				return err
			}
		}
	}
}

func (s *sdsStream) handleRequest(req *discoveryv3.DiscoveryRequest) error {
	if req.TypeUrl != typeUrl {
		return fmt.Errorf("unexpected resource type: expect %q but requested %q", typeUrl, req.TypeUrl)
	}

	for _, name := range req.ResourceNames {
		if p, ok := s.packs[name]; ok {
			s.logResponse(p, req)
			continue
		}

		domains, err := s.packDomains(req, name)
		if err != nil {
			return err
		}
		if !domain.AllAllowed(s.sds.cdxsrv.Config.ACME.AllowedDomains, domains) {
			return fmt.Errorf("domains %v: %w", domains, domain.ErrNotAllowed)
		}
		entry, err := s.sds.cdxsrv.certCache.get(domains)
		if err != nil {
			return fmt.Errorf("cert pack %s: %w", name, err)
		}

		logging.Info("Handling pack %s with domains %v for %s", name, entry.domains, s.peer)
		p := &sdsPack{name: name, entry: entry}
		s.packs[name] = p
		s.sds.cdxsrv.subscribe(entry)
		_, seen := entry.Snapshot()
		go s.watch(p, seen)

		if err := s.offer(p); err != nil {
			return err
		}
	}
	return nil
}

// logResponse reports a client's response to the last offer of p.
func (s *sdsStream) logResponse(p *sdsPack, req *discoveryv3.DiscoveryRequest) {
	switch detail := req.GetErrorDetail(); {
	case detail != nil:
		logging.Warn("Cert pack %s rejected by %s: %d(%s)", p.name, s.peer, detail.GetCode(), detail.GetMessage())
	case p.offered && req.VersionInfo == p.sentVersion:
		logging.Info("Cert pack %s version %s deployed at %s", p.name, p.sentVersion, s.peer)
	default:
		// Stream-level version for another pack, or a stale ack.
		logging.Debug("Cert pack %s: %s reports version %q, last offered %q", p.name, s.peer, req.VersionInfo, p.sentVersion)
	}
}

// packDomains reads the domain list of pack name from the node metadata,
// which the client sends with its first request.
func (s *sdsStream) packDomains(req *discoveryv3.DiscoveryRequest, name string) ([]string, error) {
	if s.domainSets == nil {
		fields := req.GetNode().GetMetadata().GetFields()
		raw, ok := fields[domainKey]
		if !ok {
			return nil, fmt.Errorf("bad metadata: no %q key", domainKey)
		}
		m, ok := raw.AsInterface().(map[string]any)
		if !ok {
			return nil, fmt.Errorf("bad metadata: domains should be a map")
		}
		s.domainSets = m
	}

	items, ok := s.domainSets[name].([]any)
	if !ok {
		return nil, fmt.Errorf("bad metadata: domains of pack %s should be an array", name)
	}
	domains := make([]string, 0, len(items))
	for _, v := range items {
		d, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("bad metadata: domain should be string")
		}
		domains = append(domains, d)
	}
	return domains, nil
}

// watch signals the event loop whenever p's entry moves past version seen.
func (s *sdsStream) watch(p *sdsPack, seen uint64) {
	for {
		seen = p.entry.WaitForUpdate(s.ctx, seen)
		if s.ctx.Err() != nil {
			return
		}
		select {
		case s.updates <- p:
		case <-s.ctx.Done():
			return
		}
	}
}

// offer sends p's current cert unless it has none yet or it was already sent.
func (s *sdsStream) offer(p *sdsPack) error {
	cert, seq := p.entry.Snapshot()
	if len(cert.FullChain) == 0 || len(cert.Key) == 0 {
		return nil
	}
	if p.offered && seq == p.sentSeq {
		return nil
	}

	secret, err := anypb.New(&tlsv3.Secret{
		Name: p.name,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{InlineBytes: cert.FullChain},
				},
				PrivateKey: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{InlineBytes: cert.Key},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("construct SDS response for %v: %w", p.entry.domains, err)
	}

	version := cert.RenewAt.Format(time.RFC3339)
	if err := s.stream.Send(&discoveryv3.DiscoveryResponse{
		VersionInfo: version,
		TypeUrl:     typeUrl,
		Resources:   []*anypb.Any{secret},
	}); err != nil {
		return fmt.Errorf("send to %s: %w", s.peer, err)
	}

	p.offered, p.sentSeq, p.sentVersion = true, seq, version
	logging.Info("Offered cert %v version %s to %s", p.entry.domains, version, s.peer)
	return nil
}

// clientTLSLog logs the client certificates presented on each stream.
func clientTLSLog(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if p, ok := peer.FromContext(ss.Context()); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			addr := peerAddr(ss.Context())
			if len(mtls.State.PeerCertificates) > 1 {
				logging.Error("Client %s providing multiple client certificate.", addr)
			}
			for _, item := range mtls.State.PeerCertificates {
				logging.Info("Client `%s` from %s.", item.Subject.CommonName, addr)
			}
		}
	}
	return handler(srv, ss)
}

// SDSSrv runs the gRPC SDS endpoint until Stop is called. A goroutine
// watches the server's rootCtx and triggers grpcServer.Stop on shutdown,
// which closes every active stream.
func (s *CertDXServer) SDSSrv() error {
	logging.Info("Start listening GRPC at %s", s.Config.GRPCSDSServer.Listen)

	mtlsConfig, err := mtls.LoadServer(s.Config.MTLS.PEM)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(mtlsConfig)),
		grpc.StreamInterceptor(clientTLSLog),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 25 * time.Second,
		}),
	)

	sds := &MySDS{cdxsrv: s}
	secretv3.RegisterSecretDiscoveryServiceServer(grpcServer, sds)

	listener, err := net.Listen("tcp", s.Config.GRPCSDSServer.Listen)
	if err != nil {
		return fmt.Errorf("listen at %s: %w", s.Config.GRPCSDSServer.Listen, err)
	}

	go func() {
		<-s.rootCtx.Done()
		grpcServer.Stop()
	}()

	logging.Info("SDS server started")
	defer logging.Info("SDS server stopped")
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve SDS: %w", err)
	}
	return nil
}
