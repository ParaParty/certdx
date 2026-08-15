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
// or "unknown" if no peer info is available. The Envoy side is meant to
// always populate it; the nil guards exist to avoid a panic from a
// malformed first frame.
func peerAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.Addr == nil {
		return "unknown"
	}
	return p.Addr.String()
}

// sendStreamErr publishes err on errChan but bails out if ctx fires
// first, so a goroutine that wants to report a failure can never block
// the stream's teardown when the consumer of errChan has already
// stopped reading.
func sendStreamErr(ctx context.Context, errChan chan<- error, err error) {
	select {
	case errChan <- err:
	case <-ctx.Done():
	}
}

// recoverStream turns a panic in a per-stream goroutine into a stream
// error. These goroutines are plain `go func()`s, so an unrecovered panic
// on one malformed frame would take the whole server process down instead
// of just the offending connection.
func recoverStream(ctx context.Context, errChan chan<- error, what, peer string) {
	if r := recover(); r != nil {
		logging.Error("Panic while %s for %s: %v\n%s", what, peer, r, debug.Stack())
		sendStreamErr(ctx, errChan, fmt.Errorf("panic while %s for %s: %v", what, peer, r))
	}
}

// dispatchRequest hands req to a pack handler without ever blocking the
// receive loop. The handler spends most of its life parked waiting for the
// next renewal, so a blocking send here would wedge the receive loop and
// with it every other cert pack sharing the stream. reqChan buffers a
// single request; one that is still queued has been superseded by the
// newer request, so it is dropped in its favor.
func dispatchRequest(reqChan chan *discoveryv3.DiscoveryRequest, req *discoveryv3.DiscoveryRequest) {
	for {
		select {
		case reqChan <- req:
			return
		default:
		}

		select {
		case <-reqChan:
		default:
			// The handler drained it first, retry the send.
		}
	}
}

func (sds *MySDS) StreamSecrets(server secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	// Merge the stream's ctx with the server's rootCtx so a server-wide
	// shutdown also tears the stream down deterministically without
	// needing a separate kill channel.
	streamCtx, cancel := context.WithCancel(server.Context())
	defer cancel()
	go func() {
		select {
		case <-sds.cdxsrv.rootCtx.Done():
			cancel()
		case <-streamCtx.Done():
		}
	}()

	ctx := streamCtx
	peer := peerAddr(ctx)
	logging.Info("New gRPC connection from: %s", peer)

	dispatch := map[string]chan *discoveryv3.DiscoveryRequest{}
	// Buffered so a goroutine that reports a failure right at teardown
	// doesn't block the receive path.
	errChan := make(chan error, 1)

	resp := make(chan *discoveryv3.DiscoveryResponse)
	go func() {
		// goroutine for sending
		for {
			select {
			case r := <-resp:
				if err := server.Send(r); err != nil {
					// a failed in sending should make the context fail as well.
					sendStreamErr(ctx, errChan, fmt.Errorf("failed sending message: %w", err))
					return
				}
			case <-ctx.Done():
				logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
				return
			}
		}
	}()

	var domainSets map[string]interface{}

	go func() {
		// goroutine for receiving
		defer recoverStream(ctx, errChan, "receiving requests", peer)
		for {
			select {
			case <-ctx.Done():
				logging.Debug("Message dispatcher stopped due to ctx done: %s", ctx.Err())
				return
			default:
			}

			req, err := server.Recv()
			if err != nil {
				sendStreamErr(ctx, errChan, fmt.Errorf("failed receiving request from %s: %w", peer, err))
				return
			}

			if req.TypeUrl != typeUrl {
				sendStreamErr(ctx, errChan, fmt.Errorf("unexpected resource type: expect %q but requested %q", typeUrl, req.TypeUrl))
				return
			}

			if domainSets == nil {
				if req.Node == nil || req.Node.Metadata == nil {
					sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: missing node metadata"))
					return
				}
				_domainSets, exist := req.Node.Metadata.Fields[domainKey]
				if !exist {
					sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: no %q key", domainKey))
					return
				}
				m, ok := _domainSets.AsInterface().(map[string]interface{})
				if !ok {
					sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: domains should be a map"))
					return
				}
				domainSets = m
			}

			packRequests := map[string][]string{}
			for _, name := range req.ResourceNames {
				// The pack is already served on this stream: this is an
				// ack, a nack or a re-subscription. handleCert tells them
				// apart, all we do here is hand the frame over.
				if reqChan, ok := dispatch[name]; ok {
					dispatchRequest(reqChan, req)
					continue
				}

				pack, exist := domainSets[name]
				if !exist {
					sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: missing domain names for pack %s", name))
					return
				}

				items, ok := pack.([]any)
				if !ok {
					sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: domain pack should be an array"))
					return
				}
				var domains []string
				for _, v := range items {
					vs, ok := v.(string)
					if !ok {
						sendStreamErr(ctx, errChan, fmt.Errorf("bad metadata: domain should be string"))
						return
					}
					domains = append(domains, vs)
				}
				if !domain.AllAllowed(sds.cdxsrv.Config.ACME.AllowedDomains, domains) {
					sendStreamErr(ctx, errChan, fmt.Errorf("domains %v: %w", domains, domain.ErrNotAllowed))
					return
				}
				packRequests[name] = domains
			}

			for name, domains := range packRequests {
				logging.Info("Handling pack %s with domains %v in response to %s", name, domains, peer)

				entry, err := sds.cdxsrv.certCache.get(domains)
				if err != nil {
					sendStreamErr(ctx, errChan, fmt.Errorf("cert pack %s: %w", name, err))
					return
				}

				reqChan := make(chan *discoveryv3.DiscoveryRequest, 1)
				dispatch[name] = reqChan
				go sds.handleCert(ctx, name, entry, reqChan, resp, errChan, peer)
			}
		}
	}()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
		logging.Debug("Stream end due to ctx Done: %s", err)
	case err = <-errChan:
		logging.Error("Stream end due to errored: %s", err)
	}

	logging.Info("gRPC connection from %s closed", peer)
	return err
}

// handleCert serves one cert pack on a single SDS stream. On any failure
// (response marshal, send timeout) it propagates the error via errChan
// so StreamSecrets returns from its outer select and gRPC closes the
// connection — the previous "log and return from this goroutine"
// behavior left the stream alive serving a stale or absent cert pack.
//
// Renewals and client frames are awaited in the same select: a client that
// acks late (or never) must not delay the next cert, and a pack parked on a
// renewal must not stall the stream's receive loop.
func (sds *MySDS) handleCert(ctx context.Context, name string, entry *certEntry,
	req chan *discoveryv3.DiscoveryRequest, resp chan *discoveryv3.DiscoveryResponse,
	errChan chan<- error, peer string) {

	defer recoverStream(ctx, errChan, fmt.Sprintf("serving cert pack %s", name), peer)

	// Sub-context so the update watcher started below always winds down with
	// this handler, including on an early error return. The deferred recover
	// above captured the parent ctx, so it can still report a panic.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sds.cdxsrv.subscribe(entry)
	defer sds.cdxsrv.release(entry)

	cert, seen := entry.Snapshot()

	// Turn WaitForUpdate into a channel so renewals can be selected on
	// alongside inbound frames. Buffered by one: a renewal that lands while
	// the handler is busy is picked up on the next wait, because
	// WaitForUpdate returns immediately once the version has moved past
	// the last one this goroutine observed.
	updates := make(chan struct{}, 1)
	go func() {
		for {
			seen = entry.WaitForUpdate(ctx, seen)
			if ctx.Err() != nil {
				return
			}
			select {
			case updates <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}()

	for !cert.IsValid() {
		select {
		case <-updates:
		case <-req:
			// Nothing to offer yet, keep the frame from wedging the stream.
			continue
		case <-ctx.Done():
			return
		}
		cert, _ = entry.Snapshot()
	}

	// reoffered bounds re-offers to one per cert version: on a stream
	// carrying several packs the client acks with a single version that can
	// match only one of them, so an unconditional re-offer would ping-pong
	// between the packs forever. It is cleared whenever a renewal gives the
	// pack something new to say.
	reoffered := false

	for {
		secret, err := anypb.New(&tlsv3.Secret{
			Name: name,
			Type: &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: cert.FullChain,
						},
					},
					PrivateKey: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: cert.Key,
						},
					},
				},
			},
		})
		if err != nil {
			sendStreamErr(ctx, errChan, fmt.Errorf("construct SDS response for %v: %w", entry.domains, err))
			return
		}

		version := cert.RenewAt.Format(time.RFC3339)

		select {
		case resp <- &discoveryv3.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     typeUrl,
			Resources:   []*anypb.Any{secret},
		}:
		case <-ctx.Done():
			logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
			return
		}

		logging.Info("Offered cert %v version %s to %s", entry.domains, version, peer)

	awaitOffer:
		for {
			select {
			case r := <-req:
				switch {
				case r.GetErrorDetail() != nil:
					// NACK. Nothing better to send until the next renewal.
					detail := r.GetErrorDetail()
					logging.Warn("Cert pack %s version %s rejected by %s: %d(%s)",
						name, version, peer, detail.GetCode(), detail.GetMessage())
				case r.VersionInfo == version:
					logging.Info("Cert pack %s version %s deployed at %s", name, version, peer)
				case !reoffered:
					// A frame naming this pack with some other version and
					// no error detail: a re-subscription, or an ack for an
					// offer this pack has already moved past. Re-offer the
					// current cert once so a genuine re-subscription is
					// served.
					reoffered = true
					logging.Info("Re-offering cert pack %s to %s, client reported version %q", name, peer, r.VersionInfo)
					break awaitOffer
				default:
					logging.Debug("Cert pack %s: version %q from %s is stale, current is %s", name, r.VersionInfo, peer, version)
				}
			case <-updates:
				cert, _ = entry.Snapshot()
				reoffered = false
				break awaitOffer
			case <-ctx.Done():
				logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
				return
			}
		}
	}
}

// logClientTLS audits the client certificate(s) presented by the peer of
// ctx. Shared by the unary and stream interceptors: StreamSecrets is a
// streaming RPC, so a unary-only interceptor never sees the SDS clients
// this log exists for.
func logClientTLS(ctx context.Context) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return
	}
	mtls, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return
	}
	addr := peerAddr(ctx)
	if len(mtls.State.PeerCertificates) > 1 {
		logging.Error("Client %s providing multiple client certificate.", addr)
	}
	for _, item := range mtls.State.PeerCertificates {
		logging.Info("Client `%s` from %s.", item.Subject.CommonName, addr)
	}
}

func clientTLSLog(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	logClientTLS(ctx)
	return handler(ctx, req)
}

func clientTLSLogStream(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logClientTLS(ss.Context())
	return handler(srv, ss)
}

// SDSSrv runs the gRPC SDS endpoint until Stop is called. A goroutine
// watches the server's rootCtx and triggers grpcServer.Stop on shutdown,
// which closes every active stream — StreamSecrets goroutines then exit
// via their merged ctx without needing a kill channel.
func (s *CertDXServer) SDSSrv() error {
	logging.Info("Start listening GRPC at %s", s.Config.GRPCSDSServer.Listen)

	mtlsConfig, err := mtls.LoadServer(s.Config.MTLS.PEM)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(mtlsConfig)),
		grpc.UnaryInterceptor(clientTLSLog),
		grpc.StreamInterceptor(clientTLSLogStream),
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
