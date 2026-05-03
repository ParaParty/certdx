package server

import (
	"context"
	"errors"
	"fmt"
	"net"
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
				// this is an ack
				if reqChan, ok := dispatch[name]; ok {
					select {
					case reqChan <- req:
					case <-ctx.Done():
						return
					}
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

				entry := sds.cdxsrv.certCache.get(domains)

				reqChan := make(chan *discoveryv3.DiscoveryRequest)
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
func (sds *MySDS) handleCert(ctx context.Context, name string, entry *certEntry,
	req chan *discoveryv3.DiscoveryRequest, resp chan *discoveryv3.DiscoveryResponse,
	errChan chan<- error, peer string) {

	sds.cdxsrv.subscribe(entry)
	defer sds.cdxsrv.release(entry)

	cert, seen := entry.Snapshot()
	if !cert.IsValid() {
		seen = entry.WaitForUpdate(ctx, seen)
		if ctx.Err() != nil {
			return
		}
		cert, seen = entry.Snapshot()
	}

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

		select {
		case ack := <-req:
			if ack.VersionInfo == version {
				logging.Info("Cert pack %s version %s deployed at %s", name, version, peer)
			} else {
				err := ack.ErrorDetail
				logging.Warn("Cert version %s rejected by %s at %s: %d(%s)",
					version, name, peer,
					err.Code, err.Message)
			}
		case <-ctx.Done():
			logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
			return
		}

		seen = entry.WaitForUpdate(ctx, seen)
		if ctx.Err() != nil {
			logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
			return
		}
		cert, seen = entry.Snapshot()
	}
}

func clientTLSLog(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	if p, ok := peer.FromContext(ctx); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(mtls.State.PeerCertificates) > 1 {
				logging.Error("Client %s providing multiple client certificate.", p.Addr.String())
			}
			for _, item := range mtls.State.PeerCertificates {
				logging.Info("Client `%s` from %s.", item.Subject.CommonName, p.Addr.String())
			}
		}
	}
	return handler(ctx, req)
}

// SDSSrv runs the gRPC SDS endpoint until Stop is called. A goroutine
// watches the server's rootCtx and triggers grpcServer.Stop on shutdown,
// which closes every active stream — StreamSecrets goroutines then exit
// via their merged ctx without needing a kill channel.
func (s *CertDXServer) SDSSrv() error {
	logging.Info("Start listening GRPC at %s", s.Config.GRPCSDSServer.Listen)

	mtlsConfig, err := getMtlsConfig()
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(mtlsConfig)),
		grpc.UnaryInterceptor(clientTLSLog),
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
