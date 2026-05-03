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
	kill   chan struct{}
}

func (sds *MySDS) StreamSecrets(server secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := server.Context()
	peerInfo, _ := peer.FromContext(ctx)
	peer := "unknown"
	if peerInfo != nil && peerInfo.Addr != nil {
		peer = peerInfo.Addr.String()
	}

	logging.Info("New gRPC connection from: %s", peer)

	dispatch := map[string]chan *discoveryv3.DiscoveryRequest{}
	errChan := make(chan error, 1)

	resp := make(chan *discoveryv3.DiscoveryResponse)
	sendErr := func(err error) {
		select {
		case errChan <- err:
		case <-ctx.Done():
		}
	}
	go func() {
		// goroutine for sending
		for {
			select {
			case r := <-resp:
				if err := server.Send(r); err != nil {
					// a failed in sending should make the context fail as well.
					sendErr(fmt.Errorf("failed sending message: %w", err))
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
				sendErr(fmt.Errorf("failed receiving request from %s: %w", peer, err))
				return
			}

			if req.TypeUrl != typeUrl {
				sendErr(fmt.Errorf("unexpected resource type: expect `%s` but requested `%s`", typeUrl, req.TypeUrl))
				return
			}

			if domainSets == nil {
				if req.Node == nil || req.Node.Metadata == nil {
					sendErr(fmt.Errorf("bad metadata, no node metadata"))
					return
				}
				if _domainSets, exist := req.Node.Metadata.Fields[domainKey]; exist {
					if _domainSets, ok := _domainSets.AsInterface().(map[string]interface{}); ok {
						domainSets = _domainSets
					} else {
						sendErr(fmt.Errorf("bad metadata, domains should be a map"))
						return
					}
				} else {
					sendErr(fmt.Errorf("bad metadata, no domains key in metadata"))
					return
				}
			}

			packRequests := map[string][]string{}
			for _, name := range req.ResourceNames {
				// this is an ack
				if reqChan, ok := dispatch[name]; ok {
					select {
					case reqChan <- req:
					case <-ctx.Done():
					}
					continue
				}

				if pack, exist := domainSets[name]; exist {
					var domains []string
					if v, ok := pack.([]any); ok {
						for _, v := range v {
							if v, ok := v.(string); ok {
								domains = append(domains, v)
							} else {
								sendErr(fmt.Errorf("bad metadata, domain should be string"))
								return
							}
						}
					} else {
						sendErr(fmt.Errorf("bad metadata, domain pack should be an array"))
						return
					}
					if !domain.AllAllowed(sds.cdxsrv.Config.ACME.AllowedDomains, domains) {
						sendErr(fmt.Errorf("domains %v: %w", domains, domain.ErrNotAllowed))
						return
					}
					packRequests[name] = domains
				} else {
					sendErr(fmt.Errorf("bad metadata, missing domain names for pack %s", name))
					return
				}
			}

			for name, domains := range packRequests {
				logging.Info("Handling pack %s with domains %v in response to %s", name, domains, peer)

				entry := sds.cdxsrv.certCache.get(domains)

				reqChan := make(chan *discoveryv3.DiscoveryRequest)
				dispatch[name] = reqChan
				go sds.handleCert(ctx, name, entry, reqChan, resp, peer)
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
	case <-sds.kill:
		logging.Debug("Stream end due to explicit kill.")
		err = fmt.Errorf("server closed")
	}

	logging.Info("gRPC connection from %s closed", peer)
	return err
}

func (sds *MySDS) handleCert(ctx context.Context, name string, entry *certEntry,
	req chan *discoveryv3.DiscoveryRequest, resp chan *discoveryv3.DiscoveryResponse, peer string) {

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
			logging.Error("Failed to construct SDS response: %s", err)
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

// SDSSrv runs the gRPC SDS endpoint until Stop is called.
func (s *CertDXServer) SDSSrv() error {
	logging.Info("Start listening GRPC at %s", s.Config.GRPCSDSServer.Listen)

	mtlsConfig, err := getMtlsConfig()
	if err != nil {
		return err
	}

	server := grpc.NewServer(
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

	sds := &MySDS{
		cdxsrv: s,
		kill:   make(chan struct{}),
	}
	secretv3.RegisterSecretDiscoveryServiceServer(server, sds)

	l, err := net.Listen("tcp", s.Config.GRPCSDSServer.Listen)
	if err != nil {
		return fmt.Errorf("listen at %s: %w", s.Config.GRPCSDSServer.Listen, err)
	}

	errChan := make(chan error, 1)
	go func() {
		logging.Info("SDS server started")
		if err := server.Serve(l); err != nil {
			errChan <- err
			return
		}
		errChan <- nil
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve SDS: %w", err)
		}
	case <-s.rootCtx.Done():
		close(sds.kill)
		server.GracefulStop()
	}
	logging.Info("SDS Stopped")
	return nil
}
