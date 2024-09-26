package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
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
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/utils"
)

const typeUrl = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
const domainKey = "domains"

type MySDS struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
	kill chan struct{}
}

func (sds *MySDS) StreamSecrets(server secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := server.Context()
	peerInfo, _ := peer.FromContext(ctx)
	peer := peerInfo.Addr.String()

	logging.Info("New gRPC connection from: %s", peer)

	dispatch := map[string]chan *discoveryv3.DiscoveryRequest{}
	errChan := make(chan error)

	resp := make(chan *discoveryv3.DiscoveryResponse)
	go func() {
		// goroutine for sending
		for {
			select {
			case r := <-resp:
				if err := server.Send(r); err != nil {
					// a failed in sending should make the context fail as well.
					errChan <- fmt.Errorf("failed sending message: %w", err)
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
				errChan <- fmt.Errorf("failed receiving request from %s: %w", peer, err)
				return
			}

			if req.TypeUrl != typeUrl {
				errChan <- fmt.Errorf("unexpected resource type: expect `%s` but requested `%s`", typeUrl, req.TypeUrl)
			}

			if domainSets == nil {
				if _domainSets, exist := req.Node.Metadata.Fields[domainKey]; exist {
					if _domainSets, ok := _domainSets.AsInterface().(map[string]interface{}); ok {
						domainSets = _domainSets
					} else {
						errChan <- fmt.Errorf("bad metadata, domains should be a map")
						return
					}
				} else {
					errChan <- fmt.Errorf("bad metadata, no domains key in metadata")
					return
				}
			}

			packRequests := map[string][]string{}
			for _, name := range req.ResourceNames {
				// this is an ack
				if reqChan, ok := dispatch[name]; ok {
					reqChan <- req
					continue
				}

				if pack, exist := domainSets[name]; exist {
					var domains []string
					if v, ok := pack.([]any); ok {
						for _, v := range v {
							if v, ok := v.(string); ok {
								domains = append(domains, v)
							} else {
								errChan <- fmt.Errorf("bad metadata, domain should be string")
								return
							}
						}
					} else {
						errChan <- fmt.Errorf("bad metadata, domain pack should be an array")
						return
					}
					if !domainsAllowed(domains) {
						errChan <- fmt.Errorf("domains %v not allowed", domains)
						return
					}
					packRequests[name] = domains
				} else {
					errChan <- fmt.Errorf("bad metadata, missing domain names for pack %s", name)
					return
				}
			}

			for name, domains := range packRequests {
				logging.Info("Handling pack %s with domains %v in response to %s", name, domains, peer)

				entry := serverCertCache.GetEntry(domains)

				reqChan := make(chan *discoveryv3.DiscoveryRequest)
				dispatch[name] = reqChan
				go sds.handleCert(ctx, name, entry, reqChan, resp, peer)
			}
		}
	}()

	select {
	case <-ctx.Done():
		logging.Debug("Stream end due to ctx Done: %s", ctx.Err())
		return ctx.Err()
	case err := <-errChan:
		logging.Error("Stream end due to errored: %s", err)
		return err
	case <-sds.kill:
		logging.Debug("Stream end due to explicit kill.")
		return fmt.Errorf("server closed")
	}
}

func (sds *MySDS) handleCert(ctx context.Context, name string, entry *ServerCertCacheEntry,
	req chan *discoveryv3.DiscoveryRequest, resp chan *discoveryv3.DiscoveryResponse, peer string) {

	cert_ := entry.Cert()

	entry.Subscribe()
	defer entry.Release()

	if !cert_.IsValid() {
		<-*entry.Updated.Load()
	}

	for {
		cert := entry.Cert()

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
			logging.Panic("Unexpected error constructing response, err: %s", err)
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
		}

		select {
		case <-ctx.Done():
			logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
			return
		case <-*entry.Updated.Load():
			// continue
		}
	}
}

func getTLSConfig() *tls.Config {
	srvCertPath, srvKeyPath, err := utils.GetSDSServerCertPath()
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	cert, err := tls.LoadX509KeyPair(srvCertPath, srvKeyPath)
	if err != nil {
		logging.Fatal("Invalid sds server cert, err: %s", err)
	}

	caPEMPath, _, err := utils.GetSDSCAPath()
	if err != nil {
		logging.Fatal("%s", err)
	}
	caPEM, err := os.ReadFile(caPEMPath)
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(caPEM) {
		logging.Fatal("Invalid ca cert")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
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

func SDSSrv(stop chan struct{}) {
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(getTLSConfig())),
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
		kill: make(chan struct{}),
	}
	secretv3.RegisterSecretDiscoveryServiceServer(server, sds)

	go func() {
		l, err := net.Listen("tcp", Config.GRPCSDSServer.Listen)
		if err != nil {
			logging.Fatal("Failed to listen at %s, err: %s", Config.GRPCSDSServer.Listen, err)
		}
		logging.Info("SDS server started")
		if err := server.Serve(l); err != nil {
			logging.Fatal("%s", err)
		}
	}()

	<-stop

	close(sds.kill)
	server.GracefulStop()
	logging.Info("SDS Stopped")
}
