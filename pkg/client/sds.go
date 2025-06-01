package client

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

const typeUrl = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
const domainKey = "domains"

type killed struct {
	Err string
}

type respData struct {
	Version string
	Secret  *tlsv3.Secret
}

func (e *killed) Error() string {
	return e.Err
}

type CertDXgRPCClient struct {
	tlsCred credentials.TransportCredentials
	server  *config.ClientGRPCServer
	certs   map[uint64]*watchingCert

	kill     chan struct{}
	Running  atomic.Bool
	Received atomic.Pointer[chan struct{}]
}

func MakeCertDXgRPCClient(server *config.ClientGRPCServer, certs map[uint64]*watchingCert) *CertDXgRPCClient {
	c := &CertDXgRPCClient{
		server: server,
		certs:  certs,
		kill:   make(chan struct{}),
	}
	received := make(chan struct{})
	c.Received.Store(&received)
	c.Running.Store(false)
	c.tlsCred = credentials.NewTLS(getMtlsConfig(server.CA, server.Certificate, server.Key))
	return c
}

func (c *CertDXgRPCClient) Stream() error {
	select {
	case <-c.kill:
		return &killed{Err: "stream killed"}
	default:
	}

	c.Running.Store(true)
	conn, err := grpc.NewClient(c.server.Server,
		grpc.WithTransportCredentials(c.tlsCred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 25 * time.Second,
		}),
	)

	if err != nil {
		return fmt.Errorf("new grpc client failed: %w", err)
	}
	defer func() {
		conn.Close()
		c.Running.Store(false)
	}()

	client := secretv3.NewSecretDiscoveryServiceClient(conn)
	stream, err := client.StreamSecrets(context.Background())
	if err != nil {
		return fmt.Errorf("stream secrets failed: %w", err)
	}
	ctx := stream.Context()

	dispatch := map[string]chan respData{}
	ack := make(chan *discoveryv3.DiscoveryRequest)
	errChan := make(chan error)

	for _, cert := range c.certs {
		dispatch[cert.Config.Name] = make(chan respData)
		go c.handleCert(ctx, cert, dispatch[cert.Config.Name], ack, errChan)
	}

	go func() {
		// goroutine for receiving
		for {
			select {
			case <-ctx.Done():
				logging.Debug("Receiving goroutine stopped due to ctx done: %s", ctx.Err())
				return
			default:
			}

			resp, err := stream.Recv()
			if err != nil {
				errChan <- fmt.Errorf("failed receiving request: %w", err)
				return
			}
			newReceived := make(chan struct{})
			close(*c.Received.Swap(&newReceived))

			secretResp := &tlsv3.Secret{}
			err = anypb.UnmarshalTo(resp.Resources[0], secretResp, proto.UnmarshalOptions{})
			if err != nil {
				errChan <- fmt.Errorf("can not unmarshal message from srv: %w", err)
				return
			}

			respChan, ok := dispatch[secretResp.Name]
			if !ok {
				errChan <- fmt.Errorf("unexcepted cert: %s", secretResp.Name)
				return
			}

			respChan <- respData{
				Version: resp.VersionInfo,
				Secret:  secretResp,
			}
		}
	}()

	go func() {
		// goroutine for sending
		domainSets := map[string]interface{}{}
		resourceNames := []string{}
		for _, cert := range c.certs {
			_domainSet := []interface{}{}
			for _, domain := range cert.Config.Domains {
				_domainSet = append(_domainSet, domain)
			}
			domainSets[cert.Config.Name] = _domainSet
			resourceNames = append(resourceNames, cert.Config.Name)
		}

		metaDataStruct, err := structpb.NewStruct(map[string]interface{}{
			domainKey: domainSets,
		})
		if err != nil {
			errChan <- fmt.Errorf("failed constructing meta data struct: %w", err)
			return
		}

		packReq := &discoveryv3.DiscoveryRequest{
			TypeUrl:       typeUrl,
			ResourceNames: resourceNames,
			Node: &corev3.Node{
				Metadata: metaDataStruct,
			},
		}

		err = stream.Send(packReq)
		if err != nil {
			errChan <- fmt.Errorf("failed sending request: %w", err)
			return
		}

		for {
			select {
			case a := <-ack:
				if err := stream.Send(a); err != nil {
					// a failed in sending should make the context fail as well.
					errChan <- fmt.Errorf("failed sending ack: %w", err)
					return
				}
			case <-ctx.Done():
				logging.Debug("Message sender stopped due to ctx done: %s", ctx.Err())
				return
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
	case <-c.kill:
		logging.Debug("Stream end due to explicit kill.")
		return &killed{Err: "stream killed"}
	}
}

func (c *CertDXgRPCClient) handleCert(ctx context.Context, cert *watchingCert,
	resp chan respData, ack chan *discoveryv3.DiscoveryRequest, errChan chan error) {

	for {
		select {
		case _respData := <-resp:
			respCert, ok := _respData.Secret.Type.(*tlsv3.Secret_TlsCertificate)
			if !ok {
				errChan <- fmt.Errorf("unexcepted resp type")
				return
			}

			cert.UpdateChan <- certData{
				Domains:   cert.Config.Domains,
				Fullchain: respCert.TlsCertificate.CertificateChain.GetInlineBytes(),
				Key:       respCert.TlsCertificate.PrivateKey.GetInlineBytes(),
			}

			ack <- &discoveryv3.DiscoveryRequest{
				TypeUrl:       typeUrl,
				VersionInfo:   _respData.Version,
				ResourceNames: []string{cert.Config.Name},
			}
		case <-ctx.Done():
			logging.Debug("handler stopped due to ctx done: %s", ctx.Err())
			return
		}
	}
}

func (c *CertDXgRPCClient) Kill() {
	if c.Running.Load() {
		close(c.kill)
		c.kill = make(chan struct{})
	}
}
