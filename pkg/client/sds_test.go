package client

import (
	"context"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"pkg.para.party/certdx/pkg/config"
)

func TestHandleCertNilTlsCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cert := &watchingCert{
		Config:     config.ClientCertificate{Name: "x", Domains: []string{"example.com"}},
		UpdateChan: make(chan certData, 1),
	}
	resp := make(chan respData)
	ack := make(chan *discoveryv3.DiscoveryRequest, 1)
	errChan := make(chan error, 1)
	go (&CertDXgRPCClient{}).handleCert(ctx, cert, resp, ack, errChan)

	resp <- respData{Version: "v1", Secret: &tlsv3.Secret{Name: "x", Type: &tlsv3.Secret_TlsCertificate{}}}

	select {
	case got := <-cert.UpdateChan:
		t.Fatalf("empty response reached the watcher: %+v", got)
	case <-errChan:
	case <-time.After(2 * time.Second):
		t.Fatal("response was not handled")
	}
}
