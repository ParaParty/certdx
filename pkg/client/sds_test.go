package client

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
)

// TestStreamRejectsDuplicateCertNames pins the dispatch-starvation
// guard: two cert packs sharing a Name would collide in the dispatch
// map and in the Node.Metadata domain sets, so Stream must refuse
// before anything reaches the wire.
func TestStreamRejectsDuplicateCertNames(t *testing.T) {
	certs := map[domain.Key]*watchingCert{}
	for _, domains := range [][]string{{"a.example.com"}, {"b.example.com"}} {
		certs[domain.AsKey(domains)] = &watchingCert{
			Config:     config.ClientCertification{Name: "dup", Domains: domains},
			UpdateChan: make(chan certData, 1),
		}
	}

	c := MakeCertDXgRPCClient(&config.ClientGRPCServer{Server: "127.0.0.1:1"}, certs)
	err := c.Stream(context.Background())
	if err == nil {
		t.Fatal("expected error for duplicate cert names")
	}
	if !strings.Contains(err.Error(), "duplicate certificate name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStreamMTLSFailureIsNotFatal pins the os.Exit fix on the gRPC
// side: an unreadable bundle surfaces as a stream error the failover
// state machine can retry.
func TestStreamMTLSFailureIsNotFatal(t *testing.T) {
	c := MakeCertDXgRPCClient(&config.ClientGRPCServer{
		Server:           "127.0.0.1:1",
		ClientMtlsConfig: config.ClientMtlsConfig{PEM: filepath.Join(t.TempDir(), "does-not-exist.pem")},
	}, map[domain.Key]*watchingCert{})

	err := c.Stream(context.Background())
	if err == nil {
		t.Fatal("expected error for unreadable mtls bundle")
	}
	if !strings.Contains(err.Error(), "load mtls bundle") {
		t.Fatalf("unexpected error: %v", err)
	}
}
