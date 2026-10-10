package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestClientConfigValidateUnsupportedMode(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = "websocket"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on unsupported mode")
	}
	if !strings.Contains(err.Error(), "unsupported mode") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateInvalidReconnectInterval(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.ReconnectInterval = "not-a-duration"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	c.Http.MainServer.Url = "https://example.com"
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on invalid ReconnectInterval")
	}
	if !strings.Contains(err.Error(), "ReconnectInterval") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateEmptyCertificatesDefault(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Http.MainServer.Url = "https://example.com"
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on empty certificates list")
	}
	if !strings.Contains(err.Error(), "no certificate configured") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateEmptyCertificatesAccepted(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Http.MainServer.Url = "https://example.com"
	err := c.Validate([]ValidatingOption{WithAcceptEmptyCertificatesList(true)})
	if err != nil {
		t.Fatalf("expected empty certificates to be accepted with option: %v", err)
	}
}

func TestClientCertificateValidateCanonicalizesDomains(t *testing.T) {
	c := &ClientCertificate{Name: "x", Domains: []string{"WWW.Example.COM.", "example.com", "www.example.com"}}
	if err := c.Validate(&validatingConfiguration{acceptEmptyUpdateActions: true}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if want := []string{"example.com", "www.example.com"}; !slices.Equal(c.Domains, want) {
		t.Fatalf("domains: got %q want %q", c.Domains, want)
	}
}

func TestClientCertificateValidateRejectsNoDomains(t *testing.T) {
	for _, domains := range [][]string{nil, {"", "."}} {
		c := &ClientCertificate{Name: "x", Domains: domains}
		if err := c.Validate(&validatingConfiguration{acceptEmptyUpdateActions: true}); err == nil {
			t.Fatalf("domains %q: expected error", domains)
		}
	}
}

func TestClientConfigValidateHttpModeValid(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_HTTP
	c.Http.MainServer.Url = "https://example.com"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err != nil {
		t.Fatalf("expected valid http config: %v", err)
	}
}

func TestClientConfigValidateHttpModeMissingUrl(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_HTTP
	c.Http.MainServer.Url = ""
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on empty http main server url")
	}
	if !strings.Contains(err.Error(), "http main server url is empty") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateGrpcModeValid(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	if err := os.WriteFile(bundle, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_GRPC
	c.GRPC.MainServer.Server = "localhost:10002"
	c.GRPC.MainServer.PEM = bundle
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err != nil {
		t.Fatalf("expected valid grpc config: %v", err)
	}
}

func TestClientConfigValidateGrpcModeMissingServer(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_GRPC
	c.GRPC.MainServer.Server = ""
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on empty grpc main server")
	}
	if !strings.Contains(err.Error(), "grpc main server url is empty") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateGrpcModeMissingMtlsFiles(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_GRPC
	c.GRPC.MainServer.Server = "localhost:10002"
	c.GRPC.MainServer.PEM = "/nonexistent/client.pem"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on missing mtls files")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateHttpMtlsMissingFiles(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_HTTP
	c.Http.MainServer.Url = "https://example.com"
	c.Http.MainServer.AuthMethod = HTTP_AUTH_MTLS
	c.Http.MainServer.PEM = "/nonexistent/client.pem"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on missing mtls files for http")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateHttpTokenNoMtlsCheck(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_HTTP
	c.Http.MainServer.Url = "https://example.com"
	c.Http.MainServer.AuthMethod = HTTP_AUTH_TOKEN
	c.Http.MainServer.Token = "secret"
	c.Certificates = []ClientCertificate{
		{Name: "x", Domains: []string{"example.com"}, Actions: []UpdateActionConfig{&FileAction{SavePath: "/tmp"}}},
	}
	err := c.Validate(nil)
	if err != nil {
		t.Fatalf("token auth should not require mtls files: %v", err)
	}
}

func TestClientHttpServerValidateAuthMethod(t *testing.T) {
	for _, method := range []string{"", "mTLS", "none"} {
		s := &ClientHttpServer{Url: "https://example.com", AuthMethod: method}
		if err := s.Validate(); err == nil {
			t.Fatalf("authMethod %q: expected error", method)
		}
	}
}

func TestClientConfigSetDefault(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()

	if c.Common.Mode != CLIENT_MODE_HTTP {
		t.Errorf("default mode: got %s want %s", c.Common.Mode, CLIENT_MODE_HTTP)
	}
	if c.Common.RetryCount != 5 {
		t.Errorf("default retryCount: got %d want 5", c.Common.RetryCount)
	}
	if c.Common.ReconnectInterval != "10m" {
		t.Errorf("default reconnectInterval: got %s want 10m", c.Common.ReconnectInterval)
	}
	if c.Http.MainServer.AuthMethod != HTTP_AUTH_TOKEN {
		t.Errorf("default http main authMethod: got %s want %s", c.Http.MainServer.AuthMethod, HTTP_AUTH_TOKEN)
	}
	if c.Http.StandbyServer.AuthMethod != HTTP_AUTH_TOKEN {
		t.Errorf("default http standby authMethod: got %s want %s", c.Http.StandbyServer.AuthMethod, HTTP_AUTH_TOKEN)
	}
}

func TestClientConfigValidateMultipleErrors(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.ReconnectInterval = "bad"
	c.Common.Mode = "unknown"
	// No certificates → error too.

	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected multiple errors")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ReconnectInterval") {
		t.Errorf("missing ReconnectInterval error in: %s", msg)
	}
	if !strings.Contains(msg, "unsupported mode") {
		t.Errorf("missing unsupported mode error in: %s", msg)
	}
	if !strings.Contains(msg, "no certificate configured") {
		t.Errorf("missing no certificate configured error in: %s", msg)
	}
}
