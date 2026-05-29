package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientConfigValidateUnsupportedMode(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = "websocket"
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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

func TestClientConfigValidateEmptyCertificationsDefault(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Http.MainServer.Url = "https://example.com"
	err := c.Validate(nil)
	if err == nil {
		t.Fatal("expected error on empty certifications list")
	}
	if !strings.Contains(err.Error(), "no certification configured") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientConfigValidateEmptyCertificationsAccepted(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Http.MainServer.Url = "https://example.com"
	err := c.Validate([]ValidatingOption{WithAcceptEmptyCertificatesList(true)})
	if err != nil {
		t.Fatalf("expected empty certifications to be accepted with option: %v", err)
	}
}

func TestClientConfigValidateHttpModeValid(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	c.Common.Mode = CLIENT_MODE_HTTP
	c.Http.MainServer.Url = "https://example.com"
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
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
	c.Certifications = []ClientCertification{
		{Name: "x", SavePath: "/tmp", Domains: []string{"example.com"}},
	}
	err := c.Validate(nil)
	if err != nil {
		t.Fatalf("token auth should not require mtls files: %v", err)
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
	// No certifications → error too.

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
	if !strings.Contains(msg, "no certification configured") {
		t.Errorf("missing no certification configured error in: %s", msg)
	}
}
