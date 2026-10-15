package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

func onceTestCert(t *testing.T) (chain, key []byte) {
	t.Helper()
	chain, key, err := acme.NewMockACME(time.Hour).Obtain(context.Background(), []string{"example.com"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return chain, key
}

func TestRunOnceWritesFileAndExits(t *testing.T) {
	chain, key := onceTestCert(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: chain, Key: key})
	}))
	defer server.Close()

	dir := t.TempDir()
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: dir}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for name, want := range map[string][]byte{"web.pem": chain, "web.key": key} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestRunOnceWaitsForOtherCertificatesAfterActionFailure(t *testing.T) {
	chain, key := onceTestCert(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: chain, Key: key})
	}))
	defer server.Close()

	dir := t.TempDir()
	badPath := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(badPath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = []config.ClientCertificate{
		{Name: "bad", Domains: []string{"bad.example.com"}, Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: badPath}}},
		{Name: "good", Domains: []string{"good.example.com"}, Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: dir}}},
	}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	err := daemon.RunOnce()
	if err == nil || !strings.Contains(err.Error(), "certificate bad: update action file") {
		t.Fatalf("RunOnce error = %v, want bad certificate action failure", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "good.pem")); err != nil {
		t.Fatalf("good certificate was not written: %v", err)
	}
}

func TestRunOnceReportsFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{Err: "certificate denied"})
	}))
	defer server.Close()

	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "certificate denied") {
		t.Fatalf("RunOnce error = %v, want server error", err)
	}
}

func TestRunOnceReportsInvalidCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: []byte("invalid"), Key: []byte("invalid")})
	}))
	defer server.Close()

	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "invalid certificate or key") {
		t.Fatalf("RunOnce error = %v, want invalid certificate", err)
	}
}

func TestRunOnceReportsAllHTTPServersFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "all HTTP servers failed") {
		t.Fatalf("RunOnce error = %v, want HTTP server failure", err)
	}
}

func TestRunOnceUsesHTTPStandby(t *testing.T) {
	chain, key := onceTestCert(t)
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer main.Close()
	standby := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: chain, Key: key})
	}))
	defer standby.Close()

	dir := t.TempDir()
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 1
	daemon.Config.Http.MainServer.Url = main.URL
	daemon.Config.Http.StandbyServer.Url = standby.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: dir}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err != nil {
		t.Fatalf("RunOnce with standby: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "web.pem"))
	if err != nil || !bytes.Equal(got, chain) {
		t.Fatalf("standby certificate = %q, %v", got, err)
	}
}

func TestRunOnceReportsHTTPClientInitFailure(t *testing.T) {
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Http.MainServer.Url = "https://example.com"
	daemon.Config.Http.MainServer.AuthMethod = config.HTTP_AUTH_MTLS
	daemon.Config.Http.MainServer.PEM = "/nonexistent/client.pem"
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "http main server") {
		t.Fatalf("RunOnce error = %v, want HTTP client init failure", err)
	}
}
