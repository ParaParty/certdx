package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestRunOnceRejectsGRPC(t *testing.T) {
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.Mode = config.CLIENT_MODE_GRPC
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "not supported with grpc") {
		t.Fatalf("RunOnce error = %v, want grpc rejection", err)
	}
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

const onceTestActionType = "onceTest"

// onceTestAction serves as both the config and the action of a scripted update.
type onceTestAction struct {
	update func(ctx context.Context) error
}

func (a *onceTestAction) ActionType() string                    { return onceTestActionType }
func (a *onceTestAction) OneShot() bool                         { return true }
func (a *onceTestAction) Validate(_ *config.ClientConfig) error { return nil }
func (a *onceTestAction) Type() string                          { return onceTestActionType }
func (a *onceTestAction) Update(ctx context.Context, _, _ []byte, _ *config.ClientCertificate) error {
	return a.update(ctx)
}

func init() {
	RegisterUpdateAction(onceTestActionType, func(cfg config.UpdateActionConfig, _ *config.ClientConfig) (UpdateAction, error) {
		return cfg.(*onceTestAction), nil
	})
}

// onceTestDaemon returns an initialized daemon fetching a valid certificate.
func onceTestDaemon(t *testing.T, certs ...config.ClientCertificate) *CertDXClientDaemon {
	t.Helper()
	chain, key := onceTestCert(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: chain, Key: key})
	}))
	t.Cleanup(server.Close)
	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 0
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certificates = certs
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	return daemon
}

func onceTestCertificate(name string, updates ...func(context.Context) error) config.ClientCertificate {
	cert := config.ClientCertificate{Name: name, Domains: []string{name + ".example.com"}}
	for _, update := range updates {
		cert.Actions = append(cert.Actions, &onceTestAction{update: update})
	}
	return cert
}

func TestRunOnceDoesNotCancelOtherCertificatesAfterActionFailure(t *testing.T) {
	badFailed := make(chan struct{})
	var goodCtxErr error
	daemon := onceTestDaemon(t,
		onceTestCertificate("bad", func(context.Context) error {
			defer close(badFailed)
			return errors.New("bad action failed")
		}),
		onceTestCertificate("good", func(ctx context.Context) error {
			<-badFailed
			time.Sleep(100 * time.Millisecond)
			goodCtxErr = ctx.Err()
			return errors.New("good action finished")
		}),
	)
	err := daemon.RunOnce()
	if goodCtxErr != nil {
		t.Fatalf("the other certificate's action was cancelled: %v", goodCtxErr)
	}
	for _, want := range []string{"bad action failed", "good action finished"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("RunOnce error = %v, want it to contain %q", err, want)
		}
	}
}

func TestRunOnceReportsFailureOfAnyActionOfACertificate(t *testing.T) {
	ranFirst := false
	daemon := onceTestDaemon(t, onceTestCertificate("web",
		func(context.Context) error { ranFirst = true; return nil },
		func(context.Context) error { return errors.New("second action failed") },
	))
	if err := daemon.RunOnce(); err == nil || !strings.Contains(err.Error(), "second action failed") {
		t.Fatalf("RunOnce error = %v, want the second action's failure", err)
	}
	if !ranFirst {
		t.Fatal("the first action did not run")
	}
}

func TestRunOnceReportsEveryFailedCertificate(t *testing.T) {
	daemon := onceTestDaemon(t,
		onceTestCertificate("one", func(context.Context) error { return errors.New("first certificate failed") }),
		onceTestCertificate("two", func(context.Context) error { return errors.New("second certificate failed") }),
	)
	err := daemon.RunOnce()
	for _, want := range []string{"certificate one", "first certificate failed", "certificate two", "second certificate failed"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("RunOnce error = %v, want it to contain %q", err, want)
		}
	}
}

func TestRunOnceStoppedDuringActionFails(t *testing.T) {
	started := make(chan struct{})
	daemon := onceTestDaemon(t, onceTestCertificate("web", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}))
	go func() {
		<-started
		daemon.Stop()
	}()
	if err := daemon.RunOnce(); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce error = %v, want context.Canceled", err)
	}
}

func TestRunOnceKeepsRealFailureDuringShutdown(t *testing.T) {
	started := make(chan struct{})
	daemon := onceTestDaemon(t, onceTestCertificate("web", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return errors.New("write failed: disk full")
	}))
	go func() {
		<-started
		daemon.Stop()
	}()
	err := daemon.RunOnce()
	for _, want := range []string{"certificate web", "disk full"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("RunOnce error = %v, want it to contain %q", err, want)
		}
	}
}

func TestRunOnceReportsFailureOfEveryHTTPServer(t *testing.T) {
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "token rejected", http.StatusUnauthorized)
	}))
	defer main.Close()
	standby := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer standby.Close()

	daemon := MakeCertDXClientDaemon()
	daemon.Config.Common.RetryCount = 1
	daemon.Config.Http.MainServer.Url = main.URL
	daemon.Config.Http.StandbyServer.Url = standby.URL
	daemon.Config.Certificates = []config.ClientCertificate{{
		Name: "web", Domains: []string{"example.com"},
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: t.TempDir()}},
	}}
	if err := daemon.ClientInit(); err != nil {
		t.Fatal(err)
	}
	err := daemon.RunOnce()
	for _, want := range []string{"MainServer", "401", "StandbyServer", "502"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("RunOnce error = %v, want it to contain %q", err, want)
		}
	}
}
