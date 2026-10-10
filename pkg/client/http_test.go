package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

func mustMakeClient(t *testing.T, opts ...CertDXHttpClientOption) *CertDXHttpClient {
	t.Helper()
	c, err := MakeCertDXHttpClient(opts...)
	if err != nil {
		t.Fatalf("MakeCertDXHttpClient: %v", err)
	}
	return c
}

func TestMakeCertDXHttpClientBadMtlsBundle(t *testing.T) {
	_, err := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
		Url:              "https://example.com",
		AuthMethod:       config.HTTP_AUTH_MTLS,
		ClientMtlsConfig: config.ClientMtlsConfig{PEM: "/nonexistent/client.pem"},
	}))
	if err == nil {
		t.Fatal("expected error for a missing mtls bundle")
	}
}

func TestPollInterval(t *testing.T) {
	cases := []struct {
		renewTimeLeft, want time.Duration
	}{
		{24 * time.Hour, 6 * time.Hour},
		{16 * time.Second, 4 * time.Second},
		{2 * time.Second, time.Second},
		{0, time.Minute},
		{-time.Hour, time.Minute},
	}
	for _, tc := range cases {
		if got := pollInterval(tc.renewTimeLeft); got != tc.want {
			t.Errorf("pollInterval(%s) = %s, want %s", tc.renewTimeLeft, got, tc.want)
		}
	}
}

func TestHttpPollerFailover(t *testing.T) {
	serve := func(fullchain string, down *atomic.Bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if down.Load() {
				http.Error(w, "", http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(api.HttpCertResp{FullChain: []byte(fullchain), RenewTimeLeft: 24 * time.Hour})
		}))
	}
	var mainDown, standbyDown atomic.Bool
	mainDown.Store(true)
	mainSrv := serve("main", &mainDown)
	defer mainSrv.Close()
	standbySrv := serve("standby", &standbyDown)
	defer standbySrv.Close()

	d := MakeCertDXClientDaemon()
	defer d.Stop()
	d.Config.Common.RetryCount = 2
	main := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{Url: mainSrv.URL}))
	standby := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{Url: standbySrv.URL}))
	cert := &watchingCert{
		Config:     config.ClientCertificate{Name: "x", Domains: []string{"example.com"}},
		UpdateChan: make(chan certData, 1),
	}
	p := d.newHttpPoller(cert, main, standby)

	expectWait := func(step string, want time.Duration) {
		t.Helper()
		if got := p.poll(); got != want {
			t.Fatalf("%s: wait %s, want %s", step, got, want)
		}
	}
	expectCert := func(want string) {
		t.Helper()
		if got := <-cert.UpdateChan; string(got.Fullchain) != want {
			t.Fatalf("delivered %q, want %q", got.Fullchain, want)
		}
	}

	// Main gets retryCount attempts on a backoff, then the standby takes over.
	expectWait("main 1/2", pollRetryMin)
	expectWait("main 2/2", 0)
	expectWait("standby", 6*time.Hour)
	expectCert("standby")

	// The next round starts over from the main server.
	mainDown.Store(false)
	expectWait("main back", 6*time.Hour)
	expectCert("main")

	// Both down: each server uses up its retries, then the poller idles.
	mainDown.Store(true)
	standbyDown.Store(true)
	expectWait("main 1/2", pollRetryMin)
	expectWait("main 2/2", 0)
	expectWait("standby 1/2", pollRetryMin)
	expectWait("standby 2/2", pollIdleWait)
	if p.current != 0 {
		t.Fatal("poller did not go back to the main server")
	}
}

func TestMakeCertDXHttpClientDefaults(t *testing.T) {
	c := mustMakeClient(t)
	if c.HttpClient == nil {
		t.Fatal("HttpClient is nil")
	}
	if c.HttpClient.Timeout != 30*time.Second {
		t.Fatalf("timeout: got %v want 30s", c.HttpClient.Timeout)
	}
	if c.Server != nil {
		t.Fatal("Server should be nil without option")
	}
}

func TestWithCertDXInsecure(t *testing.T) {
	c := mustMakeClient(t, WithCertDXInsecure())
	tr, ok := c.HttpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify not set")
	}
	if tr.IdleConnTimeout != idleConnTimeout {
		t.Fatalf("IdleConnTimeout: got %v want %v", tr.IdleConnTimeout, idleConnTimeout)
	}
}

func TestWithCertDXServerInfo(t *testing.T) {
	srv := &config.ClientHttpServer{
		Url:        "https://example.com",
		AuthMethod: config.HTTP_AUTH_TOKEN,
		Token:      "tok",
	}
	c := mustMakeClient(t, WithCertDXServerInfo(srv))
	if c.Server != srv {
		t.Fatal("Server not set by option")
	}
}

func TestMakeGetCertRequestMethod(t *testing.T) {
	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: "https://example.com/api",
	}))

	req, err := c.makeGetCertRequest(context.Background(), []string{"a.com"})
	if err != nil {
		t.Fatalf("makeGetCertRequest: %v", err)
	}
	if req.Method != "POST" {
		t.Fatalf("method: got %s want POST", req.Method)
	}
	if req.URL.String() != "https://example.com/api" {
		t.Fatalf("url: got %s", req.URL.String())
	}
}

func TestMakeGetCertRequestTokenHeader(t *testing.T) {
	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url:        "https://example.com",
		AuthMethod: config.HTTP_AUTH_TOKEN,
		Token:      "secret",
	}))

	req, err := c.makeGetCertRequest(context.Background(), []string{"a.com"})
	if err != nil {
		t.Fatalf("makeGetCertRequest: %v", err)
	}
	auth := req.Header.Get("Authorization")
	if auth != "Token secret" {
		t.Fatalf("Authorization header: got %q want %q", auth, "Token secret")
	}
}

func TestMakeGetCertRequestNoTokenHeader(t *testing.T) {
	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url:        "https://example.com",
		AuthMethod: config.HTTP_AUTH_TOKEN,
		Token:      "",
	}))

	req, err := c.makeGetCertRequest(context.Background(), []string{"a.com"})
	if err != nil {
		t.Fatalf("makeGetCertRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatalf("should not set Authorization for empty token")
	}
}

func TestMakeGetCertRequestBody(t *testing.T) {
	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: "https://example.com",
	}))

	req, err := c.makeGetCertRequest(context.Background(), []string{"a.com", "b.com"})
	if err != nil {
		t.Fatalf("makeGetCertRequest: %v", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var certReq api.HttpCertReq
	if err := json.Unmarshal(body, &certReq); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(certReq.Domains) != 2 || certReq.Domains[0] != "a.com" || certReq.Domains[1] != "b.com" {
		t.Fatalf("body domains: got %v", certReq.Domains)
	}
}

func TestGetCertCtxSuccess(t *testing.T) {
	resp := api.HttpCertResp{
		RenewTimeLeft: 24 * time.Hour,
		FullChain:     []byte("PEM-fullchain"),
		Key:           []byte("PEM-key"),
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	got, err := c.GetCertCtx(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatalf("GetCertCtx: %v", err)
	}
	if string(got.FullChain) != "PEM-fullchain" {
		t.Errorf("fullchain: got %q", got.FullChain)
	}
	if string(got.Key) != "PEM-key" {
		t.Errorf("key: got %q", got.Key)
	}
	if got.RenewTimeLeft != 24*time.Hour {
		t.Errorf("renewTimeLeft: got %v", got.RenewTimeLeft)
	}
}

func TestGetCertCtxNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer ts.Close()

	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	_, err := c.GetCertCtx(context.Background(), []string{"example.com"})
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}

func TestGetCertCtxBadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{bad json"))
	}))
	defer ts.Close()

	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	_, err := c.GetCertCtx(context.Background(), []string{"example.com"})
	if err == nil {
		t.Fatal("expected error on bad JSON response")
	}
}

func TestGetCertCtxBodyTooLarge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"key":"` + strings.Repeat("A", maxCertRespBodySize) + `"}`))
	}))
	defer ts.Close()

	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	if _, err := c.GetCertCtx(context.Background(), []string{"example.com"}); err == nil {
		t.Fatal("expected error on an oversized response")
	}
}

func TestGetCertDelegatesToGetCertCtx(t *testing.T) {
	resp := api.HttpCertResp{
		FullChain: []byte("fc"),
		Key:       []byte("k"),
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	c := mustMakeClient(t, WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	got, err := c.GetCert([]string{"example.com"})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if string(got.FullChain) != "fc" {
		t.Errorf("fullchain: got %q", got.FullChain)
	}
}
