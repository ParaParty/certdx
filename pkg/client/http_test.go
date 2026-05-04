package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

func TestMakeCertDXHttpClientDefaults(t *testing.T) {
	c := MakeCertDXHttpClient()
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
	c := MakeCertDXHttpClient(WithCertDXInsecure())
	tr, ok := c.HttpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify not set")
	}
}

func TestWithCertDXServerInfo(t *testing.T) {
	srv := &config.ClientHttpServer{
		Url:        "https://example.com",
		AuthMethod: config.HTTP_AUTH_TOKEN,
		Token:      "tok",
	}
	c := MakeCertDXHttpClient(WithCertDXServerInfo(srv))
	if c.Server != srv {
		t.Fatal("Server not set by option")
	}
}

func TestMakeGetCertRequestMethod(t *testing.T) {
	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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
	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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
	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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
	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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

	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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

	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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

	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
		Url: ts.URL,
	}))

	_, err := c.GetCertCtx(context.Background(), []string{"example.com"})
	if err == nil {
		t.Fatal("expected error on bad JSON response")
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

	c := MakeCertDXHttpClient(WithCertDXServerInfo(&config.ClientHttpServer{
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
