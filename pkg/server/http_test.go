package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/api"
)

func makeTestServer(token string, apiPath string, allowedDomains []string) *CertDXServer {
	s := MakeCertDXServer()
	s.Config.HttpServer.Token = token
	s.Config.HttpServer.APIPath = apiPath
	s.Config.ACME.AllowedDomains = allowedDomains
	return s
}

func TestCheckAuthorizationTokenEmptyConfig(t *testing.T) {
	s := makeTestServer("", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	if !s.checkAuthorizationToken(req) {
		t.Fatal("empty config token should always authorize")
	}
}

func TestCheckAuthorizationTokenValid(t *testing.T) {
	s := makeTestServer("secret123", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Token secret123")
	if !s.checkAuthorizationToken(req) {
		t.Fatal("valid token should authorize")
	}
}

func TestCheckAuthorizationTokenInvalid(t *testing.T) {
	s := makeTestServer("secret123", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Token wrong")
	if s.checkAuthorizationToken(req) {
		t.Fatal("invalid token should not authorize")
	}
}

func TestCheckAuthorizationTokenMissingHeader(t *testing.T) {
	s := makeTestServer("secret123", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	if s.checkAuthorizationToken(req) {
		t.Fatal("missing Authorization header should not authorize")
	}
}

func TestCheckAuthorizationTokenWrongScheme(t *testing.T) {
	s := makeTestServer("secret123", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	if s.checkAuthorizationToken(req) {
		t.Fatal("Bearer scheme should not authorize (expects 'Token ')")
	}
}

func TestApiHandlerWrongPath(t *testing.T) {
	s := makeTestServer("", "/api/cert", nil)
	req := httptest.NewRequest("POST", "/wrong", nil)
	w := httptest.NewRecorder()
	s.apiHandler(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("wrong path: got %d want %d", w.Code, http.StatusNotFound)
	}
}

func TestApiHandlerWrongMethod(t *testing.T) {
	s := makeTestServer("", "/api/cert", nil)
	req := httptest.NewRequest("GET", "/api/cert", nil)
	w := httptest.NewRecorder()
	s.apiHandler(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("wrong method: got %d want %d", w.Code, http.StatusNotFound)
	}
}

func TestApiWithTokenHandlerRejectsInvalidToken(t *testing.T) {
	s := makeTestServer("mysecret", "/", nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Token wrong")
	w := httptest.NewRecorder()
	s.apiWithTokenHandler(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("invalid token: got %d want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleCertReqEmptyBody(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	var rw http.ResponseWriter = w
	s.handleCertReq(&rw, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("empty body: got %d want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestHandleCertReqDomainsNotAllowed(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	body, _ := json.Marshal(api.HttpCertReq{Domains: []string{"evil.com"}})
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	var rw http.ResponseWriter = w
	s.handleCertReq(&rw, req)

	if w.Code != http.StatusOK {
		t.Fatalf("domains not allowed: got status %d want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Domains not allowed") {
		t.Fatalf("expected error message in body: %s", w.Body.String())
	}
}

func TestHandleCertReqValidDomainsCachedCert(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})

	// Pre-populate the cert cache with a valid cert.
	entry := s.certCache.get([]string{"example.com"})
	entry.stateMu.Lock()
	entry.cert = CertT{
		FullChain:   []byte("PEM-chain"),
		Key:         []byte("PEM-key"),
		ValidBefore: time.Now().Add(time.Hour),
	}
	entry.subscribing = 1 // Mark as subscribing so handleCertReq skips renew.
	entry.stateMu.Unlock()

	body, _ := json.Marshal(api.HttpCertReq{Domains: []string{"example.com"}})
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	var rw http.ResponseWriter = w
	s.handleCertReq(&rw, req)

	if w.Code != http.StatusOK {
		t.Fatalf("valid domains: got status %d want %d", w.Code, http.StatusOK)
	}

	var resp api.HttpCertResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if string(resp.FullChain) != "PEM-chain" {
		t.Errorf("fullchain: got %q want %q", resp.FullChain, "PEM-chain")
	}
	if string(resp.Key) != "PEM-key" {
		t.Errorf("key: got %q want %q", resp.Key, "PEM-key")
	}
}

func TestHandleCertReqInvalidJSON(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	req := httptest.NewRequest("POST", "/", strings.NewReader("{invalid"))
	w := httptest.NewRecorder()
	var rw http.ResponseWriter = w
	s.handleCertReq(&rw, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("invalid json: got %d want %d", w.Code, http.StatusInternalServerError)
	}
}
