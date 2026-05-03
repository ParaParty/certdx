package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
)

// httpShutdownTimeout caps how long graceful shutdown of the HTTP API
// waits for in-flight requests to drain before forcing a close.
const httpShutdownTimeout = 30 * time.Second

func (s *CertDXServer) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == s.Config.HttpServer.APIPath {
		switch r.Method {
		case "POST":
			logstr := fmt.Sprintf("Http received cert request from: %s", r.RemoteAddr)
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				logstr = fmt.Sprintf("%s, xff: %s", logstr, xff)
			}
			logging.Info("%s", logstr)

			s.handleCertReq(&w, r)
			return
		default:
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func (s *CertDXServer) apiWithTokenHandler(w http.ResponseWriter, r *http.Request) {
	if s.checkAuthorizationToken(r) {
		s.apiHandler(w, r)
	} else {
		http.Error(w, "", http.StatusNotFound)
	}
}

func (s *CertDXServer) checkAuthorizationToken(r *http.Request) bool {
	if s.Config.HttpServer.Token == "" {
		return true
	}

	auth := r.Header.Get("Authorization")
	if auth != "" && strings.HasPrefix(auth, "Token ") {
		token := strings.TrimPrefix(auth, "Token ")
		if token == s.Config.HttpServer.Token {
			return true
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	logging.Warn("Not authorized request from: %s, xff: %s", r.RemoteAddr, xff)
	return false
}

func (s *CertDXServer) handleCertReq(w *http.ResponseWriter, r *http.Request) {
	var req api.HttpCertReq
	var resp []byte
	var cachedCert *certEntry
	var cert CertT

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		if err == io.EOF {
			err = fmt.Errorf("no body")
		}
		goto ERR
	}

	if !domain.AllAllowed(s.Config.ACME.AllowedDomains, req.Domains) {
		// Wrap the sentinel so the response handler below can branch on
		// errors.Is — same pattern as the SDS path, instead of two
		// separate "domains not allowed" code sites.
		err = fmt.Errorf("domains %v: %w", req.Domains, domain.ErrNotAllowed)
		goto ERR
	}

	cachedCert = s.certCache.get(req.Domains)
	if !s.isSubscribing(cachedCert) {
		_, err = s.renew(r.Context(), cachedCert, false)
		if err != nil {
			goto ERR
		}
	}

	cert = cachedCert.Cert()
	resp, err = json.Marshal(&api.HttpCertResp{
		RenewTimeLeft: s.Config.ACME.RenewTimeLeftDuration,
		FullChain:     cert.FullChain,
		Key:           cert.Key,
	})
	if err != nil {
		goto ERR
	}

	(*w).Header().Set("Content-Type", "application/json")
	(*w).Write(resp)
	logging.Info("Http sent cert: %v to: %s", cachedCert.domains, r.RemoteAddr)
	return

ERR:
	if errors.Is(err, domain.ErrNotAllowed) {
		logging.Warn("Requested domains not allowed: %v", req.Domains)
		(*w).Header().Set("Content-Type", "application/json")
		(*w).Write([]byte(`{ "err": "Domains not allowed" }`))
		return
	}
	logging.Error("Handle http cert request failed: %s", err)
	http.Error(*w, "", http.StatusInternalServerError)
}

// runHTTPServer starts a graceful-shutdown watcher tied to ctx and then
// blocks on listen() until either the listener exits on its own or ctx
// fires. On ctx fire, server.Shutdown is called with httpShutdownTimeout
// using a fresh context.Background — caller's ctx is already done by
// then, but in-flight requests still get the grace period to drain.
func runHTTPServer(ctx context.Context, server *http.Server, listen func() error) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := listen(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveHttps runs the token-auth HTTPS API. On every cert update the
// listener is shut down and re-bound with the fresh certificate, so the
// active TLS keypair always matches the latest snapshot. The per-
// iteration sub-ctx fires on either rootCtx or a fresh cert; runHTTPServer
// drives the listener and the graceful shutdown for that iteration.
func (s *CertDXServer) serveHttps(handler http.Handler) error {
	entry := s.certCache.get(s.Config.HttpServer.Names)
	s.subscribe(entry)
	defer s.release(entry)

	cert, seen := entry.Snapshot()
	for !cert.IsValid() {
		seen = entry.WaitForUpdate(s.rootCtx, seen)
		if s.rootCtx.Err() != nil {
			return nil
		}
		cert, _ = entry.Snapshot()
	}

	for s.rootCtx.Err() == nil {
		certificate, err := tls.X509KeyPair(cert.FullChain, cert.Key)
		if err != nil {
			return fmt.Errorf("load HTTPS certificate: %w", err)
		}

		server := &http.Server{
			Addr:    s.Config.HttpServer.Listen,
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{certificate},
			},
		}

		// iterCtx fires on either rootCtx or a fresh cert. WaitForUpdate
		// runs in a goroutine that calls cancel() on update; cancel is
		// also fired on iteration exit so the goroutine never leaks.
		iterCtx, cancel := context.WithCancel(s.rootCtx)
		go func() {
			seen = entry.WaitForUpdate(iterCtx, seen)
			cancel()
		}()

		logging.Info("Https server started")
		err = runHTTPServer(iterCtx, server, func() error {
			return server.ListenAndServeTLS("", "")
		})
		cancel()
		logging.Info("Https server stopped")

		if err != nil {
			return err
		}
		cert, _ = entry.Snapshot()
	}
	return nil
}

// serveHttp runs the plain (unencrypted) token-auth HTTP API. Used only
// when token auth is enabled and Secure is false.
func (s *CertDXServer) serveHttp(handler http.Handler) error {
	server := &http.Server{
		Addr:    s.Config.HttpServer.Listen,
		Handler: handler,
	}
	logging.Info("Http server started")
	defer logging.Info("Http server stopped")
	return runHTTPServer(s.rootCtx, server, server.ListenAndServe)
}

// serveHttpMtls runs the mTLS-authenticated HTTP API.
func (s *CertDXServer) serveHttpMtls(handler http.Handler) error {
	mtlsConfig, err := getMtlsConfig()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:      s.Config.HttpServer.Listen,
		Handler:   handler,
		TLSConfig: mtlsConfig,
	}
	logging.Info("Http mtls server started")
	defer logging.Info("Http mtls server stopped")
	return runHTTPServer(s.rootCtx, server, func() error {
		return server.ListenAndServeTLS("", "")
	})
}

// HttpSrv runs the HTTP API endpoint until Stop is called. Returns the
// first listener / setup error or nil on graceful shutdown.
func (s *CertDXServer) HttpSrv() error {
	logging.Info("Start listening Http at %s%s", s.Config.HttpServer.Listen, s.Config.HttpServer.APIPath)

	mux := http.NewServeMux()
	switch s.Config.HttpServer.AuthMethod {
	case config.HTTP_AUTH_TOKEN:
		mux.HandleFunc("/", s.apiWithTokenHandler)
		if s.Config.HttpServer.Secure {
			return s.serveHttps(mux)
		}
		return s.serveHttp(mux)
	case config.HTTP_AUTH_MTLS:
		mux.HandleFunc("/", s.apiHandler)
		return s.serveHttpMtls(mux)
	default:
		return fmt.Errorf("unsupported HTTP auth method: %q", s.Config.HttpServer.AuthMethod)
	}
}
