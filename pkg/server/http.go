package server

import (
	"context"
	"crypto/subtle"
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
	"pkg.para.party/certdx/pkg/mtls"
)

// httpShutdownTimeout caps how long graceful shutdown of the HTTP API
// waits for in-flight requests to drain before forcing a close.
const httpShutdownTimeout = 30 * time.Second

// httpCertWaitTimeout caps how long a cert request waits for an in-flight
// issuance to land before answering 503. It only applies when another
// subscriber (the SDS path, the HTTPS listener, ...) already has a renewer
// running for the requested pack, so the request piggybacks on that
// issuance rather than starting a second one.
const httpCertWaitTimeout = 30 * time.Second

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
		// Constant-time compare so the response latency doesn't leak how
		// many leading bytes of the token were guessed right. The length
		// check keeps ConstantTimeCompare from short-circuiting on it.
		expected := s.Config.HttpServer.Token
		if len(token) == len(expected) &&
			subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return true
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	logging.Warn("Not authorized request from: %s, xff: %s", r.RemoteAddr, xff)
	return false
}

func (s *CertDXServer) handleCertReq(w *http.ResponseWriter, r *http.Request) {
	var req api.HttpCertReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			err = fmt.Errorf("no body")
		}
		// A body we can't parse is the caller's fault, not ours; 500 stays
		// reserved for server-side (ACME) failures.
		logging.Warn("Malformed http cert request from %s: %s", r.RemoteAddr, err)
		http.Error(*w, "", http.StatusBadRequest)
		return
	}

	// An empty domain set would otherwise pass the allow-list check
	// vacuously and have the server issue for nothing.
	if len(req.Domains) == 0 {
		logging.Warn("Http cert request from %s carries no domains", r.RemoteAddr)
		http.Error(*w, "", http.StatusBadRequest)
		return
	}

	if !domain.AllAllowed(s.Config.ACME.AllowedDomains, req.Domains) {
		logging.Warn("Requested domains not allowed: %v (%s)", req.Domains, domain.ErrNotAllowed)
		(*w).Header().Set("Content-Type", "application/json")
		(*w).Write([]byte(`{ "err": "Domains not allowed" }`))
		return
	}

	cachedCert, err := s.certCache.get(req.Domains)
	if err != nil {
		if errors.Is(err, ErrNoDomains) {
			logging.Warn("Http cert request from %s carries no usable domains: %v", r.RemoteAddr, req.Domains)
			http.Error(*w, "", http.StatusBadRequest)
			return
		}
		logging.Error("Handle http cert request failed: %s", err)
		http.Error(*w, "", http.StatusServiceUnavailable)
		return
	}

	cert, seen := cachedCert.Snapshot()
	if !cert.IsValid() {
		if s.isSubscribing(cachedCert) {
			// A renewer already owns this pack — wait for it to publish
			// instead of racing a second ACME obtain against it. The entry
			// may be subscribed but not yet issued, in which case its cert
			// is still the zero value.
			waitCtx, cancel := context.WithTimeout(r.Context(), httpCertWaitTimeout)
			cachedCert.WaitForUpdate(waitCtx, seen)
			cancel()
		} else if _, err := s.renew(r.Context(), cachedCert, false); err != nil {
			logging.Error("Handle http cert request failed: %s", err)
			http.Error(*w, "", http.StatusInternalServerError)
			return
		}
		cert = cachedCert.Cert()
	}

	// Never answer 200 with an empty cert: the client writes whatever it
	// gets straight to disk and would clobber a working certificate with
	// zero-length files. Absent material is the only "no cert yet" signal
	// this guard keys on — expiry is the renewer's business, and answering
	// 503 for a cert we do hold would leave the client with nothing at all
	// instead of a cert it can keep using while the renewal lands.
	if len(cert.FullChain) == 0 || len(cert.Key) == 0 {
		logging.Warn("No cert for %v available yet, asked by: %s", cachedCert.domains, r.RemoteAddr)
		http.Error(*w, "", http.StatusServiceUnavailable)
		return
	}

	resp, err := json.Marshal(&api.HttpCertResp{
		RenewTimeLeft: s.Config.ACME.RenewTimeLeftDuration,
		FullChain:     cert.FullChain,
		Key:           cert.Key,
	})
	if err != nil {
		logging.Error("Handle http cert request failed: %s", err)
		http.Error(*w, "", http.StatusInternalServerError)
		return
	}

	(*w).Header().Set("Content-Type", "application/json")
	(*w).Write(resp)
	logging.Info("Http sent cert: %v to: %s", cachedCert.domains, r.RemoteAddr)
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
	entry, err := s.certCache.get(s.Config.HttpServer.Names)
	if err != nil {
		return fmt.Errorf("HTTPS listener certificate %v: %w", s.Config.HttpServer.Names, err)
	}
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
			ErrorLog: logging.ErrorLogger(),
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
		Addr:     s.Config.HttpServer.Listen,
		Handler:  handler,
		ErrorLog: logging.ErrorLogger(),
	}
	logging.Info("Http server started")
	defer logging.Info("Http server stopped")
	return runHTTPServer(s.rootCtx, server, server.ListenAndServe)
}

// serveHttpMtls runs the mTLS-authenticated HTTP API.
func (s *CertDXServer) serveHttpMtls(handler http.Handler) error {
	mtlsConfig, err := mtls.LoadServer(s.Config.MTLS.PEM)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:      s.Config.HttpServer.Listen,
		Handler:   handler,
		TLSConfig: mtlsConfig,
		ErrorLog:  logging.ErrorLogger(),
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
