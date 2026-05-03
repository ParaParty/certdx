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
		logging.Warn("Requested domains not allowed: %v", req.Domains)
		(*w).Header().Set("Content-Type", "application/json")
		(*w).Write([]byte(`{ "err": "Domains not allowed" }`))
		return
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
	logging.Error("Handle http cert request failed, err: %s", err)
	http.Error(*w, "", http.StatusInternalServerError)
}

func shutdownHTTPServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *CertDXServer) serveHttps(handler http.Handler) error {
	ctx := s.rootCtx
	entry := s.certCache.get(s.Config.HttpServer.Names)

	s.subscribe(entry)
	defer s.release(entry)

	cert, seen := entry.Snapshot()
	if !cert.IsValid() {
		seen = entry.WaitForUpdate(ctx, seen)
		if ctx.Err() != nil {
			return nil
		}
		cert, seen = entry.Snapshot()
	}

	for {
		certificate, err := tls.X509KeyPair(cert.FullChain, cert.Key)
		if err != nil {
			return fmt.Errorf("load HTTPS certificate: %w", err)
		}

		server := http.Server{
			Addr:    s.Config.HttpServer.Listen,
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{certificate},
			},
		}

		errChan := make(chan error, 1)
		go func() {
			logging.Info("Https server started")
			err := server.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- err
				return
			}
			logging.Info("Https server stopped: %s", err)
			errChan <- nil
		}()

		waitCtx, cancelWait := context.WithCancel(ctx)
		update := make(chan uint64, 1)
		go func() {
			update <- entry.WaitForUpdate(waitCtx, seen)
		}()

		select {
		case err := <-errChan:
			cancelWait()
			if err != nil {
				return fmt.Errorf("serve HTTPS: %w", err)
			}
			return nil
		case seen = <-update:
			cancelWait()
			if err := shutdownHTTPServer(&server); err != nil {
				return fmt.Errorf("shutdown HTTPS server: %w", err)
			}
			if ctx.Err() != nil {
				return nil
			}
			cert, seen = entry.Snapshot()
			continue
		case <-ctx.Done():
			cancelWait()
			if err := shutdownHTTPServer(&server); err != nil {
				return fmt.Errorf("shutdown HTTPS server: %w", err)
			}
			return nil
		}
	}
}

func (s *CertDXServer) serveHttp(handler http.Handler) error {
	server := http.Server{
		Addr:    s.Config.HttpServer.Listen,
		Handler: handler,
	}

	errChan := make(chan error, 1)
	go func() {
		logging.Info("Http server started")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
			return
		}
		logging.Info("Http server stopped: %s", err)
		errChan <- nil
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-s.rootCtx.Done():
		if err := shutdownHTTPServer(&server); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		return nil
	}
}

func (s *CertDXServer) serveHttpMtls(handler http.Handler) error {
	mtlsConfig, err := getMtlsConfig()
	if err != nil {
		return err
	}

	server := http.Server{
		Addr:      s.Config.HttpServer.Listen,
		Handler:   handler,
		TLSConfig: mtlsConfig,
	}

	errChan := make(chan error, 1)
	go func() {
		logging.Info("Http mtls server started")
		err := server.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
			return
		}
		logging.Info("Http mtls server stopped: %s", err)
		errChan <- nil
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("serve HTTP mTLS: %w", err)
		}
		return nil
	case <-s.rootCtx.Done():
		if err := shutdownHTTPServer(&server); err != nil {
			return fmt.Errorf("shutdown HTTP mTLS server: %w", err)
		}
		return nil
	}
}

// HttpSrv runs the HTTP API endpoint until Stop is called.
func (s *CertDXServer) HttpSrv() error {
	logging.Info("Start listening Http at %s%s", s.Config.HttpServer.Listen, s.Config.HttpServer.APIPath)

	mux := http.NewServeMux()
	if s.Config.HttpServer.AuthMethod == config.HTTP_AUTH_TOKEN {
		mux.HandleFunc("/", s.apiWithTokenHandler)
		if !s.Config.HttpServer.Secure {
			return s.serveHttp(mux)
		} else {
			return s.serveHttps(mux)
		}
	} else if s.Config.HttpServer.AuthMethod == config.HTTP_AUTH_MTLS {
		mux.HandleFunc("/", s.apiHandler)
		return s.serveHttpMtls(mux)
	}
	return fmt.Errorf("unsupported HTTP auth method: %s", s.Config.HttpServer.AuthMethod)
}
