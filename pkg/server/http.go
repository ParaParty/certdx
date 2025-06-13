package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/types"
	"pkg.para.party/certdx/pkg/utils"
)

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
	var req types.HttpCertReq
	var resp []byte
	var cachedCert *ServerCertCacheEntry
	var cert CertT

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		if err == io.EOF {
			err = fmt.Errorf("no body")
		}
		goto ERR
	}

	if !utils.DomainsAllowed(s.Config.ACME.AllowedDomains, req.Domains) {
		logging.Warn("Requested domains not allowed: %v", req.Domains)
		(*w).Header().Set("Content-Type", "application/json")
		(*w).Write([]byte(`{ "err": "Domains not allowed" }`))
		return
	}

	cachedCert = s.GetCertCacheEntry(req.Domains)
	if !s.IsSubcribing(cachedCert) {
		_, err = s.Renew(cachedCert, false)
		if err != nil {
			goto ERR
		}
	}

	cert = cachedCert.Cert()
	resp, err = json.Marshal(&types.HttpCertResp{
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

func (s *CertDXServer) serveHttps() {
	entry := s.GetCertCacheEntry(s.Config.HttpServer.Names)
	cert_ := entry.Cert()

	s.Subscribe(entry)

	if !cert_.IsValid() {
		<-*entry.Updated.Load()
	}

	for {
		cert := entry.Cert()
		certificate, err := tls.X509KeyPair(cert.FullChain, cert.Key)
		if err != nil {
			logging.Fatal("Failed to load cert, err: %s", err)
		}

		server := http.Server{
			Addr: s.Config.HttpServer.Listen,
		}

		server.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		}

		go func() {
			logging.Info("Https server started")
			err := server.ListenAndServeTLS("", "")
			logging.Info("Https server stopped: %s", err)
		}()

		select {
		case <-*entry.Updated.Load():
			server.Close()
		case <-s.stop:
			server.Close()
			return
		}
	}
}

func (s *CertDXServer) serveHttp() {
	server := http.Server{
		Addr: s.Config.HttpServer.Listen,
	}

	go func() {
		logging.Info("Http server started")
		err := server.ListenAndServe()
		logging.Info("Http server stopped: %s", err)
	}()

	<-s.stop
	server.Close()
}

func (s *CertDXServer) serveHttpMtls() {
	server := http.Server{
		Addr:      s.Config.HttpServer.Listen,
		TLSConfig: getMtlsConfig(),
	}

	go func() {
		logging.Info("Http mtls server started")
		err := server.ListenAndServeTLS("", "")
		logging.Info("Http mtls server stopped: %s", err)
	}()

	<-s.stop
	server.Close()
}

func (s *CertDXServer) HttpSrv() {
	logging.Info("Start listening Http at %s%s", s.Config.HttpServer.Listen, s.Config.HttpServer.APIPath)

	if s.Config.HttpServer.AuthMethod == config.HTTP_AUTH_TOKEN {
		http.HandleFunc("/", s.apiWithTokenHandler)
		if !s.Config.HttpServer.Secure {
			s.serveHttp()
		} else {
			s.serveHttps()
		}
	} else if s.Config.HttpServer.AuthMethod == config.HTTP_AUTH_MTLS {
		http.HandleFunc("/", s.apiHandler)
		s.serveHttpMtls()
	}
}
