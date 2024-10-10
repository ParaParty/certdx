package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/types"
)

func apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == Config.HttpServer.APIPath {
		switch r.Method {
		case "POST":
			if checkAuthorization(r) {
				xff := r.Header.Get("X-Forwarded-For")
				logging.Info("Http received cert request from: %s, xff: %s", r.RemoteAddr, xff)
				handleCertReq(&w, r)
				return
			}
		default:
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func checkAuthorization(r *http.Request) bool {
	if Config.HttpServer.Token == "" {
		return true
	}

	auth := r.Header.Get("Authorization")
	if auth != "" && strings.HasPrefix(auth, "Token ") {
		token := strings.TrimPrefix(auth, "Token ")
		if token == Config.HttpServer.Token {
			return true
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	logging.Warn("Not authorized request from: %s, xff: %s", r.RemoteAddr, xff)
	return false
}

func handleCertReq(w *http.ResponseWriter, r *http.Request) {
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

	if !domainsAllowed(req.Domains) {
		logging.Warn("Requested domains not allowed: %v", req.Domains)
		(*w).Header().Set("Content-Type", "application/json")
		(*w).Write([]byte(`{ "err": "Domains not allowed" }`))
		return
	}

	cachedCert = serverCertCache.GetEntry(req.Domains)
	if !cachedCert.IsSubcribing() {
		_, err = cachedCert.Renew(false)
		if err != nil {
			goto ERR
		}
	}

	cert = cachedCert.Cert()
	resp, err = json.Marshal(&types.HttpCertResp{
		RenewTimeLeft: Config.ACME.RenewTimeLeftDuration,
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

func serveHttps() {
	entry := serverCertCache.GetEntry(Config.HttpServer.Names)
	cert_ := entry.Cert()

	entry.Subscribe()

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
			Addr: Config.HttpServer.Listen,
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
		<-*entry.Updated.Load()
		server.Close()
	}
}

func HttpSrv() {
	http.HandleFunc("/", apiHandler)

	if !Config.HttpServer.Secure {
		logging.Info("Http server started")
		err := http.ListenAndServe(Config.HttpServer.Listen, nil)
		logging.Info("Http server stopped: %s", err)
	} else {
		serveHttps()
	}
}
