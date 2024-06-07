package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"pkg.para.party/certdx/pkg/types"
)

func apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == Config.HttpServer.APIPath {
		switch r.Method {
		case "POST":
			if checkAuthorization(r) {
				log.Printf("[INF] Http received cert request from: %s", r.RemoteAddr)
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

	log.Printf("[WRN] Not authorized request from: %s", r.RemoteAddr)
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
		log.Printf("[WRN] Requested domains not allowed: %v", req.Domains)
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
	log.Printf("[INF] Http sent cert: %v to: %s", cachedCert.domains, r.RemoteAddr)
	return

ERR:
	log.Printf("[ERR] Handle http cert request failed: %s", err)
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
			log.Fatalf("[ERR] Failed to load cert: %s", err)
		}

		server := http.Server{
			Addr: Config.HttpServer.Listen,
		}

		server.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		}

		go func() {
			log.Printf("[INF] Https server started")
			err := server.ListenAndServeTLS("", "")
			log.Printf("[INF] Https server stopped: %s", err)
		}()
		<-*entry.Updated.Load()
		server.Close()
	}
}

func HttpSrv() {
	http.HandleFunc("/", apiHandler)

	if !Config.HttpServer.Secure {
		log.Printf("[INF] Http server started")
		err := http.ListenAndServe(Config.HttpServer.Listen, nil)
		log.Printf("[INF] Http server stopped: %s", err)
	} else {
		serveHttps()
	}
}
