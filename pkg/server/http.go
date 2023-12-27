package server

import (
	"certdx/pkg/types"

	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func APIHandler(w http.ResponseWriter, r *http.Request) {
	if checkAuthorization(r) {
		switch r.Method {
		case "POST":
			log.Printf("[INF] Http received cert request from: %s", r.RemoteAddr)
			handleCertReq(&w, r)
			return
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
		goto ERR
	}

	if !domainsAllowed(req.Domains) {
		log.Printf("[WRN] Requested domains not allowed: %v", req.Domains)
		http.Error(*w, "Domains not allowed", http.StatusForbidden)
		return
	}

	cachedCert = ServerCertCache.GetEntry(req.Domains)
	if !cachedCert.Listening.Load() {
		_, err = cachedCert.Renew(false)
		if err != nil {
			goto ERR
		}
	}

	cert = cachedCert.Cert()
	resp, err = json.Marshal(&types.HttpCertResp{
		RenewTimeLeft: Config.ACME.RenewTimeLeftDuration,
		Cert:          cert.Cert,
		Key:           cert.Key,
	})
	if err != nil {
		goto ERR
	}

	(*w).Header().Set("Content-Type", "application/json")
	(*w).Write(resp)
	log.Printf("[INF] Http sent cert: %v to: %s", cachedCert.Domains, r.RemoteAddr)
	return

ERR:
	log.Printf("[ERR] Handle http cert request failed: %s", err)
	http.Error(*w, "", http.StatusInternalServerError)
}
