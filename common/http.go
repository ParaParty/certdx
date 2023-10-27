package common

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

type httpParamResp struct {
	RenewTimeLeft time.Duration `json:"renewTimeLeft"`
}

type httpCertReq struct {
	Domains []string `json:"domains"`
}

type httpCertResp struct {
	ValidBefore time.Time `json:"validBefore"`
	Cert        []byte    `json:"cert"`
	Key         []byte    `json:"key"`
}

func checkAuthorization(r *http.Request) bool {
	if ServerConfig.HttpServer.Token == "" {
		return true
	}

	auth := r.Header.Get("Authorization")
	if auth != "" && strings.HasPrefix(auth, "Token ") {
		token := strings.TrimPrefix(auth, "Token ")
		if token == ServerConfig.HttpServer.Token {
			return true
		}
	}

	log.Printf("[WRN] Not authorized request from: %s", r.RemoteAddr)
	return false
}

func APIHandler(w http.ResponseWriter, r *http.Request) {
	if checkAuthorization(r) {
		switch r.Method {
		case "GET":
			log.Printf("[INF] Http received param request from: %s", r.RemoteAddr)
			resp, err := json.Marshal(&httpParamResp{
				RenewTimeLeft: ServerConfig.ACME.RenewTimeLeftDuration,
			})
			if err == nil {
				w.Header().Set("Content-Type", "application/json")
				w.Write(resp)
			} else {
				http.Error(w, "", http.StatusInternalServerError)
			}
			return
		case "POST":
			log.Printf("[INF] Http received cert request from: %s", r.RemoteAddr)
			handleCertReq(&w, r)
			return
		default:
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func handleCertReq(w *http.ResponseWriter, r *http.Request) {
	var req httpCertReq
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

	cachedCert = ServerCertCache.GetServerCacheEntry(req.Domains)
	if !cachedCert.Listening.Load() {
		_, err = cachedCert.Renew(false)
		if err != nil {
			goto ERR
		}
	}

	cert = cachedCert.Cert()
	resp, err = json.Marshal(&httpCertResp{
		ValidBefore: cert.ValidBefore,
		Cert:        cert.Cert,
		Key:         cert.Key,
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
