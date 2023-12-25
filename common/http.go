package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type httpCertReq struct {
	Domains []string `json:"domains"`
}

type httpCertResp struct {
	RenewTimeLeft time.Duration `json:"renewTimeLeft"`
	Cert          []byte        `json:"cert"`
	Key           []byte        `json:"key"`
}

func checkHttpAuthorization(r *http.Request) bool {
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

func HttpAPIHandler(w http.ResponseWriter, r *http.Request) {
	if checkHttpAuthorization(r) {
		switch r.Method {
		case "POST":
			log.Printf("[INF] Http received cert request from: %s", r.RemoteAddr)
			handleHttpCertReq(&w, r)
			return
		default:
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func handleHttpCertReq(w *http.ResponseWriter, r *http.Request) {
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
		RenewTimeLeft: ServerConfig.ACME.RenewTimeLeftDuration,
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

var client = &http.Client{
	Timeout: 30 * time.Second,
}

func HttpGetCert(server *ClientHttpServer, domains []string) (*httpCertResp, error) {
	body, err := json.Marshal(httpCertReq{Domains: domains})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", server.Url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	if server.Token != "" {
		req.Header = http.Header{
			"Authorization": {fmt.Sprintf("Token %s", server.Token)},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST '%s' status: %s", server.Url, resp.Status)
	}

	var certResp = new(httpCertResp)
	err = json.NewDecoder(resp.Body).Decode(certResp)
	if err != nil {
		return nil, err
	}

	return certResp, nil
}
