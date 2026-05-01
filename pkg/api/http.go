// Package api defines the wire-format types exchanged between certdx_server
// and certdx_client over HTTP.
//
// These types are part of certdx's public contract: any change to their
// JSON shape is a breaking change for mixed-version deployments. Treat this
// package as the authoritative home for that contract.
package api

import "time"

// HttpCertReq is the request body for POST / on the certdx HTTP server.
// The server validates Domains against its allow-list and returns an
// HttpCertResp with a fresh certificate, reloading from cache as needed.
type HttpCertReq struct {
	Domains []string `json:"domains"`
}

// HttpCertResp is the response body for POST / on the certdx HTTP server.
//
// FullChain and Key carry the PEM-encoded certificate chain and private key.
// RenewTimeLeft tells the client how long the cert is expected to remain
// valid; the client uses RenewTimeLeft/4 as its polling interval.
//
// Err carries a human-readable error string when the server cannot satisfy
// the request — e.g. the requested Domains are outside the allow-list.
type HttpCertResp struct {
	RenewTimeLeft time.Duration `json:"renewTimeLeft"`
	FullChain     []byte        `json:"fullchain"`
	Key           []byte        `json:"key"`
	Err           string        `json:"err"`
}
