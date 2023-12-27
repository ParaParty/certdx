package types

import "time"

type HttpCertReq struct {
	Domains []string `json:"domains"`
}

type HttpCertResp struct {
	RenewTimeLeft time.Duration `json:"renewTimeLeft"`
	Cert          []byte        `json:"cert"`
	Key           []byte        `json:"key"`
}
