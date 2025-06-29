package types

import "time"

type HttpCertReq struct {
	Domains []string `json:"domains"`
}

type HttpCertResp struct {
	RenewTimeLeft time.Duration `json:"renewTimeLeft"`
	FullChain     []byte        `json:"fullchain"`
	Key           []byte        `json:"key"`
	Err           string        `json:"err"`
}

type DomainKey uint64
