package client

import (
	"certdx/pkg/config"
	"certdx/pkg/types"

	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var client = &http.Client{
	Timeout: 30 * time.Second,
}

func GetCert(server *config.ClientHttpServer, domains []string) (*types.HttpCertResp, error) {
	body, err := json.Marshal(types.HttpCertReq{Domains: domains})
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

	var certResp = new(types.HttpCertResp)
	err = json.NewDecoder(resp.Body).Decode(certResp)
	if err != nil {
		return nil, err
	}

	return certResp, nil
}
