package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/types"
)

type CertDXHttpClient struct {
	HttpClient *http.Client
	Server     *config.ClientHttpServer
}

type CertDXHttpClientOption func(client *CertDXHttpClient)

func WithCertDXServerInfo(server *config.ClientHttpServer) CertDXHttpClientOption {
	return func(client *CertDXHttpClient) {
		client.Server = server

		if server.AuthMethod == config.HTTP_AUTH_MTLS {
			client.HttpClient.Transport = &http.Transport{
				TLSClientConfig: getMtlsConfig(server.CA, server.Certificate, server.Key),
			}
		}
	}
}

func WithCertDXInsecure() CertDXHttpClientOption {
	return func(client *CertDXHttpClient) {
		client.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}
}

func MakeCertDXHttpClient(s ...CertDXHttpClientOption) *CertDXHttpClient {
	ret := &CertDXHttpClient{
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, item := range s {
		item(ret)
	}

	return ret
}

func (c *CertDXHttpClient) makeGetCertRequest(ctx context.Context, domains []string) (*http.Request, error) {
	body, err := json.Marshal(types.HttpCertReq{Domains: domains})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.Server.Url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	if c.Server.AuthMethod == config.HTTP_AUTH_TOKEN && c.Server.Token != "" {
		req.Header = http.Header{
			"Authorization": {fmt.Sprintf("Token %s", c.Server.Token)},
		}
	}
	return req, nil
}

func (c *CertDXHttpClient) GetCertCtx(ctx context.Context, domains []string) (*types.HttpCertResp, error) {
	req, err := c.makeGetCertRequest(ctx, domains)
	if err != nil {
		return nil, err
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST '%s' status: %s", c.Server.Url, resp.Status)
	}

	var certResp = new(types.HttpCertResp)
	err = json.NewDecoder(resp.Body).Decode(certResp)
	if err != nil {
		return nil, err
	}

	return certResp, nil
}

func (c *CertDXHttpClient) GetCert(domains []string) (*types.HttpCertResp, error) {
	return c.GetCertCtx(context.Background(), domains)
}
