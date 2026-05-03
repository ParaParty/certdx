package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
)

type CertDXHttpClient struct {
	HttpClient *http.Client
	Server     *config.ClientHttpServer
}

// CertDXHttpClientOption configures a CertDXHttpClient. Returning an
// error lets options that do real I/O (e.g. loading mtls material) fail
// the construction of the client instead of logging.Fatal-ing inside.
type CertDXHttpClientOption func(client *CertDXHttpClient) error

func WithCertDXServerInfo(server *config.ClientHttpServer) CertDXHttpClientOption {
	return func(client *CertDXHttpClient) error {
		client.Server = server

		if server.AuthMethod == config.HTTP_AUTH_MTLS {
			cfg, err := getMtlsConfig(server.CA, server.Certificate, server.Key)
			if err != nil {
				return fmt.Errorf("configure mtls for %s: %w", server.Url, err)
			}
			client.HttpClient.Transport = &http.Transport{
				TLSClientConfig: cfg,
			}
		}
		return nil
	}
}

func WithCertDXInsecure() CertDXHttpClientOption {
	return func(client *CertDXHttpClient) error {
		client.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		return nil
	}
}

func MakeCertDXHttpClient(s ...CertDXHttpClientOption) (*CertDXHttpClient, error) {
	ret := &CertDXHttpClient{
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, item := range s {
		if err := item(ret); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (c *CertDXHttpClient) makeGetCertRequest(ctx context.Context, domains []string) (*http.Request, error) {
	body, err := json.Marshal(api.HttpCertReq{Domains: domains})
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

func (c *CertDXHttpClient) GetCertCtx(ctx context.Context, domains []string) (*api.HttpCertResp, error) {
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

	var certResp = new(api.HttpCertResp)
	err = json.NewDecoder(resp.Body).Decode(certResp)
	if err != nil {
		return nil, err
	}

	return certResp, nil
}

func (c *CertDXHttpClient) GetCert(domains []string) (*api.HttpCertResp, error) {
	return c.GetCertCtx(context.Background(), domains)
}
