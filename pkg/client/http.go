package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/mtls"
)

// httpIdleConnTimeout bounds how long an idle keep-alive connection is
// kept alive. Clients are built once per server and reused, but a
// bounded idle timeout still keeps sockets from piling up when the peer
// goes away.
const httpIdleConnTimeout = 90 * time.Second

type CertDXHttpClient struct {
	HttpClient *http.Client
	Server     *config.ClientHttpServer
}

// CertDXHttpClientOption customises a client under construction. An
// option that cannot be satisfied (e.g. an unreadable mTLS bundle)
// returns an error, which MakeCertDXHttpClient surfaces to the caller.
// Options must never be process-fatal: this code also runs inside the
// Caddy plugin and certdx_tools, where killing the host process on a
// transient file error is unacceptable.
type CertDXHttpClientOption func(client *CertDXHttpClient) error

func newTLSTransport(cfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig: cfg,
		IdleConnTimeout: httpIdleConnTimeout,
	}
}

func WithCertDXServerInfo(server *config.ClientHttpServer) CertDXHttpClientOption {
	return func(client *CertDXHttpClient) error {
		client.Server = server

		if server.AuthMethod == config.HTTP_AUTH_MTLS {
			cfg, err := mtls.LoadClient(server.PEM)
			if err != nil {
				return fmt.Errorf("load mtls bundle: %w", err)
			}
			client.HttpClient.Transport = newTLSTransport(cfg)
		}
		return nil
	}
}

func WithCertDXInsecure() CertDXHttpClientOption {
	return func(client *CertDXHttpClient) error {
		client.HttpClient.Transport = newTLSTransport(&tls.Config{
			InsecureSkipVerify: true,
		})
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
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
