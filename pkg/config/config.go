package config

import (
	"fmt"
	"google.golang.org/appengine"
	"path"
	"time"
)

const (
	DnsProviderTypeCloudflare   string = "cloudflare"
	DnsProviderTypeTencentCloud string = "tencentcloud"
)

type DnsProvider struct {
	Type                                  string `toml:"type" json:"type,omitempty"`
	DisableCompletePropagationRequirement bool   `toml:"disableCompletePropagationRequirement" json:"disable_complete_propagation_requirement,omitempty"`

	// cloudflare
	Email  string `toml:"email" json:"email,omitempty"`
	APIKey string `toml:"apiKey" json:"api_key,omitempty"`

	// tencentcloud
	SecretID  string `toml:"secretID" json:"secret_id,omitempty"`
	SecretKey string `toml:"secretKey" json:"secret_key,omitempty"`
}

func (p DnsProvider) Validate() error {
	switch p.Type {
	case DnsProviderTypeCloudflare:
		if p.Email == "" || p.APIKey == "" {
			return fmt.Errorf("DnsProvider Cloudflare: empty email or key")
		}
	case DnsProviderTypeTencentCloud:
		if p.SecretID == "" || p.SecretKey == "" {
			return fmt.Errorf("DnsProvider TencentCloud: empty email or key")
		}
	}
	return nil
}

type ServerConfigT struct {
	ACME ACMEConfig `toml:"ACME" json:"acme,omitempty"`

	DnsProvider DnsProvider `toml:"DnsProvider" json:"dns_provider,omitempty"`

	HttpServer HttpServerConfig `toml:"HttpServer" json:"http_server,omitempty"`
}

type ACMEConfig struct {
	Email          string   `toml:"email" json:"email,omitempty"`
	Provider       string   `toml:"provider" json:"provider,omitempty"`
	RetryCount     int      `toml:"retryCount" json:"retry_count,omitempty"`
	CertLifeTime   string   `toml:"certLifeTime" json:"cert_life_time,omitempty"`
	RenewTimeLeft  string   `toml:"renewTimeLeft" json:"renew_time_left,omitempty"`
	AllowedDomains []string `toml:"allowedDomains" json:"allowed_domains,omitempty"`

	CertLifeTimeDuration  time.Duration `toml:"-" json:"-"`
	RenewTimeLeftDuration time.Duration `toml:"-" json:"-"`
}

func (c ACMEConfig) Validate() error {
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("AllowedDomains is empty")
	}
	return nil
}

type HttpServerConfig struct {
	Enabled bool     `toml:"enabled" json:"enabled,omitempty"`
	Listen  string   `toml:"listen" json:"listen,omitempty"`
	APIPath string   `toml:"apiPath" json:"api_path,omitempty"`
	Secure  bool     `toml:"secure" json:"secure,omitempty"`
	Names   []string `toml:"names" json:"names,omitempty"`
	Token   string   `toml:"token" json:"token,omitempty"`
}

func (c HttpServerConfig) Validate() error {
	if c.Secure && len(c.Names) == 0 {
		return fmt.Errorf("secure http server with no name")
	}
	return nil
}

// type GRPCServerConfig struct {
// 	Listen string `toml:"listen"`
// 	Secure bool   `toml:"secure"`
// 	Name   string `toml:"name"`
// 	Token  string `toml:"token"`
// }

func (c *ServerConfigT) SetDefault() {
	c.ACME = ACMEConfig{
		RetryCount:            5,
		CertLifeTimeDuration:  168 * time.Hour,
		RenewTimeLeftDuration: 24 * time.Hour,
	}

	c.HttpServer = HttpServerConfig{
		Listen:  ":10001",
		APIPath: "/",
		Secure:  false,
	}
}

func (c *ServerConfigT) Validate() error {
	ret := appengine.MultiError{}

	if err := c.DnsProvider.Validate(); err != nil {
		ret = append(ret, err)
	}

	if err := c.ACME.Validate(); err != nil {
		ret = append(ret, err)
	}

	if err := c.HttpServer.Validate(); err != nil {
		ret = append(ret, err)
	}

	if len(ret) > 0 {
		return ret
	}
	return nil
}

type ClientConfigT struct {
	Server ClientServerConfig `toml:"Server" json:"server,omitempty"`

	Http struct {
		MainServer    ClientHttpServer `toml:"MainServer" json:"main_server,omitempty"`
		StandbyServer ClientHttpServer `toml:"StandbyServer" json:"standby_server,omitempty"`
	} `toml:"Http" json:"http,omitempty"`

	// GRPC struct {
	// 	MainServer    ClientGRPCServer `toml:"MainServer"`
	// 	StandbyServer ClientGRPCServer `toml:"StandbyServer"`
	// } `toml:"GRPC"`

	Certifications []ClientCertification `toml:"Certifications" json:"certifications,omitempty"`
}

type ClientServerConfig struct {
	RetryCount        int    `toml:"retryCount" json:"retry_count,omitempty"`
	Mode              string `toml:"mode" json:"mode,omitempty"`
	FailBackIntervial string `toml:"failBackIntervial" json:"fail_back_intervial,omitempty"`
}

type ClientHttpServer struct {
	Url   string `toml:"url" json:"url,omitempty"`
	Token string `toml:"token" json:"token,omitempty"`
}

// type ClientGRPCServer struct {
// 	Secure bool   `toml:"secure"`
// 	Server string `toml:"server"`
// 	Token  string `toml:"token"`
// }

type ClientCertification struct {
	Name          string   `toml:"name" json:"name,omitempty"`
	SavePath      string   `toml:"savePath" json:"save_path,omitempty"`
	Domains       []string `toml:"domains" json:"domains,omitempty"`
	ReloadCommand string   `toml:"reloadCommand" json:"reload_command,omitempty"`
}

func (c *ClientCertification) GetFullChainAndKeyPath() (fullchain, key string) {
	fullchain = path.Join(c.SavePath, fmt.Sprintf("%s.pem", c.Name))
	key = path.Join(c.SavePath, fmt.Sprintf("%s.key", c.Name))
	return
}

func (c *ClientConfigT) SetDefault() {
	c.Server = ClientServerConfig{
		RetryCount:        5,
		Mode:              "http",
		FailBackIntervial: "10m",
	}
}
