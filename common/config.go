package common

import "time"

type ServerConfigT struct {
	ACME ACMEConfig `toml:"ACME"`

	Cloudflare struct {
		Email  string `toml:"email"`
		APIKey string `toml:"apiKey"`
	} `toml:"Cloudflare"`

	HttpServer HttpServerConfig `toml:"HttpServer"`
}

type ACMEConfig struct {
	Email         string `toml:"email"`
	Provider      string `toml:"provider"`
	RetryCount    int    `toml:"retryCount"`
	CertLifeTime  string `toml:"certLifeTime"`
	RenewTimeLeft string `toml:"renewTimeLeft"`

	AllowedDomains []string `toml:"allowedDomains"`

	CertLifeTimeDuration  time.Duration `toml:"-"`
	RenewTimeLeftDuration time.Duration `toml:"-"`
}

type HttpServerConfig struct {
	Enabled bool     `toml:"enabled"`
	Listen  string   `toml:"listen"`
	APIPath string   `toml:"apiPath"`
	Secure  bool     `toml:"secure"`
	Names   []string `toml:"names"`
	Token   string   `toml:"token"`
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

type ClientConfigT struct {
	Server ClientServerConfig `toml:"Server"`

	Http struct {
		MainServer    ClientHttpServer `toml:"MainServer"`
		StandbyServer ClientHttpServer `toml:"StandbyServer"`
	} `toml:"Http"`

	// GRPC struct {
	// 	MainServer    ClientGRPCServer `toml:"MainServer"`
	// 	StandbyServer ClientGRPCServer `toml:"StandbyServer"`
	// } `toml:"GRPC"`

	Certifications []ClientCertification `toml:"Certifications"`
}

type ClientServerConfig struct {
	RetryCount        int    `toml:"retryCount"`
	Mode              string `toml:"mode"`
	FailBackIntervial string `toml:"failBackIntervial"`
}

type ClientHttpServer struct {
	Url   string `toml:"url"`
	Token string `toml:"token"`
}

// type ClientGRPCServer struct {
// 	Secure bool   `toml:"secure"`
// 	Server string `toml:"server"`
// 	Token  string `toml:"token"`
// }

type ClientCertification struct {
	Name          string   `toml:"name"`
	SavePath      string   `toml:"savePath"`
	Domains       []string `toml:"domains"`
	ReloadCommand string   `toml:"reloadCommand"`
}

func (c *ClientConfigT) SetDefault() {
	c.Server = ClientServerConfig{
		RetryCount:        5,
		Mode:              "http",
		FailBackIntervial: "10m",
	}
}

var (
	ClientConfig = &ClientConfigT{}
	ServerConfig = &ServerConfigT{}
)
