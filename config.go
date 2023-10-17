package main

type ServerConfig struct {
	ACME ACME `toml:"ACME"`

	Cloudflare struct {
		Email  string `toml:"email"`
		APIKey string `toml:"apiKey"`
	} `toml:"Cloudflare"`

	HttpServer HttpServerConfig `toml:"HttpServer"`
}

type ACME struct {
	ACMEServer     string `toml:"acmeServer"`
	RetryCount     int    `toml:"retryCount"`
	CertLifeTime   string `toml:"certLifeTime"`
	RenewTimeLeft  string `toml:"renewTimeLeft"`
	ForceWildcards bool   `toml:"forceWildcards"`

	AllowedDomains []string `toml:"allowedDomains"`
}

type HttpServerConfig struct {
	Port    int    `toml:"port"`
	APIPath string `toml:"apiPath"`
	Secure  bool   `toml:"secure"`
	Name    string `toml:"name"`
	Token   string `toml:"token"`
}

// type GRpcServerConfig struct {
// 	Port   int    `toml:"port"`
// 	Secure bool   `toml:"secure"`
// 	Name   string `toml:"name"`
// 	Token  string `toml:"token"`
// }

type ClientConfig struct {
}

type ClientServerConfig struct {
	RetryCount int    `toml:"retryCount"`
	Mode       string `toml:"mode"`

	Http struct {
		MainServer    ClientHttpServer `toml:"MainServer"`
		StandbyServer ClientHttpServer `toml:"StandbyServer"`
	} `toml:"Http"`

	// GRpc struct {
	// 	MainServer    ClientGRpcServer `toml:"MainServer"`
	// 	StandbyServer ClientGRpcServer `toml:"StandbyServer"`
	// } `toml:"GRpc"`

	Certification ClientCertification `toml:"Certification"`
}

type ClientHttpServer struct {
	ServerUrl string `toml:"serverUrl"`
	Token     string `toml:"token"`
}

// type ClientGRpcServer struct {
// 	Secure bool   `toml:"secure"`
// 	Server string `toml:"server"`
// 	Token  string `toml:"token"`
// }

type ClientCertification struct {
	SavePath      string   `toml:"savePath"`
	Domains       []string `toml:"domains"`
	ReloadCommand string   `toml:"reloadCommand"`
}
