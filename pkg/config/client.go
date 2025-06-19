package config

import (
	"fmt"
	"path"
	"time"

	"google.golang.org/appengine"
	"pkg.para.party/certdx/pkg/utils"
)

type ClientConfig struct {
	Common ClientCommonConfig `toml:"Common" json:"common,omitempty"`

	Http struct {
		MainServer    ClientHttpServer `toml:"MainServer" json:"main_server,omitempty"`
		StandbyServer ClientHttpServer `toml:"StandbyServer" json:"standby_server,omitempty"`
	} `toml:"Http" json:"http,omitempty"`

	GRPC struct {
		MainServer    ClientGRPCServer `toml:"MainServer" json:"main_server,omitempty"`
		StandbyServer ClientGRPCServer `toml:"StandbyServer" json:"standby_server,omitempty"`
	} `toml:"GRPC" json:"GRPC,omitempty"`

	Certifications []ClientCertification `toml:"Certifications" json:"certifications,omitempty"`
}

func (c *ClientConfig) Validate(optionList []ValidatingOption) error {
	option := makeValidatingConfiguration()
	for _, it := range optionList {
		it(option)
	}

	ret := appengine.MultiError{}

	if err := c.parseDuration(); err != nil {
		ret = append(ret, err)
	}

	if len(c.Certifications) == 0 && !option.acceptEmptyCertificatesList {
		ret = append(ret, fmt.Errorf("no certification configured"))
	}

	for _, cert := range c.Certifications {
		if err := cert.Validate(option); err != nil {
			ret = append(ret, err)
		}
	}

	switch c.Common.Mode {
	case CLIENT_MODE_HTTP:
		err := c.validateHttpMode()
		if err != nil {
			ret = append(ret, err)
		}
	case CLIENT_MODE_GRPC:
		err := c.validateGrpcMode()
		if err != nil {
			ret = append(ret, err)
		}
	default:
		ret = append(ret, fmt.Errorf("unsupported mode: %s", c.Common.Mode))
	}

	if len(ret) > 0 {
		return ret
	}
	return nil
}

func (c *ClientConfig) parseDuration() error {
	var err error
	c.Common.ReconnectDuration, err = time.ParseDuration(c.Common.ReconnectInterval)
	if err != nil {
		return fmt.Errorf("can not parse ReconnectInterval: %s", err)
	}
	return nil
}

func (c *ClientConfig) validateHttpMode() error {
	if c.Http.MainServer.Url == "" {
		return fmt.Errorf("http main server url is empty")
	}

	if err := c.Http.MainServer.Validate(); err != nil {
		return err
	}

	if c.Http.StandbyServer.Url != "" {
		if err := c.Http.StandbyServer.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c *ClientConfig) validateGrpcMode() error {
	if c.GRPC.MainServer.Server == "" {
		return fmt.Errorf("grpc main server url is empty")
	}

	if err := c.GRPC.MainServer.Validate(); err != nil {
		return err
	}

	if c.GRPC.StandbyServer.Server != "" {
		if err := c.GRPC.StandbyServer.Validate(); err != nil {
			return err
		}
	}

	return nil
}

type ClientCommonConfig struct {
	RetryCount        int    `toml:"retryCount" json:"retry_count,omitempty"`
	Mode              string `toml:"mode" json:"mode,omitempty"`
	ReconnectInterval string `toml:"reconnectInterval" json:"reconnect_interval,omitempty"`

	ReconnectDuration time.Duration `toml:"-" json:"-"`
}

type ClientMtlsConfig struct {
	CA          string `toml:"ca" json:"ca,omitempty"`
	Certificate string `toml:"certificate" json:"certificate,omitempty"`
	Key         string `toml:"key" json:"key,omitempty"`
}

func (c *ClientMtlsConfig) Validate() error {
	if !utils.FileExists(c.CA) {
		return fmt.Errorf("file not found: %s", c.CA)
	}

	if !utils.FileExists(c.Certificate) {
		return fmt.Errorf("file not found: %s", c.Certificate)
	}

	if !utils.FileExists(c.Key) {
		return fmt.Errorf("file not found: %s", c.Key)
	}

	return nil
}

type ClientHttpServer struct {
	Url        string `toml:"url" json:"url,omitempty"`
	AuthMethod string `toml:"authMethod" json:"authMethod,omitempty"`
	Token      string `toml:"token" json:"token,omitempty"`
	ClientMtlsConfig
}

func (c *ClientHttpServer) Validate() error {
	if c.AuthMethod == HTTP_AUTH_MTLS {
		return c.ClientMtlsConfig.Validate()
	}

	return nil
}

type ClientGRPCServer struct {
	Server string `toml:"server" json:"server,omitempty"`
	ClientMtlsConfig
}

func (c *ClientGRPCServer) Validate() error {
	return c.ClientMtlsConfig.Validate()
}

type ClientCertification struct {
	Name          string   `toml:"name" json:"name,omitempty"`
	SavePath      string   `toml:"savePath" json:"save_path,omitempty"`
	Domains       []string `toml:"domains" json:"domains,omitempty"`
	ReloadCommand string   `toml:"reloadCommand" json:"reload_command,omitempty"`
}

func (c *ClientCertification) Validate(options *validatingConfiguration) error {
	var savePathAccepted = c.SavePath != ""
	if options.acceptEmptyCertificateSavePath && len(c.SavePath) == 0 {
		savePathAccepted = true
	}
	if len(c.Domains) == 0 || c.Name == "" || !savePathAccepted {
		return fmt.Errorf("wrong certification configuration for %s", c.Name)
	}
	return nil
}

func (c *ClientCertification) GetFullChainAndKeyPath() (fullchain, key string, err error) {
	if len(c.SavePath) == 0 || len(c.Name) == 0 {
		return "", "", fmt.Errorf("empty save path")
	}
	fullchain = path.Join(c.SavePath, fmt.Sprintf("%s.pem", c.Name))
	key = path.Join(c.SavePath, fmt.Sprintf("%s.key", c.Name))
	return
}

func (c *ClientConfig) SetDefault() {
	c.Common = ClientCommonConfig{
		RetryCount:        5,
		Mode:              CLIENT_MODE_HTTP,
		ReconnectInterval: "10m",
	}

	c.Http.MainServer.AuthMethod = HTTP_AUTH_TOKEN
	c.Http.StandbyServer.AuthMethod = HTTP_AUTH_TOKEN
}

type validatingConfiguration struct {
	acceptEmptyCertificateSavePath bool
	acceptEmptyCertificatesList    bool
}

func makeValidatingConfiguration() *validatingConfiguration {
	return &validatingConfiguration{
		acceptEmptyCertificateSavePath: false,
		acceptEmptyCertificatesList:    false,
	}
}

type ValidatingOption func(*validatingConfiguration)

func WithAcceptEmptyCertificateSavePath(value bool) ValidatingOption {
	return func(v *validatingConfiguration) {
		v.acceptEmptyCertificateSavePath = value
	}
}

func WithAcceptEmptyCertificatesList(value bool) ValidatingOption {
	return func(v *validatingConfiguration) {
		v.acceptEmptyCertificatesList = value
	}
}
