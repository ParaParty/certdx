package config

import (
	"errors"
	"fmt"
	"path"
	"time"

	"pkg.para.party/certdx/pkg/paths"
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

	Profiles ClientProfiles `toml:"Profile" json:"profiles,omitempty"`

	Certificates []ClientCertificate `toml:"Certificate" json:"certificates,omitempty"`
}

func (c *ClientConfig) Validate(optionList []ValidatingOption) error {
	option := makeValidatingConfiguration()
	for _, it := range optionList {
		it(option)
	}

	var ret []error

	if err := c.parseDuration(); err != nil {
		ret = append(ret, err)
	}

	if err := c.Profiles.Validate(); err != nil {
		ret = append(ret, err)
	}

	if len(c.Certificates) == 0 && !option.acceptEmptyCertificatesList {
		ret = append(ret, fmt.Errorf("no certificate configured"))
	}

	for _, cert := range c.Certificates {
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

	return errors.Join(ret...)
}

func (c *ClientConfig) parseDuration() error {
	var err error
	c.Common.ReconnectDuration, err = time.ParseDuration(c.Common.ReconnectInterval)
	if err != nil {
		return fmt.Errorf("can not parse ReconnectInterval: %w", err)
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
	PEM string `toml:"pem" json:"pem,omitempty"`
}

func (c *ClientMtlsConfig) Validate() error {
	if !paths.FileExists(c.PEM) {
		return fmt.Errorf("file not found: %s", c.PEM)
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

type ClientCertificate struct {
	Name          string   `toml:"name" json:"name,omitempty"`
	SavePath      string   `toml:"savePath" json:"save_path,omitempty"`
	Domains       []string `toml:"domains" json:"domains,omitempty"`
	ReloadCommand string   `toml:"reloadCommand" json:"reload_command,omitempty"`
}

func (c *ClientCertificate) Validate(options *validatingConfiguration) error {
	var savePathAccepted = c.SavePath != ""
	if options.acceptEmptyCertificateSavePath && len(c.SavePath) == 0 {
		savePathAccepted = true
	}
	if len(c.Domains) == 0 || c.Name == "" || !savePathAccepted {
		return fmt.Errorf("wrong certificate configuration for %s", c.Name)
	}
	return nil
}

func (c *ClientCertificate) GetFullChainAndKeyPath() (fullchain, key string, err error) {
	if len(c.SavePath) == 0 || len(c.Name) == 0 {
		return "", "", fmt.Errorf("empty save path")
	}
	fullchain = path.Join(c.SavePath, fmt.Sprintf("%s.pem", c.Name))
	key = path.Join(c.SavePath, fmt.Sprintf("%s.key", c.Name))
	return
}

// ClientProfiles holds the named credential and connection settings that
// update actions reference by name. Names are scoped per profile type.
type ClientProfiles struct {
	TencentCloud []TencentCloudProfile `toml:"TencentCloud" json:"tencent_cloud,omitempty"`
	Kubernetes   []KubernetesProfile   `toml:"Kubernetes" json:"kubernetes,omitempty"`
}

func (p *ClientProfiles) Validate() error {
	var ret []error

	tencentCloudNames := make(map[string]struct{}, len(p.TencentCloud))
	for _, it := range p.TencentCloud {
		if err := it.Validate(); err != nil {
			ret = append(ret, err)
			continue
		}
		if _, dup := tencentCloudNames[it.Name]; dup {
			ret = append(ret, fmt.Errorf("duplicated tencentCloud profile name: %s", it.Name))
			continue
		}
		tencentCloudNames[it.Name] = struct{}{}
	}

	kubernetesNames := make(map[string]struct{}, len(p.Kubernetes))
	for _, it := range p.Kubernetes {
		if err := it.Validate(); err != nil {
			ret = append(ret, err)
			continue
		}
		if _, dup := kubernetesNames[it.Name]; dup {
			ret = append(ret, fmt.Errorf("duplicated kubernetes profile name: %s", it.Name))
			continue
		}
		kubernetesNames[it.Name] = struct{}{}
	}

	return errors.Join(ret...)
}

type TencentCloudProfile struct {
	Name      string `toml:"name" json:"name,omitempty"`
	SecretID  string `toml:"secretID" json:"secret_id,omitempty"`
	SecretKey string `toml:"secretKey" json:"secret_key,omitempty"`
	Endpoint  string `toml:"endpoint" json:"endpoint,omitempty"`
}

func (p *TencentCloudProfile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("tencentCloud profile has no name")
	}
	if p.SecretID == "" || p.SecretKey == "" {
		return fmt.Errorf("tencentCloud profile %s: secretID and secretKey are required", p.Name)
	}
	return nil
}

type KubernetesProfile struct {
	// KubeConfig empty means in-cluster config, then the default client-go chain.
	KubeConfig string `toml:"kubeConfig" json:"kube_config,omitempty"`
	Name       string `toml:"name" json:"name,omitempty"`
}

func (p *KubernetesProfile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("kubernetes profile has no name")
	}
	if p.KubeConfig != "" && !paths.FileExists(p.KubeConfig) {
		return fmt.Errorf("kubernetes profile %s: file not found: %s", p.Name, p.KubeConfig)
	}
	return nil
}

func (c *ClientConfig) FindTencentCloudProfile(name string) (*TencentCloudProfile, bool) {
	for i := range c.Profiles.TencentCloud {
		if c.Profiles.TencentCloud[i].Name == name {
			return &c.Profiles.TencentCloud[i], true
		}
	}
	return nil, false
}

func (c *ClientConfig) FindKubernetesProfile(name string) (*KubernetesProfile, bool) {
	for i := range c.Profiles.Kubernetes {
		if c.Profiles.Kubernetes[i].Name == name {
			return &c.Profiles.Kubernetes[i], true
		}
	}
	return nil, false
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
