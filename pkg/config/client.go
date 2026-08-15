package config

import (
	"errors"
	"fmt"
	"path"
	"time"

	"pkg.para.party/certdx/pkg/domain"
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

	Certifications []ClientCertification `toml:"Certifications" json:"certifications,omitempty"`
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

	if len(c.Certifications) == 0 && !option.acceptEmptyCertificatesList {
		ret = append(ret, fmt.Errorf("no certification configured"))
	}

	// A certification name is only a global identifier in gRPC/SDS mode, where
	// it is the SDS resource name on the wire (pkg/client/sds.go guards this
	// again at runtime). In HTTP mode the on-disk identity is savePath + name
	// and the daemon keys its watch map on the domain set, so the same name
	// under two different savePaths is a perfectly good config and has always
	// loaded. Only an identical savePath + name pair is a real collision
	// there: both entries would write the same .pem/.key files.
	grpcMode := c.Common.Mode == CLIENT_MODE_GRPC
	seenNames := make(map[string]struct{}, len(c.Certifications))
	seenDomains := make(map[domain.Key]string, len(c.Certifications))
	for _, cert := range c.Certifications {
		if err := cert.Validate(option); err != nil {
			ret = append(ret, err)
			continue
		}

		if nameKey, dupErr := certNameKey(cert, grpcMode); nameKey != "" {
			if _, ok := seenNames[nameKey]; ok {
				ret = append(ret, dupErr)
			} else {
				seenNames[nameKey] = struct{}{}
			}
		}

		// Two certifications over the same domain set would race each other
		// writing the same cert, so they have to be merged in the config.
		key := domain.AsKey(cert.Domains)
		if first, ok := seenDomains[key]; ok {
			ret = append(ret, fmt.Errorf("certification %s duplicates the domain set of %s: %v",
				cert.Name, first, cert.Domains))
		} else {
			seenDomains[key] = cert.Name
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

// certNameKey returns the uniqueness key for one certification's name, plus
// the error to report when that key repeats. An empty key means the name has
// no identity worth checking here (non-gRPC mode with no savePath, e.g. an
// embedder that never writes files).
func certNameKey(cert ClientCertification, grpcMode bool) (string, error) {
	if grpcMode {
		return cert.Name, fmt.Errorf("duplicate certification name: %s", cert.Name)
	}
	if cert.SavePath == "" {
		return "", nil
	}
	return cert.SavePath + "\x00" + cert.Name,
		fmt.Errorf("duplicate certification name: %s under savePath %s", cert.Name, cert.SavePath)
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
