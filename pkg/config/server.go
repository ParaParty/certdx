package config

import (
	"fmt"
	"time"

	"google.golang.org/appengine"
	"pkg.para.party/certdx/pkg/acmeprovider"
)

type ServerConfig struct {
	ACME ACMEConfig `toml:"ACME" json:"acme,omitempty"`

	GoogleCloudCredential GoogleCloudCredential `toml:"GoogleCloudCredential" json:"google_cloud_credential,omitempty"`

	DnsProvider  *DnsProvider  `toml:"DnsProvider" json:"dns_provider,omitempty"`
	HttpProvider *HttpProvider `toml:"HttpProvider" json:"http_provider,omitempty"`

	HttpServer    HttpServerConfig `toml:"HttpServer" json:"http_server,omitempty"`
	GRPCSDSServer GRPCServerConfig `toml:"gRPCSDSServer" json:"grpc_sds_server,omitempty"`
}

func (c *ServerConfig) Validate() error {
	ret := appengine.MultiError{}

	if err := c.ACME.Validate(); err != nil {
		ret = append(ret, err)
	}

	switch c.ACME.ChallengeType {
	case ChallengeTypeDns01:
		if c.DnsProvider != nil {
			if err := c.DnsProvider.Validate(); err != nil {
				ret = append(ret, err)
			}
		} else {
			ret = append(ret, fmt.Errorf("no dns provider"))
		}
	case ChallengeTypeHttp01:
		if c.HttpProvider != nil {
			if err := c.HttpProvider.Validate(); err != nil {
				ret = append(ret, err)
			}
		} else {
			ret = append(ret, fmt.Errorf("no http provider"))
		}
	default:
	}

	if err := c.parseDuration(); err != nil {
		ret = append(ret, err)
	}

	if err := c.HttpServer.Validate(); err != nil {
		ret = append(ret, err)
	}

	if err := c.GRPCSDSServer.Validate(); err != nil {
		ret = append(ret, err)
	}

	if len(ret) > 0 {
		return ret
	}
	return nil
}

func (c *ServerConfig) parseDuration() error {
	var err error
	c.ACME.CertLifeTimeDuration, err = time.ParseDuration(c.ACME.CertLifeTime)
	if err != nil {
		return fmt.Errorf("can not parse CertLifeTime: %s", err)
	}

	c.ACME.RenewTimeLeftDuration, err = time.ParseDuration(c.ACME.RenewTimeLeft)
	if err != nil {
		return fmt.Errorf("can not parse RenewTimeLeft: %s", err)
	}

	return nil
}

type ACMEConfig struct {
	ChallengeType  string   `toml:"challengeType" json:"challenge_type,omitempty"`
	Email          string   `toml:"email" json:"email,omitempty"`
	Provider       string   `toml:"provider" json:"provider,omitempty"`
	RetryCount     int      `toml:"retryCount" json:"retry_count,omitempty"`
	CertLifeTime   string   `toml:"certLifeTime" json:"cert_life_time,omitempty"`
	RenewTimeLeft  string   `toml:"renewTimeLeft" json:"renew_time_left,omitempty"`
	AllowedDomains []string `toml:"allowedDomains" json:"allowed_domains,omitempty"`

	CertLifeTimeDuration  time.Duration `toml:"-" json:"-"`
	RenewTimeLeftDuration time.Duration `toml:"-" json:"-"`
}

func (c *ACMEConfig) Validate() error {
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("AllowedDomains is empty")
	}

	if c.ChallengeType == "" {
		return fmt.Errorf("challenge type is empty")
	}

	if c.ChallengeType != ChallengeTypeDns01 && c.ChallengeType != ChallengeTypeHttp01 {
		return fmt.Errorf("challenge type: %s not supported", c.ChallengeType)
	}

	if !acmeprovider.ACMEProviderSupported(c.Provider) {
		return fmt.Errorf("ACME provider not supported: %s", c.Provider)
	}

	return nil
}

type GoogleCloudCredential map[string]string

type DnsProvider struct {
	Type                                  string `toml:"type" json:"type,omitempty"`
	DisableCompletePropagationRequirement bool   `toml:"disableCompletePropagationRequirement" json:"disable_complete_propagation_requirement,omitempty"`

	// cloudflare global
	Email  string `toml:"email" json:"email,omitempty"`
	APIKey string `toml:"apiKey" json:"api_key,omitempty"`

	// cloudflare zone
	AuthToken string `toml:"authToken" json:"auth_token,omitempty"`
	ZoneToken string `toml:"zoneToken" json:"zone_token,omitempty"`

	// tencentcloud
	SecretID  string `toml:"secretID" json:"secret_id,omitempty"`
	SecretKey string `toml:"secretKey" json:"secret_key,omitempty"`
}

func (p *DnsProvider) Validate() error {
	switch p.Type {
	case DnsProviderTypeCloudflare:
		if (p.Email == "" || p.APIKey == "") && (p.AuthToken == "" || p.ZoneToken == "") {
			return fmt.Errorf("DnsProvider Cloudflare: empty Email or APIKey")
		}
	case DnsProviderTypeTencentCloud:
		if p.SecretID == "" || p.SecretKey == "" {
			return fmt.Errorf("DnsProvider TencentCloud: empty SecretID or SecretKey")
		}
	default:
		return fmt.Errorf("unknown DnsProvider: %s", p.Type)
	}
	return nil
}

type S3Client struct {
	Region          string `toml:"region" json:"region,omitempty"`
	Bucket          string `toml:"bucket" json:"bucket,omitempty"`
	PartitionID     string `toml:"partitionId" json:"partition_id,omitempty"`
	URL             string `toml:"url" json:"url,omitempty"`
	AccessKeyId     string `toml:"accessKeyId" json:"access_key_id,omitempty"`
	AccessKeySecret string `toml:"accessKeySecret" json:"access_key_secret,omitempty"`
	SessionToken    string `toml:"sessionToken" json:"session_token,omitempty"`
}

type HttpProvider struct {
	Type string `toml:"type" json:"type,omitempty"`

	S3    *S3Client `toml:"S3" json:"s3,omitempty"`
	Local *string   `toml:"local" json:"local,omitempty"`
}

func (p *HttpProvider) Validate() error {
	switch p.Type {
	case HttpProviderTypeS3:
		if p.S3 == nil {
			return fmt.Errorf("HttpProvider S3: empty S3")
		}
	// case HttpProviderTypeLocal:
	// 	if p.Local == nil {
	// 		return fmt.Errorf("HttpProvider Local: empty Local")
	// 	}
	default:
		return fmt.Errorf("unknown HttpProvider: %s", p.Type)
	}
	return nil
}

type HttpServerConfig struct {
	Enabled    bool     `toml:"enabled" json:"enabled,omitempty"`
	Listen     string   `toml:"listen" json:"listen,omitempty"`
	APIPath    string   `toml:"apiPath" json:"api_path,omitempty"`
	AuthMethod string   `toml:"authMethod" json:"authMethod,omitempty"`
	Secure     bool     `toml:"secure" json:"secure,omitempty"`
	Names      []string `toml:"names" json:"names,omitempty"`
	Token      string   `toml:"token" json:"token,omitempty"`
}

func (c *HttpServerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Secure && len(c.Names) == 0 {
		return fmt.Errorf("secure http server with no name")
	}

	return nil
}

type GRPCServerConfig struct {
	Enabled bool     `toml:"enabled" json:"enabled,omitempty"`
	Listen  string   `toml:"listen" json:"listen,omitempty"`
	Names   []string `toml:"names" json:"names,omitempty"`
}

func (c *GRPCServerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if len(c.Names) == 0 {
		return fmt.Errorf("no grpc server name")
	}
	return nil
}

func (c *ServerConfig) SetDefault() {
	c.ACME = ACMEConfig{
		ChallengeType:         "dns",
		RetryCount:            5,
		RenewTimeLeft:         "24h",
		CertLifeTime:          "168h",
		RenewTimeLeftDuration: 24 * time.Hour,
		CertLifeTimeDuration:  168 * time.Hour,
	}

	c.HttpServer = HttpServerConfig{
		Enabled: false,
		Listen:  ":10001",
		APIPath: "/",
		Secure:  false,
	}

	c.GRPCSDSServer = GRPCServerConfig{
		Enabled: false,
		Listen:  ":10002",
	}
}
