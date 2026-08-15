package config

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"pkg.para.party/certdx/pkg/acme/acmeproviders"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
)

// providerMaxCertLifeTime is the longest validity the known ACME providers
// will issue. Let's Encrypt and Google Trust Services both cap at 90 days;
// asking for more yields a cert that really expires long before the server
// thinks it does.
const providerMaxCertLifeTime = 90 * 24 * time.Hour

type ServerConfig struct {
	ACME ACMEConfig `toml:"ACME" json:"acme,omitempty"`

	GoogleCloudCredential GoogleCloudCredential `toml:"GoogleCloudCredential" json:"google_cloud_credential,omitempty"`

	DnsProvider  *DnsProvider  `toml:"DnsProvider" json:"dns_provider,omitempty"`
	HttpProvider *HttpProvider `toml:"HttpProvider" json:"http_provider,omitempty"`

	MTLS          MTLSConfig       `toml:"MTLS" json:"mtls,omitempty"`
	HttpServer    HttpServerConfig `toml:"HttpServer" json:"http_server,omitempty"`
	GRPCSDSServer GRPCServerConfig `toml:"gRPCSDSServer" json:"grpc_sds_server,omitempty"`
}

func (c *ServerConfig) Validate() error {
	var ret []error

	if err := c.ACME.Validate(); err != nil {
		ret = append(ret, err)
	}

	// The mock provider is hermetic and does not require any DNS/HTTP
	// challenge provider configuration.
	if !acmeproviders.IsMock(c.ACME.Provider) {
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

	if c.needsMTLS() {
		if err := c.MTLS.Validate(); err != nil {
			ret = append(ret, err)
		}
	}

	return errors.Join(ret...)
}

func (c *ServerConfig) parseDuration() error {
	var err error
	c.ACME.CertLifeTimeDuration, err = time.ParseDuration(c.ACME.CertLifeTime)
	if err != nil {
		return fmt.Errorf("can not parse CertLifeTime: %w", err)
	}

	c.ACME.RenewTimeLeftDuration, err = time.ParseDuration(c.ACME.RenewTimeLeft)
	if err != nil {
		return fmt.Errorf("can not parse RenewTimeLeft: %w", err)
	}

	if c.ACME.CertLifeTimeDuration <= 0 {
		return fmt.Errorf("CertLifeTime must be positive, got %q", c.ACME.CertLifeTime)
	}

	if c.ACME.RenewTimeLeftDuration <= 0 {
		return fmt.Errorf("RenewTimeLeft must be positive, got %q", c.ACME.RenewTimeLeft)
	}

	// RenewTimeLeft == CertLifeTime is the "renew at half life" setup and is
	// perfectly fine; only a renew window longer than the life time is
	// pathological (the cert would be due for renewal before it is issued).
	if c.ACME.RenewTimeLeftDuration > c.ACME.CertLifeTimeDuration {
		return fmt.Errorf("RenewTimeLeft (%q) must not be longer than CertLifeTime (%q)",
			c.ACME.RenewTimeLeft, c.ACME.CertLifeTime)
	}

	// A cert is requested to stay valid for CertLifeTime + RenewTimeLeft.
	//
	// Only Google's ACME gets that sum put on the wire as the order's
	// NotAfter (see acme.needNotAfter), so asking for more than the provider
	// maximum there is a hard order failure and is rejected here. Every other
	// provider ignores the requested lifetime entirely: the server takes what
	// it is given and clamps ValidBefore against the issued leaf's real
	// NotAfter, so an over-long CertLifeTime self-corrects at runtime. That
	// configuration has always loaded, so it stays a warning.
	if acmeproviders.Supported(c.ACME.Provider) && !acmeproviders.IsMock(c.ACME.Provider) {
		if total := c.ACME.CertLifeTimeDuration + c.ACME.RenewTimeLeftDuration; total > providerMaxCertLifeTime {
			if acmeproviders.IsGoogle(c.ACME.Provider) {
				return fmt.Errorf("CertLifeTime (%q) + RenewTimeLeft (%q) is %s, longer than the %s ACME provider %q can issue",
					c.ACME.CertLifeTime, c.ACME.RenewTimeLeft, total, providerMaxCertLifeTime, c.ACME.Provider)
			}
			logging.Warn("CertLifeTime (%q) + RenewTimeLeft (%q) is %s, longer than the %s ACME provider %q can issue; "+
				"certificates will be renewed on their real expiry instead",
				c.ACME.CertLifeTime, c.ACME.RenewTimeLeft, total, providerMaxCertLifeTime, c.ACME.Provider)
		}
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

	// MaxCacheEntries caps the number of distinct cert packs the cert cache
	// keeps. Zero (the default) means unlimited.
	MaxCacheEntries int `toml:"maxCacheEntries" json:"max_cache_entries,omitempty"`

	CertLifeTimeDuration  time.Duration `toml:"-" json:"-"`
	RenewTimeLeftDuration time.Duration `toml:"-" json:"-"`
}

func (c *ACMEConfig) Validate() error {
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("AllowedDomains is empty")
	}

	if c.MaxCacheEntries < 0 {
		return fmt.Errorf("MaxCacheEntries must not be negative, got %d", c.MaxCacheEntries)
	}

	if acmeproviders.IsMock(c.Provider) {
		// Mock provider skips ACME-specific validation entirely.
		return nil
	}

	if c.ChallengeType == "" {
		return fmt.Errorf("challenge type is empty")
	}

	if c.ChallengeType != ChallengeTypeDns01 && c.ChallengeType != ChallengeTypeHttp01 {
		return fmt.Errorf("challenge type: %s not supported", c.ChallengeType)
	}

	if !acmeproviders.Supported(c.Provider) {
		return fmt.Errorf("ACME provider not supported: %s", c.Provider)
	}

	return nil
}

type GoogleCloudCredential map[string]string

type DnsProvider struct {
	Type                                  string `toml:"type" json:"type,omitempty"`
	DisableCompletePropagationRequirement bool   `toml:"disableCompletePropagationRequirement" json:"disable_complete_propagation_requirement,omitempty"`

	// DNS propagation check settings
	Nameservers []string `toml:"nameservers" json:"nameservers,omitempty"`
	DNSTimeout  string   `toml:"dnsTimeout" json:"dns_timeout,omitempty"`

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
	if p.DNSTimeout != "" {
		timeout, err := time.ParseDuration(p.DNSTimeout)
		if err != nil {
			return fmt.Errorf("DnsProvider: invalid dnsTimeout %q: %w", p.DNSTimeout, err)
		}
		if timeout <= 0 {
			return fmt.Errorf("DnsProvider: dnsTimeout must be positive, got %q", p.DNSTimeout)
		}
	}
	for _, ns := range p.Nameservers {
		if err := validateNameserver(ns); err != nil {
			return fmt.Errorf("DnsProvider: %w", err)
		}
	}
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
		return fmt.Errorf("unknown DnsProvider: %s, expected one of: %s, %s",
			p.Type, DnsProviderTypeCloudflare, DnsProviderTypeTencentCloud)
	}
	return nil
}

// validateNameserver checks that a recursive nameserver entry is a plain
// host[:port] pair, the shape lego's dns01.ParseNameservers expects. The port
// defaults to 53 when omitted, exactly as lego does.
func validateNameserver(ns string) error {
	if ns == "" {
		return fmt.Errorf("nameserver is empty")
	}
	if strings.ContainsAny(ns, " \t\r\n") {
		return fmt.Errorf("nameserver %q contains whitespace", ns)
	}
	if strings.Contains(ns, "://") || strings.Contains(ns, "/") {
		return fmt.Errorf("nameserver %q must be host[:port], not a URL", ns)
	}

	host, port, err := net.SplitHostPort(ns)
	if err != nil {
		// No port given: default to 53 the same way lego does, and re-check.
		host, port, err = net.SplitHostPort(net.JoinHostPort(ns, "53"))
		if err != nil {
			return fmt.Errorf("nameserver %q is not a valid host[:port]: %w", ns, err)
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("nameserver %q has invalid port %q", ns, port)
	}

	if net.ParseIP(host) == nil && !isHostname(host) {
		return fmt.Errorf("nameserver %q has invalid host %q", ns, host)
	}

	return nil
}

// isHostname reports whether s looks like a DNS hostname: dot separated
// alphanumeric-or-hyphen labels, optionally with a trailing root dot.
func isHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			switch {
			// '_' is not legal in a hostname per RFC 1123, but it is common in
			// AD/legacy internal DNS names and both miekg/dns and lego query
			// such names happily, so it is accepted here.
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}

type S3Client struct {
	Region          string `toml:"region" json:"region,omitempty"`
	Bucket          string `toml:"bucket" json:"bucket,omitempty"`
	PartitionID     string `toml:"partitionId" json:"partition_id,omitempty"`
	URL             string `toml:"url" json:"url,omitempty"`
	AccessKeyId     string `toml:"accessKeyId" json:"access_key_id,omitempty"`
	AccessKeySecret string `toml:"accessKeySecret" json:"access_key_secret,omitempty"`
	SessionToken    string `toml:"sessionToken" json:"session_token,omitempty"`

	// ACL is the canned ACL sent with the challenge object. It is a pointer
	// so that "unset" and "explicitly empty" are distinguishable:
	//
	//   - unset (nil): send [DefaultS3ACL], the ACL certdx has hardcoded
	//     since v0.6.0. Existing ACL-based buckets keep working untouched.
	//   - acl = "": send no ACL header at all, the only thing buckets with
	//     ACLs disabled (the default since Apr 2023) accept.
	//   - any other value: sent as-is.
	ACL *string `toml:"acl" json:"acl,omitempty"`
}

// DefaultS3ACL is the canned ACL sent when [S3Client.ACL] is not set at all.
// certdx up to v0.6.0 hardcoded it, so leaving acl out of the config must
// keep producing publicly readable challenge objects.
const DefaultS3ACL = "public-read"

// ResolvedACL returns the canned ACL to send with the challenge object. An
// empty return means "send no ACL header".
func (c *S3Client) ResolvedACL() string {
	if c == nil || c.ACL == nil {
		return DefaultS3ACL
	}
	return *c.ACL
}

// s3CannedACLs is the set of AWS canned object ACLs accepted in
// [S3Client.ACL]. The empty string (send no ACL) is handled separately.
var s3CannedACLs = []string{
	"private",
	"public-read",
	"public-read-write",
	"authenticated-read",
	"aws-exec-read",
	"bucket-owner-read",
	"bucket-owner-full-control",
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
		if p.S3.Bucket == "" || p.S3.URL == "" {
			return fmt.Errorf("HttpProvider S3: empty bucket or url")
		}
		if p.S3.AccessKeyId == "" || p.S3.AccessKeySecret == "" {
			return fmt.Errorf("HttpProvider S3: empty accessKeyId or accessKeySecret")
		}
		// acl unset keeps the historical default; acl = "" is the explicit
		// "send no ACL header" opt-out. Anything else has to be a real canned
		// ACL or S3 rejects the PutObject at challenge time.
		if acl := p.S3.ACL; acl != nil && *acl != "" && !slices.Contains(s3CannedACLs, *acl) {
			return fmt.Errorf("HttpProvider S3: unknown acl %q, expect one of %v or empty", *acl, s3CannedACLs)
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

	// AllowAnonymous makes an empty token an explicit choice: without it an
	// enabled token-auth server with no token is rejected.
	AllowAnonymous bool `toml:"allowAnonymous" json:"allow_anonymous,omitempty"`
	// AllowInsecureToken silences the warning about serving the token and the
	// private keys over plain HTTP.
	AllowInsecureToken bool `toml:"allowInsecureToken" json:"allow_insecure_token,omitempty"`
}

func (c *HttpServerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if !strings.HasPrefix(c.APIPath, "/") {
		c.APIPath = fmt.Sprintf("/%s", c.APIPath)
	}

	if c.Secure && len(c.Names) == 0 {
		return fmt.Errorf("secure http server with no name")
	}

	switch c.AuthMethod {
	case HTTP_AUTH_TOKEN:
		if c.Token == "" && !c.AllowAnonymous {
			return fmt.Errorf("[HttpServer] authMethod = %q with an empty token serves certificates to anyone, "+
				"set token, or set allowAnonymous = true if that is intended", HTTP_AUTH_TOKEN)
		}
		if !c.Secure && !c.AllowInsecureToken {
			logging.Warn("!!! [HttpServer] authMethod = %q with secure = false serves the token AND the private keys "+
				"in cleartext. Set secure = true (or put the server behind TLS), "+
				"or set allowInsecureToken = true to silence this warning !!!", HTTP_AUTH_TOKEN)
		}
	case HTTP_AUTH_MTLS:
	default:
		return fmt.Errorf("[HttpServer] unknown authMethod: %q, expected %q or %q",
			c.AuthMethod, HTTP_AUTH_TOKEN, HTTP_AUTH_MTLS)
	}

	return nil
}

type GRPCServerConfig struct {
	Enabled bool   `toml:"enabled" json:"enabled,omitempty"`
	Listen  string `toml:"listen" json:"listen,omitempty"`
}

func (c *GRPCServerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	return nil
}

type MTLSConfig struct {
	PEM string `toml:"pem" json:"pem,omitempty"`
}

func (c *MTLSConfig) Validate() error {
	if c.PEM == "" {
		return fmt.Errorf("[MTLS] pem is required when using mTLS or gRPC SDS")
	}
	if !paths.FileExists(c.PEM) {
		return fmt.Errorf("[MTLS] file not found: %s", c.PEM)
	}
	return nil
}

func (c *ServerConfig) needsMTLS() bool {
	if c.GRPCSDSServer.Enabled {
		return true
	}
	if c.HttpServer.Enabled && c.HttpServer.AuthMethod == HTTP_AUTH_MTLS {
		return true
	}
	return false
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
		Enabled:    false,
		Listen:     ":10001",
		APIPath:    "/",
		AuthMethod: HTTP_AUTH_TOKEN,
		Secure:     false,
	}

	c.GRPCSDSServer = GRPCServerConfig{
		Enabled: false,
		Listen:  ":10002",
	}
}
