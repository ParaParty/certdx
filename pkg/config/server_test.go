package config

import (
	"strings"
	"testing"
)

func TestACMEConfigValidateEmptyAllowedDomains(t *testing.T) {
	c := &ACMEConfig{}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error on empty AllowedDomains")
	}
	if !strings.Contains(err.Error(), "AllowedDomains is empty") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestACMEConfigValidateMockSkipsChallenge(t *testing.T) {
	c := &ACMEConfig{
		Provider:       "mock",
		AllowedDomains: []string{"example.com"},
		// ChallengeType deliberately left empty — mock should skip the
		// challenge-type check.
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("mock provider with empty challenge type should validate: %v", err)
	}
}

func TestACMEConfigValidateMissingChallengeType(t *testing.T) {
	c := &ACMEConfig{
		Provider:       "r3test",
		AllowedDomains: []string{"example.com"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error on missing challenge type for non-mock provider")
	}
	if !strings.Contains(err.Error(), "challenge type is empty") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestClientCertificationValidateRequiresFields(t *testing.T) {
	options := makeValidatingConfiguration()

	cases := []struct {
		name string
		c    ClientCertification
	}{
		{"no domains", ClientCertification{Name: "x", SavePath: "/tmp"}},
		{"no name", ClientCertification{Domains: []string{"example.com"}, SavePath: "/tmp"}},
		{"no save path", ClientCertification{Name: "x", Domains: []string{"example.com"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Validate(options); err == nil {
				t.Fatalf("expected validation error for %+v", tc.c)
			}
		})
	}
}

func TestClientCertificationAcceptEmptySavePath(t *testing.T) {
	options := makeValidatingConfiguration()
	WithAcceptEmptyCertificateSavePath(true)(options)

	c := &ClientCertification{Name: "x", Domains: []string{"example.com"}}
	if err := c.Validate(options); err != nil {
		t.Fatalf("expected validation OK with empty SavePath when option set: %v", err)
	}
}

func TestClientCertificationGetFullChainAndKeyPath(t *testing.T) {
	c := &ClientCertification{Name: "site", SavePath: "/var/lib/certs"}
	full, key, err := c.GetFullChainAndKeyPath()
	if err != nil {
		t.Fatalf("GetFullChainAndKeyPath: %v", err)
	}
	if full != "/var/lib/certs/site.pem" {
		t.Errorf("fullchain path: got %s", full)
	}
	if key != "/var/lib/certs/site.key" {
		t.Errorf("key path: got %s", key)
	}
}

func TestClientCertificationGetFullChainAndKeyPathEmpty(t *testing.T) {
	c := &ClientCertification{}
	_, _, err := c.GetFullChainAndKeyPath()
	if err == nil {
		t.Fatal("expected error on empty save path")
	}
}

func TestDnsProviderValidateCloudflareGlobal(t *testing.T) {
	p := &DnsProvider{Type: DnsProviderTypeCloudflare, Email: "a@b.com", APIKey: "key"}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid cloudflare global: %v", err)
	}
}

func TestDnsProviderValidateCloudflareZone(t *testing.T) {
	p := &DnsProvider{Type: DnsProviderTypeCloudflare, AuthToken: "tok", ZoneToken: "zone"}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid cloudflare zone: %v", err)
	}
}

func TestDnsProviderValidateCloudflareEmpty(t *testing.T) {
	p := &DnsProvider{Type: DnsProviderTypeCloudflare}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on empty cloudflare credentials")
	}
	if !strings.Contains(err.Error(), "Cloudflare") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestDnsProviderValidateTencentCloudValid(t *testing.T) {
	p := &DnsProvider{Type: DnsProviderTypeTencentCloud, SecretID: "id", SecretKey: "key"}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid tencentcloud: %v", err)
	}
}

func TestDnsProviderValidateTencentCloudEmpty(t *testing.T) {
	p := &DnsProvider{Type: DnsProviderTypeTencentCloud}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on empty tencentcloud credentials")
	}
	if !strings.Contains(err.Error(), "TencentCloud") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestDnsProviderValidateUnknownType(t *testing.T) {
	p := &DnsProvider{Type: "route53"}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on unknown dns provider type")
	}
	if !strings.Contains(err.Error(), "unknown DnsProvider") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestHttpProviderValidateS3Nil(t *testing.T) {
	p := &HttpProvider{Type: HttpProviderTypeS3, S3: nil}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on nil S3 config")
	}
	if !strings.Contains(err.Error(), "empty S3") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestHttpProviderValidateS3Valid(t *testing.T) {
	p := &HttpProvider{Type: HttpProviderTypeS3, S3: &S3Client{}}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid s3 provider: %v", err)
	}
}

func TestHttpProviderValidateUnknownType(t *testing.T) {
	p := &HttpProvider{Type: "gcs"}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on unknown http provider type")
	}
	if !strings.Contains(err.Error(), "unknown HttpProvider") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestHttpServerConfigValidateDisabled(t *testing.T) {
	c := &HttpServerConfig{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled http server should skip validation: %v", err)
	}
}

func TestHttpServerConfigValidateAPIPathAutoPrefix(t *testing.T) {
	c := &HttpServerConfig{Enabled: true, APIPath: "api/cert"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.APIPath != "/api/cert" {
		t.Errorf("APIPath not prefixed: got %s want /api/cert", c.APIPath)
	}
}

func TestHttpServerConfigValidateSecureNoNames(t *testing.T) {
	c := &HttpServerConfig{Enabled: true, APIPath: "/", Secure: true, Names: nil}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error on secure http server with no names")
	}
	if !strings.Contains(err.Error(), "no name") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestGRPCServerConfigValidateDisabled(t *testing.T) {
	c := &GRPCServerConfig{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled grpc server should skip validation: %v", err)
	}
}

func TestServerConfigParseDurationInvalidCertLifeTime(t *testing.T) {
	c := &ServerConfig{}
	c.SetDefault()
	c.ACME.CertLifeTime = "bad"
	err := c.parseDuration()
	if err == nil {
		t.Fatal("expected error on invalid CertLifeTime")
	}
	if !strings.Contains(err.Error(), "CertLifeTime") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestServerConfigParseDurationInvalidRenewTimeLeft(t *testing.T) {
	c := &ServerConfig{}
	c.SetDefault()
	c.ACME.CertLifeTime = "168h"
	c.ACME.RenewTimeLeft = "bad"
	err := c.parseDuration()
	if err == nil {
		t.Fatal("expected error on invalid RenewTimeLeft")
	}
	if !strings.Contains(err.Error(), "RenewTimeLeft") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestACMEConfigValidateUnsupportedChallengeType(t *testing.T) {
	c := &ACMEConfig{
		Provider:       "r3test",
		AllowedDomains: []string{"example.com"},
		ChallengeType:  "tls-alpn",
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error on unsupported challenge type")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestServerConfigSetDefault(t *testing.T) {
	c := &ServerConfig{}
	c.SetDefault()

	if c.ACME.RetryCount != 5 {
		t.Errorf("default retryCount: got %d want 5", c.ACME.RetryCount)
	}
	if c.ACME.ChallengeType != "dns" {
		t.Errorf("default challengeType: got %s want dns", c.ACME.ChallengeType)
	}
	if !c.HttpServer.Enabled == true {
		// disabled by default
	}
	if c.HttpServer.Listen != ":10001" {
		t.Errorf("default http listen: got %s want :10001", c.HttpServer.Listen)
	}
	if c.GRPCSDSServer.Listen != ":10002" {
		t.Errorf("default grpc listen: got %s want :10002", c.GRPCSDSServer.Listen)
	}
}
