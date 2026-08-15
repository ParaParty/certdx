package config

import (
	"strings"
	"testing"
	"time"
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

func TestDnsProviderValidateDNSTimeout(t *testing.T) {
	base := DnsProvider{Type: DnsProviderTypeCloudflare, Email: "a@b.com", APIKey: "key"}

	for _, valid := range []string{"", "30s", "1m30s"} {
		p := base
		p.DNSTimeout = valid
		if err := p.Validate(); err != nil {
			t.Fatalf("valid dnsTimeout %q: %v", valid, err)
		}
	}

	for _, invalid := range []string{"30", "abc", "0s", "-5s"} {
		p := base
		p.DNSTimeout = invalid
		err := p.Validate()
		if err == nil {
			t.Fatalf("expected error on dnsTimeout %q", invalid)
		}
		if !strings.Contains(err.Error(), "dnsTimeout") {
			t.Fatalf("error wording drifted: %v", err)
		}
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
	p := &HttpProvider{Type: HttpProviderTypeS3, S3: validS3Client()}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid s3 provider: %v", err)
	}
}

func validS3Client() *S3Client {
	return &S3Client{
		Bucket:          "cos-1000000000",
		URL:             "https://cos.ap-beijing.myqcloud.com",
		AccessKeyId:     "id",
		AccessKeySecret: "secret",
	}
}

func TestHttpProviderValidateS3MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*S3Client)
		wantMsg string
	}{
		{"no bucket", func(s *S3Client) { s.Bucket = "" }, "empty bucket or url"},
		{"no url", func(s *S3Client) { s.URL = "" }, "empty bucket or url"},
		{"no access key id", func(s *S3Client) { s.AccessKeyId = "" }, "empty accessKeyId or accessKeySecret"},
		{"no access key secret", func(s *S3Client) { s.AccessKeySecret = "" }, "empty accessKeyId or accessKeySecret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3 := validS3Client()
			tc.mutate(s3)
			p := &HttpProvider{Type: HttpProviderTypeS3, S3: s3}
			err := p.Validate()
			if err == nil {
				t.Fatal("expected error on incomplete S3 config")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error wording drifted: %v", err)
			}
		})
	}
}

// TestS3ClientResolvedACL locks the backward-compatible ACL semantics: an
// absent acl key keeps sending the "public-read" certdx <= v0.6.0 hardcoded,
// while an explicit empty acl opts out of the header entirely.
func TestS3ClientResolvedACL(t *testing.T) {
	empty := ""
	private := "private"

	cases := []struct {
		name string
		s3   *S3Client
		want string
	}{
		{"unset keeps the historical public-read", &S3Client{}, DefaultS3ACL},
		{"explicit empty sends no ACL", &S3Client{ACL: &empty}, ""},
		{"explicit value is passed through", &S3Client{ACL: &private}, "private"},
		{"nil receiver keeps the historical public-read", nil, DefaultS3ACL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s3.ResolvedACL(); got != tc.want {
				t.Errorf("ResolvedACL() = %q want %q", got, tc.want)
			}
		})
	}
}

func TestHttpProviderValidateS3ACL(t *testing.T) {
	valid := []*string{nil, ptr(""), ptr("public-read"), ptr("private"), ptr("bucket-owner-full-control")}
	for _, acl := range valid {
		s3 := validS3Client()
		s3.ACL = acl
		p := &HttpProvider{Type: HttpProviderTypeS3, S3: s3}
		if err := p.Validate(); err != nil {
			t.Fatalf("acl %v should validate: %v", acl, err)
		}
	}

	s3 := validS3Client()
	s3.ACL = ptr("public_read")
	p := &HttpProvider{Type: HttpProviderTypeS3, S3: s3}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error on unknown canned acl")
	}
	if !strings.Contains(err.Error(), "unknown acl") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestDnsProviderValidateNameservers(t *testing.T) {
	base := DnsProvider{Type: DnsProviderTypeCloudflare, Email: "a@b.com", APIKey: "key"}

	valid := [][]string{
		nil,
		{"8.8.8.8:53"},
		{"1.1.1.1"},
		{"dns.example.com:5353"},
		{"[2001:4860:4860::8888]:53"},
		{"2001:4860:4860::8888"},
		// Underscore labels are illegal per RFC 1123 but common in AD /
		// legacy internal DNS, and lego/miekg resolve them fine.
		{"_dns.internal.example.com"},
		{"ad_dc1.corp.example.com:53"},
	}
	for _, ns := range valid {
		p := base
		p.Nameservers = ns
		if err := p.Validate(); err != nil {
			t.Fatalf("valid nameservers %v: %v", ns, err)
		}
	}

	invalid := []string{
		"",
		"https://8.8.8.8",
		"8.8.8.8:53 ",
		"8.8.8.8 1.1.1.1",
		"8.8.8.8:dns",
		"8.8.8.8:0",
		"8.8.8.8:99999",
		"8.8.8.8:53/resolve",
		"-bad-.example.com",
	}
	for _, ns := range invalid {
		p := base
		p.Nameservers = []string{ns}
		err := p.Validate()
		if err == nil {
			t.Fatalf("expected error on nameserver %q", ns)
		}
		if !strings.Contains(err.Error(), "nameserver") {
			t.Fatalf("error wording drifted for %q: %v", ns, err)
		}
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
	c := &HttpServerConfig{Enabled: true, APIPath: "api/cert", AuthMethod: HTTP_AUTH_TOKEN, Token: "t"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.APIPath != "/api/cert" {
		t.Errorf("APIPath not prefixed: got %s want /api/cert", c.APIPath)
	}
}

func TestHttpServerConfigValidateAuthMethod(t *testing.T) {
	cases := []struct {
		name    string
		c       HttpServerConfig
		wantErr string
	}{
		{"empty", HttpServerConfig{Enabled: true, APIPath: "/", Token: "t"}, "unknown authMethod"},
		{"typo", HttpServerConfig{Enabled: true, APIPath: "/", AuthMethod: "tokne", Token: "t"}, "unknown authMethod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if err == nil {
				t.Fatal("expected error on bad authMethod")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error wording drifted: %v", err)
			}
		})
	}

	ok := &HttpServerConfig{Enabled: true, APIPath: "/", AuthMethod: HTTP_AUTH_MTLS}
	if err := ok.Validate(); err != nil {
		t.Fatalf("mtls auth method should validate: %v", err)
	}
}

func TestHttpServerConfigValidateEmptyToken(t *testing.T) {
	c := &HttpServerConfig{Enabled: true, APIPath: "/", AuthMethod: HTTP_AUTH_TOKEN}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error on token auth with empty token")
	}
	if !strings.Contains(err.Error(), "allowAnonymous") {
		t.Fatalf("error wording drifted: %v", err)
	}

	c.AllowAnonymous = true
	if err := c.Validate(); err != nil {
		t.Fatalf("empty token with allowAnonymous should validate: %v", err)
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

func TestServerConfigParseDurationRejectsNonPositive(t *testing.T) {
	cases := []struct {
		name          string
		certLifeTime  string
		renewTimeLeft string
		wantMsg       string
	}{
		{"zero life time", "0s", "24h", "CertLifeTime must be positive"},
		{"negative life time", "-168h", "24h", "CertLifeTime must be positive"},
		{"zero renew time", "168h", "0s", "RenewTimeLeft must be positive"},
		{"negative renew time", "168h", "-1h", "RenewTimeLeft must be positive"},
		{"renew longer than life time", "24h", "168h", "must not be longer than CertLifeTime"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &ServerConfig{}
			c.SetDefault()
			c.ACME.Provider = "r3"
			c.ACME.CertLifeTime = tc.certLifeTime
			c.ACME.RenewTimeLeft = tc.renewTimeLeft
			err := c.parseDuration()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error wording drifted: %v", err)
			}
		})
	}
}

// TestServerConfigParseDurationRenewEqualsCertLifeTime pins the "renew at half
// life" setup (certLifeTime == renewTimeLeft): the cert is asked to live twice
// certLifeTime and is renewed halfway through. Only renewTimeLeft strictly
// longer than certLifeTime is rejected.
func TestServerConfigParseDurationRenewEqualsCertLifeTime(t *testing.T) {
	c := &ServerConfig{}
	c.SetDefault()
	c.ACME.Provider = "r3"
	c.ACME.CertLifeTime = "720h"
	c.ACME.RenewTimeLeft = "720h"
	if err := c.parseDuration(); err != nil {
		t.Fatalf("renewTimeLeft == certLifeTime should be accepted: %v", err)
	}
}

func TestServerConfigParseDurationProviderMaxLifeTime(t *testing.T) {
	c := &ServerConfig{}
	c.SetDefault()
	c.ACME.Provider = "google"
	// 90d total is exactly the provider maximum.
	c.ACME.CertLifeTime = "2136h"
	c.ACME.RenewTimeLeft = "24h"
	if err := c.parseDuration(); err != nil {
		t.Fatalf("90d total should be accepted: %v", err)
	}

	c.ACME.CertLifeTime = "2137h"
	err := c.parseDuration()
	if err == nil {
		t.Fatal("expected error on cert life time beyond provider maximum")
	}
	if !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("error wording drifted: %v", err)
	}

	// The mock provider mints its own certs, so the cap does not apply.
	c.ACME.Provider = "mock"
	c.ACME.CertLifeTime = "8760h"
	if err := c.parseDuration(); err != nil {
		t.Fatalf("mock provider should not be capped: %v", err)
	}
}

// TestServerConfigParseDurationLongLifeTimeNonGoogle locks the backward-compat
// fix: only Google gets the requested NotAfter on the wire, so an over-long
// certLifeTime against Let's Encrypt keeps loading (the server clamps
// ValidBefore against the issued leaf's real NotAfter at runtime).
func TestServerConfigParseDurationLongLifeTimeNonGoogle(t *testing.T) {
	for _, provider := range []string{"r3", "r3test"} {
		t.Run(provider, func(t *testing.T) {
			c := &ServerConfig{}
			c.SetDefault()
			c.ACME.Provider = provider
			c.ACME.CertLifeTime = "8760h"
			c.ACME.RenewTimeLeft = "168h"
			if err := c.parseDuration(); err != nil {
				t.Fatalf("non-google provider should not be hard-capped: %v", err)
			}
			if c.ACME.CertLifeTimeDuration != 8760*time.Hour {
				t.Errorf("CertLifeTimeDuration: got %s", c.ACME.CertLifeTimeDuration)
			}
		})
	}

	// googletest is Google too, and must stay a hard error.
	c := &ServerConfig{}
	c.SetDefault()
	c.ACME.Provider = "googletest"
	c.ACME.CertLifeTime = "8760h"
	c.ACME.RenewTimeLeft = "168h"
	if err := c.parseDuration(); err == nil {
		t.Fatal("expected googletest to reject an over-long cert life time")
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
	if c.HttpServer.AuthMethod != HTTP_AUTH_TOKEN {
		t.Errorf("default http authMethod: got %s want %s", c.HttpServer.AuthMethod, HTTP_AUTH_TOKEN)
	}
}
