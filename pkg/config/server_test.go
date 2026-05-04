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
