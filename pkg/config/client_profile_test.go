package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeClientTOML(t *testing.T, c *ClientConfig, body string) toml.MetaData {
	t.Helper()
	md, err := toml.Decode(body, c)
	if err != nil {
		t.Fatalf("decode toml: %v", err)
	}
	return md
}

func TestClientProfilesValidateEmpty(t *testing.T) {
	var p ClientProfiles
	if err := p.Validate(); err != nil {
		t.Fatalf("empty profiles should validate: %v", err)
	}
}

func TestTencentCloudProfileValidate(t *testing.T) {
	cases := []struct {
		name string
		p    TencentCloudProfile
		want string
	}{
		{"no name", TencentCloudProfile{SecretID: "id", SecretKey: "key"}, "has no name"},
		{"no secretID", TencentCloudProfile{Name: "prod", SecretKey: "key"}, "secretID and secretKey"},
		{"no secretKey", TencentCloudProfile{Name: "prod", SecretID: "id"}, "secretID and secretKey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error wording drifted: %v", err)
			}
		})
	}

	ok := TencentCloudProfile{Name: "prod", SecretID: "id", SecretKey: "key"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
}

func TestKubernetesProfileValidate(t *testing.T) {
	if err := (&KubernetesProfile{}).Validate(); err == nil {
		t.Fatal("expected error on missing name")
	}

	// Empty kubeConfig is valid: it means in-cluster.
	if err := (&KubernetesProfile{Name: "cluster-a"}).Validate(); err != nil {
		t.Fatalf("in-cluster profile rejected: %v", err)
	}

	missing := &KubernetesProfile{Name: "cluster-a", KubeConfig: filepath.Join(t.TempDir(), "nope")}
	err := missing.Validate()
	if err == nil {
		t.Fatal("expected error on missing kubeconfig file")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("error wording drifted: %v", err)
	}

	present := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(present, []byte("apiVersion: v1"), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	if err := (&KubernetesProfile{Name: "cluster-a", KubeConfig: present}).Validate(); err != nil {
		t.Fatalf("existing kubeconfig rejected: %v", err)
	}
}

func TestClientProfilesRejectDuplicateNames(t *testing.T) {
	p := ClientProfiles{
		TencentCloud: []TencentCloudProfile{
			{Name: "prod", SecretID: "id", SecretKey: "key"},
			{Name: "prod", SecretID: "id2", SecretKey: "key2"},
		},
		Kubernetes: []KubernetesProfile{
			{Name: "cluster-a"},
			{Name: "cluster-a"},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected duplicate name errors")
	}
	if !strings.Contains(err.Error(), "duplicated tencentCloud profile name: prod") {
		t.Errorf("missing tencentCloud duplicate error: %v", err)
	}
	if !strings.Contains(err.Error(), "duplicated kubernetes profile name: cluster-a") {
		t.Errorf("missing kubernetes duplicate error: %v", err)
	}
}

// Names are scoped per profile type, so the same name in both lists is fine.
func TestClientProfilesNamesAreScopedPerType(t *testing.T) {
	p := ClientProfiles{
		TencentCloud: []TencentCloudProfile{{Name: "shared", SecretID: "id", SecretKey: "key"}},
		Kubernetes:   []KubernetesProfile{{Name: "shared"}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("same name across types should be allowed: %v", err)
	}
}

func TestClientConfigFindProfile(t *testing.T) {
	c := &ClientConfig{}
	c.Profiles = ClientProfiles{
		TencentCloud: []TencentCloudProfile{
			{Name: "prod", SecretID: "id", SecretKey: "key"},
			{Name: "staging", SecretID: "id2", SecretKey: "key2"},
		},
		Kubernetes: []KubernetesProfile{{Name: "cluster-a", KubeConfig: "/tmp/kubeconfig"}},
	}

	got, ok := c.FindTencentCloudProfile("staging")
	if !ok || got.SecretID != "id2" {
		t.Fatalf("FindTencentCloudProfile returned %+v %v", got, ok)
	}
	if _, ok := c.FindTencentCloudProfile("nope"); ok {
		t.Fatal("expected miss for unknown tencentCloud profile")
	}

	k, ok := c.FindKubernetesProfile("cluster-a")
	if !ok || k.KubeConfig != "/tmp/kubeconfig" {
		t.Fatalf("FindKubernetesProfile returned %+v %v", k, ok)
	}
	if _, ok := c.FindKubernetesProfile("nope"); ok {
		t.Fatal("expected miss for unknown kubernetes profile")
	}
}

func TestClientConfigDecodesProfileSection(t *testing.T) {
	c := &ClientConfig{}
	c.SetDefault()
	decodeClientTOML(t, c, `
[[Profile.TencentCloud]]
name = "prod"
secretID = "id"
secretKey = "key"

[[Profile.Kubernetes]]
name = "cluster-a"
kubeConfig = ""
`)

	if len(c.Profiles.TencentCloud) != 1 || c.Profiles.TencentCloud[0].Name != "prod" {
		t.Fatalf("tencentCloud profiles decoded as %+v", c.Profiles.TencentCloud)
	}
	if len(c.Profiles.Kubernetes) != 1 || c.Profiles.Kubernetes[0].Name != "cluster-a" {
		t.Fatalf("kubernetes profiles decoded as %+v", c.Profiles.Kubernetes)
	}
}
