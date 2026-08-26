package config

import (
	"strings"
	"testing"
)

func decodeAndResolve(t *testing.T, body string) (*ClientConfig, error) {
	t.Helper()
	c := &ClientConfig{}
	c.SetDefault()
	md := decodeClientTOML(t, c, body)
	return c, c.DecodeActions(md)
}

func TestDecodeActionsConcreteTypes(t *testing.T) {
	c, err := decodeAndResolve(t, `
[[Certificate]]
name = "web"
domains = ["*.example.com"]

[[Certificate.UpdateAction]]
type = "file"
savePath = "/etc/certdx"
reloadCommand = "systemctl reload nginx"

[[Certificate.UpdateAction]]
type = "tencentCloud"
profile = "prod"
resourceTypes = ["teo", "cdn"]
resourceTypesRegions = [{ resourceType = "teo", regions = ["ap-guangzhou"] }]

[[Certificate.UpdateAction]]
type = "kubernetes"
profile = "cluster-a"
`)
	if err != nil {
		t.Fatalf("DecodeActions: %v", err)
	}

	actions := c.Certificates[0].Actions
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(actions))
	}

	file, ok := actions[0].(*FileAction)
	if !ok {
		t.Fatalf("action 0 is %T", actions[0])
	}
	if file.SavePath != "/etc/certdx" || file.ReloadCommand != "systemctl reload nginx" {
		t.Fatalf("file action decoded as %+v", file)
	}

	txc, ok := actions[1].(*TencentCloudAction)
	if !ok {
		t.Fatalf("action 1 is %T", actions[1])
	}
	if txc.Profile != "prod" || len(txc.ResourceTypes) != 2 {
		t.Fatalf("tencentCloud action decoded as %+v", txc)
	}
	if len(txc.ResourceTypesRegions) != 1 || txc.ResourceTypesRegions[0].ResourceType != "teo" {
		t.Fatalf("resourceTypesRegions decoded as %+v", txc.ResourceTypesRegions)
	}

	if _, ok := actions[2].(*KubernetesAction); !ok {
		t.Fatalf("action 2 is %T", actions[2])
	}
}

func TestDecodeActionsRejectsUnknownType(t *testing.T) {
	_, err := decodeAndResolve(t, `
[[Certificate]]
name = "web"
domains = ["*.example.com"]

[[Certificate.UpdateAction]]
type = "azureKeyVault"
`)
	if err == nil {
		t.Fatal("expected error on unknown action type")
	}
	if !strings.Contains(err.Error(), "unsupported type: azureKeyVault") {
		t.Fatalf("error wording drifted: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate web: update action #1") {
		t.Fatalf("error should locate the action: %v", err)
	}
}

func TestDecodeActionsRejectsMissingType(t *testing.T) {
	_, err := decodeAndResolve(t, `
[[Certificate]]
name = "web"
domains = ["*.example.com"]

[[Certificate.UpdateAction]]
savePath = "/etc/certdx"
`)
	if err == nil {
		t.Fatal("expected error on missing action type")
	}
	if !strings.Contains(err.Error(), "no type set") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestDecodeActionsRejectsUnknownProfileType(t *testing.T) {
	_, err := decodeAndResolve(t, `
[[Profile.AzureKeyVault]]
name = "prod"
`)
	if err == nil {
		t.Fatal("expected error on unknown profile type")
	}
	if !strings.Contains(err.Error(), "unsupported profile type: AzureKeyVault") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestFileActionValidate(t *testing.T) {
	if err := (&FileAction{}).Validate(nil); err == nil {
		t.Fatal("expected error on empty savePath")
	}
	if err := (&FileAction{SavePath: "/etc/certdx"}).Validate(nil); err != nil {
		t.Fatalf("valid file action rejected: %v", err)
	}
}

func TestFileActionGetFullChainAndKeyPath(t *testing.T) {
	a := &FileAction{SavePath: "/var/lib/certs"}
	fullchain, key, err := a.GetFullChainAndKeyPath("site")
	if err != nil {
		t.Fatalf("GetFullChainAndKeyPath: %v", err)
	}
	if fullchain != "/var/lib/certs/site.pem" || key != "/var/lib/certs/site.key" {
		t.Fatalf("unexpected paths: %s %s", fullchain, key)
	}

	if _, _, err := a.GetFullChainAndKeyPath(""); err == nil {
		t.Fatal("expected error on empty cert name")
	}
	if _, _, err := (&FileAction{}).GetFullChainAndKeyPath("site"); err == nil {
		t.Fatal("expected error on empty save path")
	}
}

func TestTencentCloudActionValidate(t *testing.T) {
	c := &ClientConfig{}
	c.Profiles.TencentCloud = []TencentCloudProfile{{Name: "prod", SecretID: "id", SecretKey: "key"}}

	cases := []struct {
		name string
		a    TencentCloudAction
		want string
	}{
		{"no profile", TencentCloudAction{ResourceTypes: []string{"teo"}}, "profile is empty"},
		{"dangling profile", TencentCloudAction{Profile: "nope", ResourceTypes: []string{"teo"}}, "no such profile: nope"},
		{"no resource types", TencentCloudAction{Profile: "prod"}, "resourceTypes is empty"},
		{"bad resource type", TencentCloudAction{Profile: "prod", ResourceTypes: []string{"s3"}}, "unsupported resource type: s3"},
		{
			"region for unlisted type",
			TencentCloudAction{
				Profile:              "prod",
				ResourceTypes:        []string{"teo"},
				ResourceTypesRegions: []ResourceTypeRegions{{ResourceType: "clb", Regions: []string{"ap-guangzhou"}}},
			},
			"is not listed in resourceTypes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.a.Validate(c)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error wording drifted: %v", err)
			}
		})
	}

	ok := TencentCloudAction{
		Profile:              "prod",
		ResourceTypes:        []string{"teo", "clb"},
		ResourceTypesRegions: []ResourceTypeRegions{{ResourceType: "clb", Regions: []string{"ap-guangzhou"}}},
	}
	if err := ok.Validate(c); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
}

func TestKubernetesActionValidate(t *testing.T) {
	c := &ClientConfig{}
	c.Profiles.Kubernetes = []KubernetesProfile{{Name: "cluster-a"}}

	if err := (&KubernetesAction{}).Validate(c); err == nil {
		t.Fatal("expected error on empty profile")
	}

	err := (&KubernetesAction{Profile: "nope"}).Validate(c)
	if err == nil {
		t.Fatal("expected error on dangling profile")
	}
	if !strings.Contains(err.Error(), "no such profile: nope") {
		t.Fatalf("error wording drifted: %v", err)
	}

	if err := (&KubernetesAction{Profile: "cluster-a"}).Validate(c); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
}

func TestClientConfigValidateReportsActionErrors(t *testing.T) {
	c, err := decodeAndResolve(t, `
[Http.MainServer]
url = "https://example.com"

[[Certificate]]
name = "web"
savePath = "/tmp"
domains = ["*.example.com"]

[[Certificate.UpdateAction]]
type = "kubernetes"
profile = "missing"
`)
	if err != nil {
		t.Fatalf("DecodeActions: %v", err)
	}

	err = c.Validate(nil)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "certificate web: kubernetes update action: no such profile: missing") {
		t.Fatalf("error wording drifted: %v", err)
	}
}
