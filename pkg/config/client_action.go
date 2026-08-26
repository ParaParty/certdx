package config

import (
	"errors"
	"fmt"
	"path"
	"slices"

	"github.com/BurntSushi/toml"
)

// UpdateActionConfig is one entry of a certificate's [[Certificate.UpdateAction]]
// list. Concrete types are selected by the `type` key at decode time.
type UpdateActionConfig interface {
	ActionType() string
	Validate(c *ClientConfig) error
}

// DecodeActions resolves every certificate's raw update action tables into
// concrete config structs. It must run after the TOML file is decoded and
// before Validate, and it needs the metadata returned by cli.LoadTOMLMeta.
func (c *ClientConfig) DecodeActions(md toml.MetaData) error {
	var ret []error

	for i := range c.Certificates {
		cert := &c.Certificates[i]
		cert.Actions = make([]UpdateActionConfig, 0, len(cert.RawActions))

		for j := range cert.RawActions {
			action, err := decodeAction(md, cert.RawActions[j])
			if err != nil {
				ret = append(ret, fmt.Errorf("certificate %s: update action #%d: %w", cert.Name, j+1, err))
				continue
			}
			cert.Actions = append(cert.Actions, action)
		}
	}

	ret = append(ret, undecodedProfileKeys(md)...)

	return errors.Join(ret...)
}

func decodeAction(md toml.MetaData, raw toml.Primitive) (UpdateActionConfig, error) {
	var probe struct {
		Type string `toml:"type"`
	}
	if err := md.PrimitiveDecode(raw, &probe); err != nil {
		return nil, err
	}

	var action UpdateActionConfig
	switch probe.Type {
	case "":
		return nil, fmt.Errorf("no type set")
	case UPDATE_ACTION_FILE:
		action = &FileAction{}
	case UPDATE_ACTION_TENCENT_CLOUD:
		action = &TencentCloudAction{}
	case UPDATE_ACTION_KUBERNETES:
		action = &KubernetesAction{}
	default:
		return nil, fmt.Errorf("unsupported type: %s", probe.Type)
	}

	if err := md.PrimitiveDecode(raw, action); err != nil {
		return nil, err
	}
	return action, nil
}

// undecodedProfileKeys reports [Profile.*] sub-tables that matched no known
// profile type. They would otherwise be dropped without a word.
func undecodedProfileKeys(md toml.MetaData) []error {
	var ret []error
	seen := make(map[string]struct{})

	for _, key := range md.Undecoded() {
		if len(key) < 2 || key[0] != "Profile" {
			continue
		}
		if _, dup := seen[key[1]]; dup {
			continue
		}
		seen[key[1]] = struct{}{}
		ret = append(ret, fmt.Errorf("unsupported profile type: %s", key[1]))
	}
	return ret
}

// FileAction writes the certificate to disk and optionally runs a reload command.
type FileAction struct {
	SavePath      string `toml:"savePath" json:"save_path,omitempty"`
	ReloadCommand string `toml:"reloadCommand" json:"reload_command,omitempty"`
}

func (a *FileAction) ActionType() string {
	return UPDATE_ACTION_FILE
}

func (a *FileAction) Validate(_ *ClientConfig) error {
	if a.SavePath == "" {
		return fmt.Errorf("file update action: savePath is empty")
	}
	return nil
}

func (a *FileAction) GetFullChainAndKeyPath(certName string) (fullchain, key string, err error) {
	if len(a.SavePath) == 0 || len(certName) == 0 {
		return "", "", fmt.Errorf("empty save path")
	}
	fullchain = path.Join(a.SavePath, fmt.Sprintf("%s.pem", certName))
	key = path.Join(a.SavePath, fmt.Sprintf("%s.key", certName))
	return
}

// TencentCloudResourceTypes lists the resource types accepted by the Tencent
// Cloud SSL UpdateCertificateInstance API.
var TencentCloudResourceTypes = []string{
	"clb", "cdn", "waf", "live", "vod", "ddos", "tke", "apigateway", "tcb", "teo",
}

type ResourceTypeRegions struct {
	ResourceType string   `toml:"resourceType" json:"resource_type,omitempty"`
	Regions      []string `toml:"regions" json:"regions,omitempty"`
}

// TencentCloudAction re-binds expiring Tencent Cloud certificates to the
// newly issued one.
type TencentCloudAction struct {
	Profile              string                `toml:"profile" json:"profile,omitempty"`
	ResourceTypes        []string              `toml:"resourceTypes" json:"resource_types,omitempty"`
	ResourceTypesRegions []ResourceTypeRegions `toml:"resourceTypesRegions" json:"resource_types_regions,omitempty"`
}

func (a *TencentCloudAction) ActionType() string {
	return UPDATE_ACTION_TENCENT_CLOUD
}

func (a *TencentCloudAction) Validate(c *ClientConfig) error {
	var ret []error

	if a.Profile == "" {
		ret = append(ret, fmt.Errorf("tencentCloud update action: profile is empty"))
	} else if _, ok := c.FindTencentCloudProfile(a.Profile); !ok {
		ret = append(ret, fmt.Errorf("tencentCloud update action: no such profile: %s", a.Profile))
	}

	if len(a.ResourceTypes) == 0 {
		ret = append(ret, fmt.Errorf("tencentCloud update action: resourceTypes is empty"))
	}

	for _, it := range a.ResourceTypes {
		if !slices.Contains(TencentCloudResourceTypes, it) {
			ret = append(ret, fmt.Errorf("tencentCloud update action: unsupported resource type: %s", it))
		}
	}

	for _, it := range a.ResourceTypesRegions {
		if !slices.Contains(a.ResourceTypes, it.ResourceType) {
			ret = append(ret, fmt.Errorf(
				"tencentCloud update action: resourceTypesRegions entry %q is not listed in resourceTypes", it.ResourceType))
		}
	}

	return errors.Join(ret...)
}

// KubernetesAction patches annotated kubernetes.io/tls secrets in place.
type KubernetesAction struct {
	Profile string `toml:"profile" json:"profile,omitempty"`
}

func (a *KubernetesAction) ActionType() string {
	return UPDATE_ACTION_KUBERNETES
}

func (a *KubernetesAction) Validate(c *ClientConfig) error {
	if a.Profile == "" {
		return fmt.Errorf("kubernetes update action: profile is empty")
	}
	if _, ok := c.FindKubernetesProfile(a.Profile); !ok {
		return fmt.Errorf("kubernetes update action: no such profile: %s", a.Profile)
	}
	return nil
}
