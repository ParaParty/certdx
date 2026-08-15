package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

// decodeSample loads a shipped sample from config/ the same way
// cli.LoadTOML does (SetDefault first, then decode over it) and reports
// every key the sample sets that no config struct field claims.
func decodeSample(t *testing.T, name string, target interface{ SetDefault() }) {
	t.Helper()

	target.SetDefault()
	b, err := os.ReadFile(filepath.Join("..", "..", "config", name))
	if err != nil {
		t.Fatalf("read sample %s: %v", name, err)
	}
	meta, err := toml.Decode(string(b), target)
	if err != nil {
		t.Fatalf("parse sample %s: %v", name, err)
	}
	for _, key := range meta.Undecoded() {
		t.Errorf("sample %s sets unknown key %q", name, key)
	}
}

// TestSampleServerConfigs guards the shipped server samples against
// drifting away from the config structs and the validation rules. The
// _full sample documents every knob, including mutually exclusive ones,
// so only the minimal sample is expected to validate as-is.
func TestSampleServerConfigs(t *testing.T) {
	for _, name := range []string{"server_config.toml", "server_config_full.toml"} {
		t.Run(name, func(t *testing.T) {
			decodeSample(t, name, &ServerConfig{})
		})
	}

	t.Run("server_config.toml validates", func(t *testing.T) {
		c := &ServerConfig{}
		decodeSample(t, "server_config.toml", c)
		if err := c.Validate(); err != nil {
			t.Errorf("sample server_config.toml does not validate: %v", err)
		}
	})
}

// TestS3ACLTOMLDecoding pins how the acl key decodes, since the whole
// backward-compat story rests on it: an absent acl stays nil (and resolves to
// the historical public-read), acl = "" is an explicit opt-out of the header.
func TestS3ACLTOMLDecoding(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"absent", "bucket = \"b\"\n", DefaultS3ACL},
		{"explicit empty", "bucket = \"b\"\nacl = \"\"\n", ""},
		{"explicit value", "bucket = \"b\"\nacl = \"private\"\n", "private"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s3 S3Client
			if _, err := toml.Decode(tc.body, &s3); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := s3.ResolvedACL(); got != tc.want {
				t.Errorf("ResolvedACL() = %q want %q", got, tc.want)
			}
		})
	}
}

// TestSampleClientConfigs does the same for the client samples.
func TestSampleClientConfigs(t *testing.T) {
	for _, name := range []string{"client_config.toml", "client_config_full.toml"} {
		t.Run(name, func(t *testing.T) {
			decodeSample(t, name, &ClientConfig{})
		})
	}

	t.Run("client_config.toml validates", func(t *testing.T) {
		c := &ClientConfig{}
		decodeSample(t, "client_config.toml", c)
		if err := c.Validate(nil); err != nil {
			t.Errorf("sample client_config.toml does not validate: %v", err)
		}
	})
}
