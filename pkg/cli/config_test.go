package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

type sampleConfig struct {
	Name string
	Port int
	Tags []string
}

func writeTempTOML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp toml: %v", err)
	}
	return p
}

func TestLoadTOMLHappyPath(t *testing.T) {
	p := writeTempTOML(t, `
Name = "alpha"
Port = 8443
Tags = ["one", "two"]
`)
	var cfg sampleConfig
	if err := LoadTOML(p, &cfg); err != nil {
		t.Fatalf("LoadTOML: %v", err)
	}
	if cfg.Name != "alpha" || cfg.Port != 8443 || len(cfg.Tags) != 2 {
		t.Fatalf("decoded mismatch: %+v", cfg)
	}
}

func TestLoadTOMLMissingFile(t *testing.T) {
	err := LoadTOML(filepath.Join(t.TempDir(), "does-not-exist.toml"), &sampleConfig{})
	if err == nil {
		t.Fatal("expected error on missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist wrapped, got %v", err)
	}
	if !strings.Contains(err.Error(), "open config") {
		t.Fatalf("error should mention open config, got %v", err)
	}
}

func TestLoadTOMLBadSyntax(t *testing.T) {
	p := writeTempTOML(t, "this = is not = valid toml")
	err := LoadTOML(p, &sampleConfig{})
	if err == nil {
		t.Fatal("expected parse error on bad TOML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("error should mention parse config, got %v", err)
	}
}

func TestLoadTOMLMetaPrimitive(t *testing.T) {
	p := writeTempTOML(t, `
[[Item]]
kind = "a"
value = "first"

[[Item]]
kind = "b"
value = "second"
`)
	var cfg struct {
		Item []toml.Primitive
	}
	md, err := LoadTOMLMeta(p, &cfg)
	if err != nil {
		t.Fatalf("LoadTOMLMeta: %v", err)
	}
	if len(cfg.Item) != 2 {
		t.Fatalf("expected 2 primitives, got %d", len(cfg.Item))
	}

	var kinds []string
	for _, it := range cfg.Item {
		var probe struct {
			Kind string `toml:"kind"`
		}
		if err := md.PrimitiveDecode(it, &probe); err != nil {
			t.Fatalf("PrimitiveDecode: %v", err)
		}
		kinds = append(kinds, probe.Kind)
	}
	if kinds[0] != "a" || kinds[1] != "b" {
		t.Fatalf("unexpected kinds: %v", kinds)
	}
}

func TestLoadTOMLMetaUndecoded(t *testing.T) {
	p := writeTempTOML(t, `
Name = "alpha"
Unexpected = "value"
`)
	var cfg sampleConfig
	md, err := LoadTOMLMeta(p, &cfg)
	if err != nil {
		t.Fatalf("LoadTOMLMeta: %v", err)
	}
	undecoded := md.Undecoded()
	if len(undecoded) != 1 || undecoded[0].String() != "Unexpected" {
		t.Fatalf("expected Unexpected to be undecoded, got %v", undecoded)
	}
}
