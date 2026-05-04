package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
