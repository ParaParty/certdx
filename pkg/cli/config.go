package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"

	"pkg.para.party/certdx/pkg/logging"
)

// LoadTOMLMeta is LoadTOML but also returns the decoder metadata, which
// callers need to resolve toml.Primitive values in a second pass.
func LoadTOMLMeta(path string, target any) (toml.MetaData, error) {
	var md toml.MetaData

	f, err := os.Open(path)
	if err != nil {
		return md, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return md, fmt.Errorf("read config %q: %w", path, err)
	}

	md, err = toml.Decode(string(b), target)
	if err != nil {
		return md, fmt.Errorf("parse config %q: %w", path, err)
	}
	logging.Info("Config loaded from %s", path)
	return md, nil
}

// LoadTOML reads a TOML file at path and unmarshals it into target.
// Wraps every step's error with the file path so the caller can log a
// single line and exit. Logs an info message on success.
//
// target must be a non-nil pointer to a struct (or any other type
// supported by the TOML decoder).
func LoadTOML(path string, target any) error {
	_, err := LoadTOMLMeta(path, target)
	return err
}
