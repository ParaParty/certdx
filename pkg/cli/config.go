package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"

	"pkg.para.party/certdx/pkg/logging"
)

// LoadTOML reads a TOML file at path and unmarshals it into target.
// Wraps every step's error with the file path so the caller can log a
// single line and exit. Logs an info message on success.
//
// target must be a non-nil pointer to a struct (or any other type
// supported by the TOML decoder).
func LoadTOML(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	if err := toml.Unmarshal(b, target); err != nil {
		return fmt.Errorf("parse config %q: %w", path, err)
	}
	logging.Info("Config loaded from %s", path)
	return nil
}
