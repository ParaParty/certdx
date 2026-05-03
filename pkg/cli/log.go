package cli

import "pkg.para.party/certdx/pkg/logging"

// LogConfig captures the logging-related flags every certdx binary
// accepts.
type LogConfig struct {
	// Path is the optional log-file destination. Empty means stderr-only.
	Path string
	// Debug enables debug-level log output.
	Debug bool
}

// Bootstrap configures the global logger from CLI flags. It is a thin
// shim over pkg/logging so callers do not need to remember the order
// or whether SetLogFile or SetDebug runs first.
func Bootstrap(c LogConfig) {
	logging.SetLogFile(c.Path)
	logging.SetDebug(c.Debug)
}
