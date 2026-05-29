package tasks

import (
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/paths"
)

// dataDirEnv is the env-var fallback for --data-dir.
const dataDirEnv = "CERTDX_DATA_DIR"

// registerDataDirFlag adds --data-dir to fs and returns a pointer to its
// value.
func registerDataDirFlag(fs *flag.FlagSet) *string {
	return fs.String("data-dir", "",
		"Data directory for mtls/, private/, cache.json (env: "+dataDirEnv+")")
}

// applyDataDir applies the resolved --data-dir value (flag wins, env
// fallback) to the paths package. Call after flag parsing and before any
// path lookup.
func applyDataDir(flagValue string) {
	dir := flagValue
	if dir == "" {
		dir = os.Getenv(dataDirEnv)
	}
	if dir != "" {
		paths.SetDataDir(dir)
	}
}
