package tasks

import (
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/tools"
)

// validForFlag is the name of the optional validity override shared by
// make-ca, make-server and make-client.
const validForFlag = "valid-for"

// registerValidForFlag adds --valid-for to fs and returns a pointer to its
// value. Unset, certificates keep the default expiry (2100-01-01).
func registerValidForFlag(fs *flag.FlagSet) *time.Duration {
	return fs.Duration(validForFlag, 0,
		"Certificate validity period, e.g. 17520h (default: valid until 2100-01-01)")
}

// validForOptions turns --valid-for into issuance options. It returns
// none when the flag was not given and rejects an explicit non-positive
// value rather than silently falling back to the default.
func validForOptions(fs *flag.FlagSet, d time.Duration) ([]tools.CertOption, error) {
	if !fs.Changed(validForFlag) {
		return nil, nil
	}
	if d <= 0 {
		return nil, fmt.Errorf("--%s must be positive, got %s", validForFlag, d)
	}
	return []tools.CertOption{tools.WithLifetime(d)}, nil
}
