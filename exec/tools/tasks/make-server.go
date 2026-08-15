package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/tools"
)

// MakeServer generates a server certificate signed by the certdx CA.
func MakeServer(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		serverName = fs.StringP("name", "n", "", "Server certificate name (output filename)")
		domains    = fs.StringSliceP("dns-names", "d", []string{}, "Server certificate DNS names (comma-separated)")
		org        = fs.StringP("organization", "o", "CertDX Private", "Subject Organization")
		commonName = fs.StringP("common-name", "c", "CertDX Secret Discovery Service", "Subject Common Name")
		validFor   = fs.Duration("valid-for", tools.DefaultLeafLifetime, "Certificate validity period")
		dataDir    = registerDataDirFlag(fs)
		help       = fs.BoolP("help", "h", false, "Print help")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	if *serverName == "" {
		return fmt.Errorf("--name is required")
	}

	if len(*domains) == 0 {
		return fmt.Errorf("--dns-names is required")
	}

	// tools.WithLifetime silently keeps the default for a non-positive
	// duration, which would hide a typo like "--valid-for -1h" or
	// "--valid-for 0". Reject it here instead.
	if *validFor <= 0 {
		return fmt.Errorf("--valid-for must be positive, got %s", *validFor)
	}

	applyDataDir(*dataDir)

	if err := tools.MakeServerCert(*serverName, *org, *commonName, *domains, tools.WithLifetime(*validFor)); err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}
	return nil
}
