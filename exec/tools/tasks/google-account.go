package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/acme"
)

// RegisterGoogleAccount registers (or registers a test) Google ACME
// account using EAB credentials.
func RegisterGoogleAccount(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		testAccount = fs.BoolP("test-account", "t", false, "Register test account")
		email       = fs.StringP("email", "e", "", "Email of registration")
		keyID       = fs.StringP("kid", "k", "", "Key id of EAB")
		hmac        = fs.StringP("hmac", "m", "", "B64HMAC of EAB")
		help        = fs.BoolP("help", "h", false, "Print help")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	if *email == "" || *keyID == "" || *hmac == "" {
		return fmt.Errorf("--email, --kid and --hmac are required")
	}
	provider := "google"
	if *testAccount {
		provider = "googletest"
	}
	if err := acme.RegisterAccount(provider, *email, *keyID, *hmac); err != nil {
		return fmt.Errorf("register account: %w", err)
	}
	return nil
}
