package main

import (
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/logging"
)

func registerGoogleAccount() {
	var (
		gaCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		testAccount = gaCMD.BoolP("test-account", "t", false, "Register test account")
		email       = gaCMD.StringP("email", "e", "", "Email of registeration")
		keyId       = gaCMD.StringP("kid", "k", "", "Key id of eab")
		hmac        = gaCMD.StringP("hmac", "h", "", "B64HMAC of eab")
		gaHelp      = gaCMD.Bool("help", false, "Print help")
	)
	gaCMD.Parse(os.Args[2:])

	if *gaHelp {
		gaCMD.PrintDefaults()
		os.Exit(0)
	}

	if *email == "" || *keyId == "" || *hmac == "" {
		logging.Fatal("Email, kid and hmac are required")
	}
	provider := "google"
	if *testAccount {
		provider = "googletest"
	}
	err := acme.RegisterAccount(provider, *email, *keyId, *hmac)
	if err != nil {
		logging.Fatal("Failed registering account, err: %s", err)
	}
}
