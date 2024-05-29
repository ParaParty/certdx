package main

import (
	"log"
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/server"
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
		log.Fatal("[ERR] Email, kid and hmac are required")
	}
	provider := "google"
	if *testAccount {
		provider = "googletest"
	}
	err := server.RegisterAccount(provider, *email, *keyId, *hmac)
	if err != nil {
		log.Printf("[ERR] Failed registering account: %s", err)
	}
}
