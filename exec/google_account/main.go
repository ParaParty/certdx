package main

import (
	"pkg.para.party/certdx/pkg/server"

	"fmt"
	"log"
	"os"

	flag "github.com/spf13/pflag"
)

var (
	buildCommit string
	buildDate   string
)

var (
	test    = flag.Bool("test", false, "Register google cloud acme test account")
	email   = flag.String("email", "", "Email of registeration")
	keyId   = flag.String("kid", "", "Key id of eab")
	hmac    = flag.String("hmac", "", "B64HMAC of eab")
	help    = flag.BoolP("help", "h", false, "Print help")
	version = flag.BoolP("version", "v", false, "Print version")
)

func main() {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("Certdx google acme acoount register tool %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	if *email == "" || *keyId == "" || *hmac == "" {
		log.Fatal("[ERR] Email or kid or hmac should not be empty")
	}
	provider := "google"
	if *test {
		provider = "googletest"
	}
	err := server.RegisterAccount(provider, *email, *keyId, *hmac)
	if err != nil {
		log.Printf("[ERR] Failed registering account: %s", err)
	}
}
