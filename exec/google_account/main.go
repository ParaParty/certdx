package main

import (
	"certdx/common"
	"log"

	flag "github.com/spf13/pflag"
)

var (
	test  = flag.Bool("test", false, "Register google cloud acme test account")
	email = flag.String("email", "", "Email of registeration")
	keyId = flag.String("kid", "", "Key id of eab")
	hmac  = flag.String("hmac", "", "B64HMAC of eab")
)

func main() {
	flag.Parse()
	if *email == "" || *keyId == "" || *hmac == "" {
		log.Fatal("[ERR] Email or kid or hmac should not be empty")
	}
	provider := "google"
	if *test {
		provider = "googletest"
	}
	err := common.RegisterAccount(provider, *email, *keyId, *hmac)
	if err != nil {
		log.Printf("[ERR] Failed registering account: %s", err)
	}
}
