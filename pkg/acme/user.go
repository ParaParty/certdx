package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"pkg.para.party/certdx/pkg/acme/google"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/utils"
)

type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}
func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func parsePEM(pem []byte) (crypto.PrivateKey, error) {
	key, err := certcrypto.ParsePEMPrivateKey(pem)
	if err != nil {
		panic(err)
	}

	return key, nil
}

func makeACMEUser(c *config.ServerConfigT) (*ACMEUser, error) {
	keyPath, err := utils.GetACMEPrivateKeySavePath(c.ACME.Email, c.ACME.Provider)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		kid := ""
		hmac := ""

		if isACMEProviderGoogle(c.ACME.Provider) {
			account, err := google.CreateExternalAccountKeyRequest(c.GoogleCloudCredential)
			if err != nil {
				return nil, fmt.Errorf("failed to register google ca: %v", err)
			}
			kid = account.KeyId
			hmac = account.HmacEncoded
		}

		if err := RegisterAccount(c.ACME.Provider, c.ACME.Email, kid, hmac); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	ACMEAccountKey, err := parsePEM(keyFile)
	if err != nil {
		return nil, err
	}

	user := &ACMEUser{
		Email: c.ACME.Email,
		Key:   ACMEAccountKey,
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = acmeProvidersMap[c.ACME.Provider]
	acmeClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed constructing acme client: %w", err)
	}

	user.Registration, err = acmeClient.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, fmt.Errorf("failed resolving account. Is account registered? Error: %w", err)
	}
	return user, nil
}

func RegisterAccount(ACMEProvider, Email, Kid, Hmac string) error {
	keyPath, err := utils.GetACMEPrivateKeySavePath(Email, ACMEProvider)
	if err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("fialed generating key: %s", err)
	}

	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	err = os.WriteFile(keyPath, pemEncoded, 0o600)
	if err != nil {
		return fmt.Errorf("failed saving key: %w", err)
	}

	myUser := ACMEUser{
		Email: Email,
		Key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.CADirURL = acmeProvidersMap[ACMEProvider]

	client, err := lego.NewClient(config)
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed constructing acme client: %w", err)
	}

	if Hmac != "" && Kid != "" {
		var eabOptions = registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  Kid,
			HmacEncoded:          Hmac,
		}
		myUser.Registration, err = client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	} else {
		var regOptions = registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		}
		myUser.Registration, err = client.Registration.Register(regOptions)
	}
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed to register: %s", err)
	}

	reg, err := json.Marshal(myUser.Registration)
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed marshaling registration: %w", err)
	}

	fmt.Println(string(reg))
	return nil
}
