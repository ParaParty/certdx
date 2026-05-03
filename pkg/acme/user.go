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
	"pkg.para.party/certdx/pkg/acme/acmeproviders"
	"pkg.para.party/certdx/pkg/acme/acmeproviders/google"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/paths"
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

// parsePEM decodes a PEM-encoded ACME account key. A corrupted file is
// returned as an error rather than crashing the process.
func parsePEM(pem []byte) (crypto.PrivateKey, error) {
	key, err := certcrypto.ParsePEMPrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse ACME account key: %w", err)
	}
	return key, nil
}

func makeACMEUser(c *config.ServerConfig) (*ACMEUser, error) {
	keyPath, err := paths.ACMEPrivateKey(c.ACME.Email, c.ACME.Provider)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		kid := ""
		hmac := ""

		if acmeproviders.IsGoogle(c.ACME.Provider) {
			account, err := google.CreateExternalAccountKeyRequest(c.GoogleCloudCredential)
			if err != nil {
				return nil, fmt.Errorf("failed to register google ca: %w", err)
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
	legoConfig.CADirURL = acmeproviders.URL(c.ACME.Provider)
	acmeClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed constructing acme client: %w", err)
	}

	user.Registration, err = acmeClient.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, fmt.Errorf("resolve ACME account by key (is the account registered?): %w", err)
	}
	return user, nil
}

func RegisterAccount(ACMEProvider, Email, Kid, Hmac string) error {
	keyPath, err := paths.ACMEPrivateKey(Email, ACMEProvider)
	if err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed generating key: %w", err)
	}

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal ACME account key: %w", err)
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	if err := os.WriteFile(keyPath, pemEncoded, 0o600); err != nil {
		return fmt.Errorf("save ACME account key: %w", err)
	}

	myUser := ACMEUser{
		Email: Email,
		Key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.CADirURL = acmeproviders.URL(ACMEProvider)

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
		return fmt.Errorf("failed to register: %w", err)
	}

	reg, err := json.Marshal(myUser.Registration)
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed marshaling registration: %w", err)
	}

	fmt.Println(string(reg))
	return nil
}
