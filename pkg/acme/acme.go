package acme

import (
	"pkg.para.party/certdx/pkg/acme/google"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/utils"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

var acmeProvidersMap = map[string]string{
	"google":     "https://dv.acme-v02.api.pki.goog/directory",
	"googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
	"r3":         "https://acme-v02.api.letsencrypt.org/directory",
	"r3test":     "https://acme-staging-v02.api.letsencrypt.org/directory",
}

var ACMEAccountKey crypto.PrivateKey

func ACMEProviderSupported(provider string) bool {
	_, ok := acmeProvidersMap[provider]
	return ok
}

func isACMEProviderGoogle(provider string) bool {
	return strings.HasPrefix(provider, "google")
}

func parsePEM(pem []byte) (crypto.PrivateKey, error) {
	key, err := certcrypto.ParsePEMPrivateKey(pem)
	if err != nil {
		panic(err)
	}

	return key, nil
}

func InitACMEAccount(c *config.ServerConfigT) error {
	keyPath, err := utils.GetACMEPrivateKeySavePath(c.ACME.Email, c.ACME.Provider)
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		kid := ""
		hmac := ""

		if isACMEProviderGoogle(c.ACME.Provider) {
			account, err := google.CreateExternalAccountKeyRequest(c.GoogleCloudCredential)
			if err != nil {
				return fmt.Errorf("failed to register google ca: %v", err)
			}
			kid = account.KeyId
			hmac = account.HmacEncoded
		}

		if err := RegisterAccount(c.ACME.Provider, c.ACME.Email, kid, hmac); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	ACMEAccountKey, err = parsePEM(keyFile)

	return err
}

type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
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

	myUser := MyUser{
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

type ACME struct {
	Registration *registration.Resource
	Client       *lego.Client
	email        string
	retry        int
	needNotAfter bool
}

func (a *ACME) GetEmail() string {
	return a.email
}
func (a *ACME) GetRegistration() *registration.Resource {
	return a.Registration
}
func (a *ACME) GetPrivateKey() crypto.PrivateKey {
	return ACMEAccountKey
}

func (a *ACME) Obtain(domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	if a.needNotAfter {
		request.NotAfter = deadline
	}

	certificates, err := a.Client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed obtaining cert: %s", err)
	}

	return certificates.Certificate, certificates.PrivateKey, nil
}

func (a *ACME) RetryObtain(domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	err = utils.Retry(a.retry,
		func() error {
			fullchain, key, err = a.Obtain(domains, deadline)
			return err
		})

	return
}

func MakeACME(c *config.ServerConfigT) (*ACME, error) {
	instance := &ACME{
		retry: c.ACME.RetryCount,
		needNotAfter: isACMEProviderGoogle(c.ACME.Provider),
	}
	config := lego.NewConfig(instance)
	config.CADirURL = acmeProvidersMap[c.ACME.Provider]
	config.Certificate.KeyType = certcrypto.EC256

	var err error
	instance.Client, err = lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unexpected error constructing acme client: %w", err)
	}

	err = SetChallenger(config, instance, c)
	if err != nil {
		return nil, err
	}

	instance.Registration, err = instance.Client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, fmt.Errorf("failed resolving account. Is account registered? Error: %w", err)
	}

	return instance, nil
}
