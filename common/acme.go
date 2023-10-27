package common

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
	"path"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
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

func InitACMEAccount() error {
	keyPath, err := GetPrivateKeySavePath(ServerConfig.ACME.Email, ServerConfig.ACME.Provider)
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if isACMEProviderGoogle(ServerConfig.ACME.Provider) {
			return fmt.Errorf("auto register google cloud acme accout has not been implemented now, please manually register it")
		}

		if err := RegisterAccount(ServerConfig.ACME.Provider, ServerConfig.ACME.Email, "", ""); err != nil {
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

func GetPrivateKeySavePath(email string, ACMEProvider string) (string, error) {
	saveDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	saveDir = path.Join(saveDir, "private")
	keyName := fmt.Sprintf("%s_%s.key", email, ACMEProvider)

	if _, err := os.Stat(saveDir); os.IsNotExist(err) {
		err := os.Mkdir(saveDir, 0o600)
		if err != nil {
			return "", fmt.Errorf("cannot create path: %s to save account key", saveDir)
		}
	}

	return path.Join(saveDir, keyName), nil
}

func RegisterAccount(ACMEProvider, Email, Kid, Hmac string) error {
	keyPath, err := GetPrivateKeySavePath(Email, ACMEProvider)
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

	var eabOptions = registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  Kid,
		HmacEncoded:          Hmac,
	}
	myUser.Registration, err = client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed register: %s", err)
	}

	reg, err := json.Marshal(myUser.Registration)
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("failed marshal registration: %w", err)
	}

	fmt.Println(string(reg))
	return nil
}

type ACME struct {
	Registration *registration.Resource
	Client       *lego.Client
	needNotAfter bool
}

func (a *ACME) GetEmail() string {
	return ServerConfig.Cloudflare.Email
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
		request.NotAfter = deadline.Format(time.RFC3339)
	}

	certificates, err := a.Client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed obtaining cert: %s", err)
	}

	return certificates.Certificate, certificates.PrivateKey, nil
}

func (a *ACME) RetryObtain(domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	err = retry(ServerConfig.ACME.RetryCount,
		func() error {
			fullchain, key, err = a.Obtain(domains, deadline)
			return err
		})

	return
}

func GetACME() (*ACME, error) {
	instance := &ACME{
		needNotAfter: isACMEProviderGoogle(ServerConfig.ACME.Provider),
	}
	config := lego.NewConfig(instance)
	config.CADirURL = acmeProvidersMap[ServerConfig.ACME.Provider]
	config.Certificate.KeyType = certcrypto.EC256

	var err error
	instance.Client, err = lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unexpected error constructing acme client: %w", err)
	}

	dns, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthEmail:          ServerConfig.Cloudflare.Email,
		AuthKey:            ServerConfig.Cloudflare.APIKey,
		TTL:                120,
		PropagationTimeout: 30 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient:         config.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("unexpected error constructing cloudflare dns client: %w", err)
	}

	if err := instance.Client.Challenge.SetDNS01Provider(dns); err != nil {
		return nil, fmt.Errorf("unexpected error setting up dns verification: %w", err)
	}

	instance.Registration, err = instance.Client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, fmt.Errorf("failed resolving account. Is account registered? Error: %w", err)
	}

	return instance, nil
}

func retry(retryCount int, work func() error) error {
	var err error

	for i := 0; i < retryCount; i++ {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		if elapsed := time.Since(begin); elapsed < 5*time.Millisecond {
			return fmt.Errorf("errored too fast, give up retry. last error is: %w", err)
		}

		time.Sleep(15 * time.Second)
	}

	return fmt.Errorf("errored too many times, give up retry. last error is: %w", err)
}
