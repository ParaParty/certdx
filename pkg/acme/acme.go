package acme

import (
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/utils"

	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

type ACME struct {
	Client       *lego.Client
	retry        int
	needNotAfter bool
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

var acme *ACME

func InitACME(c *config.ServerConfigT) error {
	user, err := makeACMEUser(c)
	if err != nil {
		return err
	}

	acme, err = makeACME(c, user)

	return err
}

func makeACME(c *config.ServerConfigT, user *ACMEUser) (*ACME, error) {
	instance := &ACME{
		retry:        c.ACME.RetryCount,
		needNotAfter: isACMEProviderGoogle(c.ACME.Provider),
	}
	config := lego.NewConfig(user)
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

	return instance, nil
}

func GetACME() *ACME {
	return acme
}
