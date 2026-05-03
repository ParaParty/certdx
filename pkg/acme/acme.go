package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"pkg.para.party/certdx/pkg/acme/acmeproviders"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/retry"
)

// Obtainer is the minimal interface the server uses to fetch certificates.
// It is satisfied by both the real *ACME (lego-backed) and the in-process
// MockACME used by the e2e test suite.
//
// ctx bounds the operation. The underlying lego client is not
// context-aware, so cancellation is observed between attempts in
// RetryObtain rather than mid-flight inside Obtain.
type Obtainer interface {
	Obtain(ctx context.Context, domains []string, deadline time.Time) (fullchain, key []byte, err error)
	RetryObtain(ctx context.Context, domains []string, deadline time.Time) (fullchain, key []byte, err error)
}

type ACME struct {
	Client       *lego.Client
	retry        int
	needNotAfter bool
}

func (a *ACME) Obtain(ctx context.Context, domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	if a.needNotAfter {
		request.NotAfter = deadline
	}

	certificates, err := a.Client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed obtaining cert: %w", err)
	}

	return certificates.Certificate, certificates.PrivateKey, nil
}

func (a *ACME) RetryObtain(ctx context.Context, domains []string, deadline time.Time) (fullchain, key []byte, err error) {
	err = retry.Do(ctx, a.retry, func() error {
		fullchain, key, err = a.Obtain(ctx, domains, deadline)
		return err
	})
	return
}

func MakeACME(c *config.ServerConfig) (Obtainer, error) {
	if acmeproviders.IsMock(c.ACME.Provider) {
		return NewMockACME(c.ACME.CertLifeTimeDuration), nil
	}

	user, err := makeACMEUser(c)
	if err != nil {
		return nil, err
	}

	instance := &ACME{
		retry:        c.ACME.RetryCount,
		needNotAfter: acmeproviders.IsGoogle(c.ACME.Provider),
	}
	config := lego.NewConfig(user)
	config.CADirURL = acmeproviders.URL(c.ACME.Provider)
	config.Certificate.KeyType = certcrypto.EC256

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
