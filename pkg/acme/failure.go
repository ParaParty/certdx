package acme

import (
	"errors"
	"net/url"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
)

// Failure is the kind of an Obtain error, which decides how soon to retry.
type Failure int

const (
	// FailureOther covers challenge, DNS propagation and unrecognized errors.
	FailureOther Failure = iota
	// FailureNetwork means an HTTP request to the CA or the DNS provider API
	// got no response.
	FailureNetwork
	// FailureRejected means the CA answered with an ACME problem, such as a
	// failed validation or an unauthorized identifier.
	FailureRejected
	// FailureRateLimited means the CA answered rateLimited.
	FailureRateLimited
)

func (f Failure) String() string {
	switch f {
	case FailureNetwork:
		return "network error"
	case FailureRejected:
		return "rejected by CA"
	case FailureRateLimited:
		return "rate limited by CA"
	default:
		return "challenge error"
	}
}

// Classify returns the kind of an Obtain error. For FailureRateLimited it also
// returns the CA's Retry-After, or 0 if the CA sent none.
func Classify(err error) (Failure, time.Duration) {
	var limited *legoacme.RateLimitedError
	if errors.As(err, &limited) {
		after, _ := api.ParseRetryAfter(limited.RetryAfter)
		return FailureRateLimited, after
	}
	var problem *legoacme.ProblemDetails
	if errors.As(err, &problem) {
		return FailureRejected, 0
	}
	var netErr *url.Error
	if errors.As(err, &netErr) {
		return FailureNetwork, 0
	}
	return FailureOther, 0
}
