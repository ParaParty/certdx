package acme

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
)

func TestClassify(t *testing.T) {
	problem := &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", HTTPStatus: 403}
	limited := &legoacme.RateLimitedError{
		ProblemDetails: &legoacme.ProblemDetails{Type: legoacme.RateLimitedErr, HTTPStatus: 429},
		RetryAfter:     "120",
	}
	netErr := &url.Error{Op: "Post", URL: "https://acme.example/new-order", Err: errors.New("connection refused")}

	cases := []struct {
		name  string
		err   error
		want  Failure
		after time.Duration
	}{
		{"rate limited", errors.Join(errors.New("obtain"), limited), FailureRateLimited, 2 * time.Minute},
		{"rate limited without Retry-After", &legoacme.RateLimitedError{ProblemDetails: problem}, FailureRateLimited, 0},
		{"rejected", fmt.Errorf("[a.example] invalid authorization: %w", problem), FailureRejected, 0},
		{"network", fmt.Errorf("obtain: %w", netErr), FailureNetwork, 0},
		{"problem wins over network", errors.Join(netErr, problem), FailureRejected, 0},
		{"propagation", errors.New("propagation: time limit exceeded"), FailureOther, 0},
	}
	for _, tc := range cases {
		got, after := Classify(tc.err)
		if got != tc.want || after != tc.after {
			t.Errorf("%s: got %s/%s want %s/%s", tc.name, got, after, tc.want, tc.after)
		}
	}
}
