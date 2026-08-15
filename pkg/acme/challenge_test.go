package acme

import (
	"reflect"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"pkg.para.party/certdx/pkg/config"
)

// preCheckFlags applies the options to a throw-away lego challenge and
// reports the two propagation requirements it ended up with. The fields
// are unexported, but reflect can read booleans out of them without
// going through Interface().
func preCheckFlags(t *testing.T, opts []dns01.ChallengeOption) (authoritative, recursive bool) {
	t.Helper()
	chlg := dns01.NewChallenge(nil, nil, nil, opts...)
	preCheck := reflect.ValueOf(chlg).Elem().FieldByName("preCheck")
	if !preCheck.IsValid() {
		t.Fatal("dns01.Challenge has no preCheck field, lego internals changed")
	}
	return preCheck.FieldByName("requireAuthoritativeNssPropagation").Bool(),
		preCheck.FieldByName("requireRecursiveNssPropagation").Bool()
}

func TestDns01OptionsPropagationRequirements(t *testing.T) {
	cases := []struct {
		name              string
		provider          config.DnsProvider
		wantAuthoritative bool
		wantRecursive     bool
	}{
		{
			name:              "defaults keep authoritative check",
			provider:          config.DnsProvider{},
			wantAuthoritative: true,
			wantRecursive:     false,
		},
		{
			name:              "nameservers alone do not add recursive check",
			provider:          config.DnsProvider{Nameservers: []string{"1.1.1.1"}},
			wantAuthoritative: true,
			wantRecursive:     false,
		},
		{
			name: "disabled authoritative check without nameservers",
			provider: config.DnsProvider{
				DisableCompletePropagationRequirement: true,
			},
			wantAuthoritative: false,
			wantRecursive:     false,
		},
		{
			// The regression: disabling the authoritative requirement while
			// pointing lego at custom resolvers used to verify nothing at all.
			name: "disabled authoritative check with nameservers verifies on the resolvers",
			provider: config.DnsProvider{
				DisableCompletePropagationRequirement: true,
				Nameservers:                           []string{"1.1.1.1", "8.8.8.8:53"},
			},
			wantAuthoritative: false,
			wantRecursive:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := dns01Options(&tc.provider)
			if err != nil {
				t.Fatalf("dns01Options: %v", err)
			}
			authoritative, recursive := preCheckFlags(t, opts)
			if authoritative != tc.wantAuthoritative {
				t.Errorf("requireAuthoritativeNssPropagation=%v want %v", authoritative, tc.wantAuthoritative)
			}
			if recursive != tc.wantRecursive {
				t.Errorf("requireRecursiveNssPropagation=%v want %v", recursive, tc.wantRecursive)
			}
		})
	}
}

func TestDns01OptionsRejectsBadTimeout(t *testing.T) {
	_, err := dns01Options(&config.DnsProvider{DNSTimeout: "not a duration"})
	if err == nil {
		t.Fatal("expected an error for an unparseable dnsTimeout")
	}
}
