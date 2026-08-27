package acme

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestConservativeCheckerChecksEveryAuthoritativeAddress(t *testing.T) {
	checker, checkedServers := newConservativeCheckerFixture(t, "challenge-value", "")

	ok, err := checker.Check("_acme-challenge.example.com", "challenge-value")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !ok {
		t.Fatal("Check returned false without an error")
	}

	slices.Sort(*checkedServers)
	want := []string{
		"192.0.2.1:53",
		"192.0.2.2:53",
		"192.0.2.3:53",
		"[2001:db8::1]:53",
	}
	if !slices.Equal(*checkedServers, want) {
		t.Fatalf("authoritative addresses checked: got %v want %v", *checkedServers, want)
	}
}

func TestConservativeCheckerFailsWhenAnyAddressDoesNotHaveTXT(t *testing.T) {
	checker, checkedServers := newConservativeCheckerFixture(t, "challenge-value", "192.0.2.2:53")

	ok, err := checker.Check("_acme-challenge.example.com.", "challenge-value")
	if err == nil {
		t.Fatal("expected an error when one authoritative address has a stale TXT record")
	}
	if ok {
		t.Fatal("Check returned true with a stale authoritative address")
	}
	if !strings.Contains(err.Error(), "192.0.2.2:53") {
		t.Fatalf("error does not identify the stale address: %v", err)
	}
	if len(*checkedServers) != 4 {
		t.Fatalf("expected every address to be queried despite one failure, got %v", *checkedServers)
	}
}

func TestConservativeCheckerSkipsUnreachableAddress(t *testing.T) {
	checker, checkedServers := newConservativeCheckerFixture(t, "challenge-value", "")
	exchange := checker.exchangeFn
	checker.exchangeFn = func(message *dns.Msg, server string) (*dns.Msg, error) {
		if server == "[2001:db8::1]:53" && message.Question[0].Qtype == dns.TypeTXT {
			return nil, errors.New("network is unreachable")
		}
		return exchange(message, server)
	}

	ok, err := checker.Check("_acme-challenge.example.com.", "challenge-value")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !ok {
		t.Fatal("Check returned false after only an unreachable address was skipped")
	}

	slices.Sort(*checkedServers)
	want := []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}
	if !slices.Equal(*checkedServers, want) {
		t.Fatalf("reachable authoritative addresses checked: got %v want %v", *checkedServers, want)
	}
}

func TestConservativeCheckerFailsWhenEveryAddressIsUnreachable(t *testing.T) {
	checker, _ := newConservativeCheckerFixture(t, "challenge-value", "")
	exchange := checker.exchangeFn
	checker.exchangeFn = func(message *dns.Msg, server string) (*dns.Msg, error) {
		if server != "resolver.test:53" && message.Question[0].Qtype == dns.TypeTXT {
			return nil, errors.New("i/o timeout")
		}
		return exchange(message, server)
	}

	ok, err := checker.Check("_acme-challenge.example.com.", "challenge-value")
	if err == nil {
		t.Fatal("expected an error when every authoritative address is unreachable")
	}
	if ok {
		t.Fatal("Check returned true without a reachable authoritative address")
	}
	if !strings.Contains(err.Error(), "no authoritative nameserver address was reachable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConservativeCheckerRequiresAddressesForEveryNameserver(t *testing.T) {
	checker := newConservativeChecker([]string{"resolver.test:53"}, time.Second)
	ns1 := mustRR(t, "example.com. 60 IN NS ns1.example.com.")
	ns2 := mustRR(t, "example.com. 60 IN NS ns2.example.com.")
	ns1Address := mustRR(t, "ns1.example.com. 60 IN A 192.0.2.1")
	checker.findZoneFn = func(fqdn string, nameservers []string) (string, error) {
		return "example.com.", nil
	}
	checker.exchangeFn = func(message *dns.Msg, server string) (*dns.Msg, error) {
		question := message.Question[0]
		response := new(dns.Msg)
		response.SetReply(message)

		switch {
		case question.Qtype == dns.TypeNS:
			response.Answer = []dns.RR{ns1, ns2}
		case question.Name == "ns1.example.com." && question.Qtype == dns.TypeA:
			response.Answer = []dns.RR{ns1Address}
		}

		return response, nil
	}

	ok, err := checker.Check("_acme-challenge.example.com.", "challenge-value")
	if err == nil {
		t.Fatal("expected an error when an authoritative nameserver has no addresses")
	}
	if ok {
		t.Fatal("Check returned true with an unresolved authoritative nameserver")
	}
	if !strings.Contains(err.Error(), "ns2.example.com.") {
		t.Fatalf("error does not identify the unresolved nameserver: %v", err)
	}
}

func TestConservativeNameserversNormalizesAndDeduplicates(t *testing.T) {
	got := conservativeNameservers([]string{
		"1.1.1.1",
		"1.1.1.1:53",
		"[2001:db8::1]:5353",
		"",
	})
	want := []string{"1.1.1.1:53", "[2001:db8::1]:5353"}

	if !slices.Equal(got, want) {
		t.Fatalf("nameservers: got %v want %v", got, want)
	}
}

func newConservativeCheckerFixture(t *testing.T, expected, staleServer string) (*conservativeChecker, *[]string) {
	t.Helper()

	checker := newConservativeChecker([]string{"resolver.test:53"}, time.Second)
	checker.findZoneFn = func(fqdn string, nameservers []string) (string, error) {
		if fqdn != "_acme-challenge.example.com." {
			return "", fmt.Errorf("unexpected fqdn: %s", fqdn)
		}
		if !slices.Equal(nameservers, []string{"resolver.test:53"}) {
			return "", fmt.Errorf("unexpected recursive nameservers: %v", nameservers)
		}
		return "example.com.", nil
	}

	resolverAnswers := map[string][]dns.RR{
		dnsQuestionKey("example.com.", dns.TypeNS): {
			mustRR(t, "example.com. 60 IN NS ns1.example.com."),
			mustRR(t, "example.com. 60 IN NS ns2.example.com."),
		},
		dnsQuestionKey("ns1.example.com.", dns.TypeA): {
			mustRR(t, "ns1.example.com. 60 IN A 192.0.2.1"),
			mustRR(t, "ns1.example.com. 60 IN A 192.0.2.2"),
		},
		dnsQuestionKey("ns1.example.com.", dns.TypeAAAA): {
			mustRR(t, "ns1.example.com. 60 IN AAAA 2001:db8::1"),
		},
		dnsQuestionKey("ns2.example.com.", dns.TypeA): {
			mustRR(t, "ns2.example.com. 60 IN A 192.0.2.2"),
			mustRR(t, "ns2.example.com. 60 IN A 192.0.2.3"),
		},
		dnsQuestionKey("ns2.example.com.", dns.TypeAAAA): {},
	}

	var mu sync.Mutex
	var checkedServers []string
	checker.exchangeFn = func(message *dns.Msg, server string) (*dns.Msg, error) {
		if len(message.Question) != 1 {
			return nil, fmt.Errorf("unexpected question count: %d", len(message.Question))
		}
		question := message.Question[0]
		response := new(dns.Msg)
		response.SetReply(message)

		if server == "resolver.test:53" {
			if !message.RecursionDesired {
				return nil, fmt.Errorf("recursive discovery query did not request recursion: %s", question.Name)
			}
			answers, ok := resolverAnswers[dnsQuestionKey(question.Name, question.Qtype)]
			if !ok {
				return nil, fmt.Errorf("unexpected recursive query: %s %s", question.Name, dns.TypeToString[question.Qtype])
			}
			response.Answer = answers
			return response, nil
		}

		if question.Qtype != dns.TypeTXT || question.Name != "_acme-challenge.example.com." {
			return nil, fmt.Errorf("unexpected authoritative query: %s %s", question.Name, dns.TypeToString[question.Qtype])
		}
		if message.RecursionDesired {
			return nil, fmt.Errorf("authoritative TXT query requested recursion from %s", server)
		}
		response.Authoritative = true

		mu.Lock()
		checkedServers = append(checkedServers, server)
		mu.Unlock()

		splitAt := len(expected) / 2
		value := []string{expected[:splitAt], expected[splitAt:]}
		if server == staleServer {
			value = []string{"stale-value"}
		}
		response.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Txt: value,
		}}
		return response, nil
	}

	return checker, &checkedServers
}

func dnsQuestionKey(name string, recordType uint16) string {
	return fmt.Sprintf("%s/%d", dns.Fqdn(name), recordType)
}

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		t.Fatalf("parse DNS record %q: %v", value, err)
	}
	return record
}
