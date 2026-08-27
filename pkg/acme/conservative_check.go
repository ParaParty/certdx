package acme

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

const (
	defaultConservativeDNSTimeout = 10 * time.Second
	defaultResolvConf             = "/etc/resolv.conf"
)

type conservativeChecker struct {
	nameservers []string
	timeout     time.Duration

	findZoneFn func(string, []string) (string, error)
	exchangeFn func(*dns.Msg, string) (*dns.Msg, error)
}

func newConservativeChecker(nameservers []string, timeout time.Duration) *conservativeChecker {
	if timeout <= 0 {
		timeout = defaultConservativeDNSTimeout
	}

	checker := &conservativeChecker{
		nameservers: conservativeNameservers(nameservers),
		timeout:     timeout,
		findZoneFn:  dns01.FindZoneByFqdnCustom,
	}
	checker.exchangeFn = checker.exchange

	return checker
}

// Wrap replaces lego's default propagation pre-check. The fqdn passed by lego
// is already the effective challenge FQDN after following a supported CNAME.
func (c *conservativeChecker) Wrap(_, fqdn, expected string, _ dns01.PreCheckFunc) (bool, error) {
	return c.Check(fqdn, expected)
}

// Check requires the expected TXT value to be visible on every reachable
// address of every authoritative nameserver. Unreachable addresses are
// skipped, but at least one address must respond. It performs one check only;
// lego owns the propagation retry loop and calls this method again until its
// timeout expires.
func (c *conservativeChecker) Check(fqdn, expected string) (bool, error) {
	if expected == "" {
		return false, errors.New("conservative DNS check: expected TXT value is empty")
	}
	if len(c.nameservers) == 0 {
		return false, errors.New("conservative DNS check: no recursive nameservers configured")
	}

	fqdn = dns.Fqdn(fqdn)
	zone, err := c.findZoneFn(fqdn, c.nameservers)
	if err != nil {
		return false, fmt.Errorf("conservative DNS check: find zone for %s: %w", fqdn, err)
	}

	nameservers, err := c.lookupAuthoritativeNameservers(zone)
	if err != nil {
		return false, fmt.Errorf("conservative DNS check: %w", err)
	}

	addresses, err := c.lookupNameserverAddresses(nameservers)
	if err != nil {
		return false, fmt.Errorf("conservative DNS check: %w", err)
	}

	return c.checkTXTOnAddresses(fqdn, expected, addresses)
}

func conservativeNameservers(configured []string) []string {
	if len(configured) == 0 {
		config, err := dns.ClientConfigFromFile(defaultResolvConf)
		if err == nil && len(config.Servers) > 0 {
			configured = config.Servers
		} else {
			configured = []string{"8.8.8.8:53", "1.1.1.1:53"}
		}
	}

	var nameservers []string
	seen := make(map[string]struct{})
	for _, nameserver := range configured {
		nameserver = strings.TrimSpace(nameserver)
		if nameserver == "" {
			continue
		}

		parsed := dns01.ParseNameservers([]string{nameserver})[0]
		if _, ok := seen[parsed]; ok {
			continue
		}
		seen[parsed] = struct{}{}
		nameservers = append(nameservers, parsed)
	}

	sort.Strings(nameservers)
	return nameservers
}

func (c *conservativeChecker) lookupAuthoritativeNameservers(zone string) ([]string, error) {
	responses, err := c.queryRecursive(zone, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("lookup authoritative nameservers for %s: %w", zone, err)
	}

	seen := make(map[string]struct{})
	for _, response := range responses {
		sections := [][]dns.RR{response.Answer, response.Ns}
		for _, section := range sections {
			for _, answer := range section {
				ns, ok := answer.(*dns.NS)
				if !ok {
					continue
				}
				seen[strings.ToLower(dns.Fqdn(ns.Ns))] = struct{}{}
			}
		}
	}

	nameservers := sortedKeys(seen)
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no authoritative nameservers found for zone %s", zone)
	}

	return nameservers, nil
}

type addressLookupResult struct {
	nameserver string
	recordType uint16
	addresses  []string
	err        error
}

func (c *conservativeChecker) lookupNameserverAddresses(nameservers []string) ([]string, error) {
	results := make(chan addressLookupResult, len(nameservers)*2)

	for _, nameserver := range nameservers {
		for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			go func(nameserver string, recordType uint16) {
				responses, err := c.queryRecursive(nameserver, recordType)
				result := addressLookupResult{
					nameserver: nameserver,
					recordType: recordType,
					err:        err,
				}
				if err == nil {
					result.addresses = addressesFromResponses(responses)
				}
				results <- result
			}(nameserver, recordType)
		}
	}

	addressesByNameserver := make(map[string]map[string]struct{}, len(nameservers))
	var lookupErrors []error
	for range len(nameservers) * 2 {
		result := <-results
		if result.err != nil {
			lookupErrors = append(lookupErrors, fmt.Errorf("lookup %s records for %s: %w",
				dns.TypeToString[result.recordType], result.nameserver, result.err))
			continue
		}

		if addressesByNameserver[result.nameserver] == nil {
			addressesByNameserver[result.nameserver] = make(map[string]struct{})
		}
		for _, address := range result.addresses {
			addressesByNameserver[result.nameserver][address] = struct{}{}
		}
	}

	for _, nameserver := range nameservers {
		if len(addressesByNameserver[nameserver]) == 0 {
			lookupErrors = append(lookupErrors, fmt.Errorf("no A or AAAA records found for nameserver %s", nameserver))
		}
	}
	if len(lookupErrors) > 0 {
		return nil, errors.Join(lookupErrors...)
	}

	addresses := make(map[string]struct{})
	for _, nameserverAddresses := range addressesByNameserver {
		for address := range nameserverAddresses {
			addresses[address] = struct{}{}
		}
	}

	return sortedKeys(addresses), nil
}

func addressesFromResponses(responses []*dns.Msg) []string {
	seen := make(map[string]struct{})
	for _, response := range responses {
		for _, answer := range response.Answer {
			switch record := answer.(type) {
			case *dns.A:
				seen[record.A.String()] = struct{}{}
			case *dns.AAAA:
				seen[record.AAAA.String()] = struct{}{}
			}
		}
	}

	return sortedKeys(seen)
}

type dnsQueryResult struct {
	response *dns.Msg
	err      error
}

// queryRecursive asks every configured resolver and combines their usable
// answers. Combining answers avoids missing an address when resolvers rotate
// the order or return different subsets of an RRset.
func (c *conservativeChecker) queryRecursive(name string, recordType uint16) ([]*dns.Msg, error) {
	results := make(chan dnsQueryResult, len(c.nameservers))

	for _, nameserver := range c.nameservers {
		go func(nameserver string) {
			response, err := c.exchangeFn(newDNSQuery(name, recordType, true), nameserver)
			if err == nil && response == nil {
				err = errors.New("empty DNS response")
			}
			if err == nil && response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
				err = fmt.Errorf("resolver %s returned %s", nameserver, dns.RcodeToString[response.Rcode])
			}
			results <- dnsQueryResult{response: response, err: err}
		}(nameserver)
	}

	var responses []*dns.Msg
	var queryErrors []error
	for range len(c.nameservers) {
		result := <-results
		if result.err != nil {
			queryErrors = append(queryErrors, result.err)
			continue
		}
		responses = append(responses, result.response)
	}

	if len(responses) == 0 {
		return nil, errors.Join(queryErrors...)
	}

	return responses, nil
}

type txtCheckResult struct {
	server    string
	reachable bool
	err       error
}

func (c *conservativeChecker) checkTXTOnAddresses(fqdn, expected string, addresses []string) (bool, error) {
	if len(addresses) == 0 {
		return false, errors.New("conservative DNS check: no authoritative nameserver addresses found")
	}

	results := make(chan txtCheckResult, len(addresses))
	for _, address := range addresses {
		server := net.JoinHostPort(address, "53")
		go func() {
			reachable, err := c.checkTXT(server, fqdn, expected)
			results <- txtCheckResult{server: server, reachable: reachable, err: err}
		}()
	}

	var checkErrors []error
	var unreachableErrors []error
	reachableCount := 0
	for range len(addresses) {
		result := <-results
		if !result.reachable {
			unreachableErrors = append(unreachableErrors, fmt.Errorf("%s: %w", result.server, result.err))
			continue
		}

		reachableCount++
		if result.err != nil {
			checkErrors = append(checkErrors, fmt.Errorf("%s: %w", result.server, result.err))
		}
	}
	if reachableCount == 0 {
		return false, fmt.Errorf("conservative DNS check: no authoritative nameserver address was reachable: %w",
			errors.Join(unreachableErrors...))
	}
	if len(checkErrors) > 0 {
		return false, fmt.Errorf("conservative DNS check: TXT record is not available on every reachable authoritative address: %w",
			errors.Join(checkErrors...))
	}

	return true, nil
}

// checkTXT uses the DNS request itself as a service-level reachability probe.
// A response proves that the address is reachable even if its contents are
// invalid. A transport failure without any response allows the caller to skip
// that address.
func (c *conservativeChecker) checkTXT(server, fqdn, expected string) (bool, error) {
	response, err := c.exchangeFn(newDNSQuery(fqdn, dns.TypeTXT, false), server)
	if err != nil {
		return response != nil, err
	}
	if response == nil {
		return false, errors.New("empty DNS response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return true, fmt.Errorf("returned %s for %s", dns.RcodeToString[response.Rcode], fqdn)
	}
	if !response.Authoritative {
		return true, fmt.Errorf("returned a non-authoritative response for %s", fqdn)
	}

	var records []string
	for _, answer := range response.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok || !strings.EqualFold(txt.Hdr.Name, fqdn) {
			continue
		}

		record := strings.Join(txt.Txt, "")
		records = append(records, record)
		if record == expected {
			return true, nil
		}
	}

	return true, fmt.Errorf("did not return expected TXT record [fqdn: %s, value: %s]: %s",
		fqdn, expected, strings.Join(records, ", "))
}

func newDNSQuery(name string, recordType uint16, recursive bool) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), recordType)
	message.SetEdns0(4096, false)
	message.RecursionDesired = recursive
	return message
}

func (c *conservativeChecker) exchange(message *dns.Msg, nameserver string) (*dns.Msg, error) {
	tcpOnly, _ := strconv.ParseBool(os.Getenv("LEGO_EXPERIMENTAL_DNS_TCP_ONLY"))
	if tcpOnly {
		response, _, err := (&dns.Client{Net: "tcp", Timeout: c.timeout}).Exchange(message, nameserver)
		if err != nil {
			return response, fmt.Errorf("TCP DNS query to %s: %w", nameserver, err)
		}
		return response, nil
	}

	response, _, err := (&dns.Client{Net: "udp", Timeout: c.timeout}).Exchange(message, nameserver)
	if response != nil && response.Truncated {
		udpResponse := response
		response, _, err = (&dns.Client{Net: "tcp", Timeout: c.timeout}).Exchange(message, nameserver)
		if err != nil && response == nil {
			// Preserve proof that the address responded over UDP. Failure to
			// retrieve the complete response must not be treated as unreachable.
			response = udpResponse
		}
	}
	if err != nil {
		return response, fmt.Errorf("DNS query to %s: %w", nameserver, err)
	}

	return response, nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
