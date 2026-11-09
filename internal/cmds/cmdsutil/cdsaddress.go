package cmdsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/pkg/cdsgenesis"
)

// The CDS endpoint document the enforcer hands an injected credential client:
// one <host>:<port>, the CDS this cluster's components dial. The node writes
// it with FormatCDSAddress (internal/cmds/nri-image-policy) and its clients
// read it back from workloadclaims.CDSAddressPath.

// Refusals a caller can match on.
var (
	ErrNotHostPort     = errors.New("must be <host>:<port>")
	ErrPortUnserved    = errors.New("no CDS serves on")
	ErrNotDNSHostname  = errors.New("must be a lowercase DNS hostname")
	ErrNotIPv4         = errors.New("must be an IPv4 address")
	ErrNotRoutableIPv4 = errors.New("must be a unicast IPv4 address")
)

// SplitCDSAddress is the host and port of the <host>:<port> this cluster's
// CDS serves on: a DNS name the node resolves, or an IPv4 address it dials as
// it stands.
func SplitCDSAddress(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("%q %w: %w", address, ErrNotHostPort, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("%q names port %q, which %w", address, portText, ErrPortUnserved)
	}
	if err := validateCDSHost(host); err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}

// ValidateCDSEndpoints holds a CDS replica set's endpoints, by slot, to the
// rule every reader of them shares: 1, 3 or 5 distinct <host>:<port>.
func ValidateCDSEndpoints(endpoints []string) error {
	if n := len(endpoints); n != 1 && n != 3 && n != 5 {
		return fmt.Errorf("%d endpoints: a replica set has 1, 3 or 5", n)
	}
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		if _, _, err := SplitCDSAddress(endpoint); err != nil {
			return fmt.Errorf("endpoint %w", err)
		}
		if seen[endpoint] {
			return fmt.Errorf("endpoint %q is listed twice", endpoint)
		}
		seen[endpoint] = true
	}
	return nil
}

// validateCDSHost accepts the two things a node's clients can dial: an IPv4
// address, and a lowercase DNS name they resolve.
func validateCDSHost(host string) error {
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() {
			return fmt.Errorf("%q %w", host, ErrNotIPv4)
		}
		return nil
	}
	if err := ValidateHostname(host); err != nil {
		return fmt.Errorf("%q must be a lowercase DNS name or an IPv4 address: %w", host, err)
	}
	return nil
}

// FormatCDSAddress renders the endpoint a node hands its clients and, after
// it, the CDS replica set chain entry the node pins ("" for none).
func FormatCDSAddress(address, chain string) []byte {
	return []byte(strings.TrimSpace(address+" "+chain) + "\n")
}

// ParseCDSAddress reads that document's endpoint. An empty one names no
// endpoint, which is an error rather than a default: a client with no
// endpoint reaches no CDS.
func ParseCDSAddress(data []byte) (string, error) {
	address, _, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
	if address == "" {
		return "", errors.New("names no address")
	}
	if _, _, err := SplitCDSAddress(address); err != nil {
		return "", err
	}
	return address, nil
}

// NodeCDSChain holds c to the CDS replica set chain entry the node pins in
// its endpoint document at path (C-ID): every answer must name it. Without
// that document, or a pin in it, c is held to nothing more.
func NodeCDSChain(c *http.Client, path string) (*http.Client, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("node policy %s: %w", path, err)
	}
	_, pin, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
	return cdsgenesis.Client(c, pin), nil
}

// CDSURL is that endpoint as the base URL a client dials. CDS is reached over
// armTLS, which makes https the only scheme the endpoint can carry.
func CDSURL(address string) string {
	return "https://" + address
}

// CDSURLAddress is the <host>:<port> a CDS base URL names, which is what a
// node's packet rules and its clients need out of a measured config's URL.
func CDSURLAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q must be the https URL of this cluster's CDS: %w", raw, err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("%q must use https, as armTLS does", raw)
	}
	if _, _, err := SplitCDSAddress(parsed.Host); err != nil {
		return "", err
	}
	return parsed.Host, nil
}

// ResolveCDSAddress returns the CDS endpoint the node mounts at path, and
// whether it mounts one at all. resolveNodePolicy states the rule; a caller
// that is handed no endpoint and holds no --cds-url reaches no CDS.
func ResolveCDSAddress(path, suppliedURL string) (string, bool, error) {
	var supplied []string
	if suppliedURL != "" {
		supplied = []string{"--cds-url"}
	}
	return resolveNodePolicy(path, supplied, ParseCDSAddress)
}

// ResolveCDSURL is the base URL a client dials: the endpoint the node mounts
// at path, otherwise suppliedURL as it was given, and whether the node
// decided. An empty answer names no CDS, which each client refuses in its own
// words.
func ResolveCDSURL(path, suppliedURL string) (string, bool, error) {
	address, fromNode, err := ResolveCDSAddress(path, suppliedURL)
	if err != nil {
		return "", false, err
	}
	if fromNode {
		return CDSURL(address), true, nil
	}
	return suppliedURL, false, nil
}

// resolveNodePolicy returns what the node mounts at path, parsed, and whether
// there is a mount at all. The mount answer holds even when parsing or the
// caller's own arguments fail it, so a caller can say which source was short.
//
// THE RULE: while the enforcer's mount is at path, it is the only source, and
// a supplied input is an error rather than a merged or silently ignored one.
// An absent mount leaves the caller's own inputs: a chart-rendered platform
// client and the CLI have no enforcer to read. Any other error reading that
// path fails: an unreadable policy still binds the client.
//
// supplied names the inputs the caller set, for an error that says which
// argument to drop.
func resolveNodePolicy[T any](path string, supplied []string, parse func([]byte) (T, error)) (T, bool, error) {
	var none T
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return none, false, nil
	case err != nil:
		return none, true, fmt.Errorf("node policy %s: %w", path, err)
	}
	if len(supplied) > 0 {
		return none, true, fmt.Errorf("this node provides %s; remove %s", path, strings.Join(supplied, " and "))
	}
	parsed, err := parse(data)
	if err != nil {
		return none, true, fmt.Errorf("node policy %s: %w", path, err)
	}
	return parsed, true, nil
}

// ValidateHostname accepts a lowercase DNS hostname: no IP, no wildcard.
func ValidateHostname(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("%q exceeds DNS name length", name)
	}
	if name == "" || net.ParseIP(name) != nil {
		return fmt.Errorf("%q %w", name, ErrNotDNSHostname)
	}
	for _, label := range strings.Split(name, ".") {
		if problems := validation.IsDNS1123Label(label); len(problems) > 0 {
			return fmt.Errorf("%q %w: label %q %s", name, ErrNotDNSHostname, label, strings.Join(problems, "; "))
		}
	}
	return nil
}

// ValidateRoutableIPv4 accepts a global-unicast IPv4 address, one a node can
// publish or dial.
func ValidateRoutableIPv4(raw string) error {
	_, err := routableIPv4(raw)
	return err
}

func routableIPv4(raw string) (netip.Addr, error) {
	addr, err := parseIPv4(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}, ErrNotRoutableIPv4
	}
	return addr, nil
}

// isAddress reports whether host is written as an IP address, not a name.
func isAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// parseIPv4 refuses an IPv4-mapped IPv6 literal: the text a document carries
// is the text a node compares.
func parseIPv4(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, ErrNotIPv4
	}
	return addr, nil
}
