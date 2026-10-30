package cmdsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// The CDS endpoint document the enforcer hands an injected credential client:
// one <host>:<port>, the CDS this cluster's components dial. The node writes
// it with FormatCDSAddress (internal/cmds/nri-image-policy) and its clients
// read it back from workloadclaims.CDSAddressPath.

// SplitCDSAddress is the host and port of the <host>:<port> this cluster's
// CDS serves on: a DNS name the node resolves, or an IPv4 address it dials as
// it stands.
func SplitCDSAddress(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("%q must be <host>:<port>: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("%q names port %q, which no CDS serves on", address, portText)
	}
	if err := validateCDSHost(host); err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}

// validateCDSHost accepts the two things a node's clients can dial: an IPv4
// address, and a lowercase DNS name they resolve. A signed launch document
// holds a literal to more than this (launchconfig.ValidateRoutableIPv4).
func validateCDSHost(host string) error {
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() {
			return fmt.Errorf("%q must be an IPv4 address", host)
		}
		return nil
	}
	if len(validation.IsDNS1123Subdomain(host)) > 0 {
		return fmt.Errorf("%q must be a lowercase DNS name or an IPv4 address", host)
	}
	return nil
}

// FormatCDSAddress renders the endpoint a node hands its clients.
func FormatCDSAddress(address string) []byte {
	return []byte(address + "\n")
}

// ParseCDSAddress reads that document. An empty one names no endpoint, which
// is an error rather than a default: a client with no endpoint reaches no CDS.
func ParseCDSAddress(data []byte) (string, error) {
	address := strings.TrimSpace(string(data))
	if address == "" {
		return "", errors.New("names no address")
	}
	if _, _, err := SplitCDSAddress(address); err != nil {
		return "", err
	}
	return address, nil
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
