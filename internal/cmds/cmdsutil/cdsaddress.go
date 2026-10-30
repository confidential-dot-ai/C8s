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
// one <host>:<port>, where this cluster's CDS serves. The node writes it with
// FormatCDSAddress (internal/cmds/nri-image-policy) and its clients read it
// back from workloadclaims.CDSAddressPath.

// CDSAddress is where this cluster's CDS serves: the host its clients dial
// and the port it answers on. Only ParseCDSAddress builds one, so a value of
// this type is an endpoint a client can dial and a port a packet rule can
// admit.
type CDSAddress struct {
	// Host is a lowercase DNS name a client resolves for itself, or an IPv4
	// address it dials as it stands.
	Host string
	Port uint16
}

// ParseCDSAddress reads one <host>:<port>.
func ParseCDSAddress(address string) (CDSAddress, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return CDSAddress{}, fmt.Errorf("%q must be <host>:<port>: %w", address, err)
	}
	if host == "" {
		return CDSAddress{}, fmt.Errorf("%q names no host", address)
	}
	port, err := cdsPort(portText)
	if err != nil {
		return CDSAddress{}, fmt.Errorf("%q: %w", address, err)
	}
	if err := cdsHost(host); err != nil {
		return CDSAddress{}, err
	}
	return CDSAddress{Host: host, Port: port}, nil
}

// cdsPort accepts the ports a CDS can serve on: decimal 1 to 65535.
func cdsPort(text string) (uint16, error) {
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("port %q is not a number from 1 to 65535", text)
	}
	return uint16(port), nil
}

// cdsHost accepts the two things a client can dial: an IPv4 address, and a
// lowercase DNS name it resolves. A host written in digits and dots is held
// to being an address, since DNS would take 10.9.9.999 for a name. A signed
// launch document holds a literal to more than this
// (launchconfig.validateCDSLiteral).
func cdsHost(host string) error {
	address, err := netip.ParseAddr(host)
	switch {
	case err == nil && address.Is4():
		return nil
	case err == nil || looksLikeIPv4(host):
		return fmt.Errorf("%q must be an IPv4 address", host)
	case len(validation.IsDNS1123Subdomain(host)) > 0:
		return fmt.Errorf("%q must be a lowercase DNS name or an IPv4 address", host)
	}
	return nil
}

// looksLikeIPv4 reports whether a host is written as an address rather than
// as a name: DNS admits an all-numeric label, so nothing else separates
// 10.9.9.999 from a name.
func looksLikeIPv4(host string) bool {
	return strings.IndexFunc(host, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) < 0
}

// String is the <host>:<port> an operator wrote and a client dials.
func (a CDSAddress) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// URL is the base URL a client dials. CDS is reached over armTLS, which makes
// https the only scheme the endpoint can carry.
func (a CDSAddress) URL() string {
	return "https://" + a.String()
}

// Literal is the address this CDS is named by, where a name is not what names
// it.
func (a CDSAddress) Literal() (netip.Addr, bool) {
	address, err := netip.ParseAddr(a.Host)
	return address, err == nil
}

// CDSURLAddress is the endpoint a CDS base URL names. The URL is that origin
// and nothing else: a path, a query or a user would say something about the
// CDS this cluster trusts that no client of it reads.
func CDSURLAddress(raw string) (CDSAddress, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return CDSAddress{}, fmt.Errorf("%q must be the https URL of this cluster's CDS: %w", raw, err)
	}
	if parsed.Scheme != "https" {
		return CDSAddress{}, fmt.Errorf("%q must use https, as armTLS does", raw)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return CDSAddress{}, fmt.Errorf("%q must be the origin https://<host>:<port>, with no user, path or query", raw)
	}
	return ParseCDSAddress(parsed.Host)
}

// FormatCDSAddress renders the endpoint a node hands its clients.
func FormatCDSAddress(address CDSAddress) []byte {
	return []byte(address.String() + "\n")
}

// parseCDSAddressDocument reads that document. An empty one names no
// endpoint, which is an error rather than a default: a client with no
// endpoint reaches no CDS.
func parseCDSAddressDocument(data []byte) (CDSAddress, error) {
	address := strings.TrimSpace(string(data))
	if address == "" {
		return CDSAddress{}, errors.New("names no address")
	}
	return ParseCDSAddress(address)
}

// ResolveCDSAddress returns the CDS endpoint the node mounts at path, and
// whether it mounts one at all. resolveNodePolicy states the rule; a caller
// that is handed no endpoint and holds no --cds-url reaches no CDS.
func ResolveCDSAddress(path, suppliedURL string) (CDSAddress, bool, error) {
	var supplied []string
	if suppliedURL != "" {
		supplied = []string{"--cds-url"}
	}
	return resolveNodePolicy(path, supplied, parseCDSAddressDocument)
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
