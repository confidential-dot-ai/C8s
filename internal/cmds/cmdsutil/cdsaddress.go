package cmdsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"
)

// The CDS endpoint document the enforcer hands an injected credential client:
// one address and port, which is the one destination that pod's packet rules
// admit for the credential role. The node writes it with FormatCDSAddress
// (internal/cmds/nri-image-policy) and its clients read it back from
// workloadclaims.CDSAddressPath.

// FormatCDSAddress renders the endpoint a node hands its clients.
func FormatCDSAddress(endpoint netip.AddrPort) []byte {
	return []byte(endpoint.String() + "\n")
}

// ParseCDSAddress reads that document. An empty one names no endpoint, which
// is an error rather than a default: a client with no endpoint reaches no CDS.
func ParseCDSAddress(data []byte) (netip.AddrPort, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return netip.AddrPort{}, errors.New("names no address")
	}
	return netip.ParseAddrPort(text)
}

// CDSURL is that endpoint as the base URL a client dials. CDS is reached over
// armTLS, which makes https the only scheme the endpoint can carry.
func CDSURL(endpoint netip.AddrPort) string {
	return "https://" + endpoint.String()
}

// ResolveCDSEndpoint returns the CDS endpoint the node mounts at path, and
// whether it mounts one at all. resolveNodePolicy states the rule; a caller
// that is handed no endpoint and holds no --cds-url reaches no CDS.
func ResolveCDSEndpoint(path, suppliedURL string) (netip.AddrPort, bool, error) {
	var supplied []string
	if suppliedURL != "" {
		supplied = []string{"--cds-url"}
	}
	return resolveNodePolicy(path, supplied, ParseCDSAddress)
}

// resolveNodePolicy returns what the node mounts at path, parsed, and whether
// there is a mount at all.
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
		return none, false, fmt.Errorf("node policy %s: %w", path, err)
	}
	if len(supplied) > 0 {
		return none, false, fmt.Errorf("this node provides %s; remove %s", path, strings.Join(supplied, " and "))
	}
	parsed, err := parse(data)
	if err != nil {
		return none, false, fmt.Errorf("node policy %s: %w", path, err)
	}
	return parsed, true, nil
}
