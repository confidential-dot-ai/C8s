package allowlist

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// maxHostLength is the longest DNS name in its text form (RFC 1035).
const maxHostLength = 253

// reservedHostSuffixes name no public host: an exit to one of them would
// resolve inside the node or the cluster, never to the service it names.
var reservedHostSuffixes = []string{"localhost", "local", "internal", "arpa", "svc"}

// validEgressHost requires a lowercase DNS name a TLS client sends as its
// server name: ASCII letters, digits and hyphens (IDNs in their punycode
// form), at least two labels, no trailing dot, and no IP literal. A wildcard
// is "*." in place of the first label alone, over a name of at least two
// labels; it stands for exactly one label (MatchEgressHost).
func validEgressHost(host string) error {
	name := strings.TrimPrefix(host, "*.")
	switch {
	case host == "":
		return fmt.Errorf("an exit needs a cidr or a host")
	case len(host) > maxHostLength:
		return fmt.Errorf("host %q is longer than %d bytes", host, maxHostLength)
	case strings.Contains(name, "*"):
		return fmt.Errorf("host %q: a wildcard is \"*.\" in place of the first label only", host)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("host %q is an IP literal; declare it as a cidr", host)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("host %q needs at least two labels after any wildcard", host)
	}
	for _, label := range labels {
		if err := validHostLabel(label); err != nil {
			return fmt.Errorf("host %q: %w", host, err)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return fmt.Errorf("host %q ends in a numeric label", host)
	}
	for _, suffix := range reservedHostSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return fmt.Errorf("host %q is under %q, which names no public host", host, suffix)
		}
	}
	if strings.Contains(name, "xn--") {
		unicode, err := idna.Lookup.ToUnicode(name)
		if err != nil {
			return fmt.Errorf("host %q: invalid punycode: %w", host, err)
		}
		if back, err := idna.Lookup.ToASCII(unicode); err != nil || back != name {
			return fmt.Errorf("host %q is not in canonical punycode form", host)
		}
	}
	return nil
}

func validHostLabel(label string) error {
	if label == "" || len(label) > 63 {
		return fmt.Errorf("label %q must be 1-63 bytes", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("label %q holds %q; a host is lowercase letters, digits and hyphens (punycode for IDNs)", label, c)
		}
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// MatchEgressHost reports whether a TLS server name is the declared host: the
// same name, or, for "*.example.com", one more label in front of
// example.com. The server name is compared in lower case without a trailing
// dot, as TLS clients send it.
func MatchEgressHost(declared, serverName string) bool {
	name := strings.ToLower(strings.TrimSuffix(serverName, "."))
	base, wildcard := strings.CutPrefix(declared, "*.")
	if !wildcard {
		return name == declared
	}
	first, rest, ok := strings.Cut(name, ".")
	return ok && first != "" && rest == base
}
