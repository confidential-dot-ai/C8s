package cmdsutil

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// ReadSANFile reads one fixed identity name from a regular, bounded file.
// Callers apply the same SAN validation as their corresponding inline flag.
func ReadSANFile(flag, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	const maxSize = 1024
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSize {
		return "", fmt.Errorf("%s must be a regular file containing 1..%d bytes", flag, maxSize)
	}
	data, err := readutil.ReadAll(f, maxSize)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s must contain a SAN", flag)
	}
	return value, nil
}

// ServiceDNSSANPattern matches an in-cluster Service DNS name,
// <service>.<namespace>.svc. Every generator writes it into the CDS
// configuration's leaf DNS rules.
const ServiceDNSSANPattern = `^[a-z0-9-]+[.][a-z0-9-]+[.]svc$`

// hostnameLabelRe accepts RFC 1123 labels: 1–63 alphanumeric characters,
// with hyphens allowed in the middle.
var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDNSName checks a literal RFC 1123 hostname, excluding wildcards,
// URLs, regular expressions, and lists of names.
func ValidateDNSName(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("'%s' exceeds maximum hostname length of 253 characters", s)
	}
	for label := range strings.SplitSeq(s, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("'%s' is not a valid RFC 1123 hostname", s)
		}
	}
	return nil
}

// CompileDNSSANName compiles one authenticated hostname into a whole-name
// match. The name is a literal identity, never a caller-supplied regular
// expression, so the anchoring is explicit here.
func CompileDNSSANName(name string) (*regexp.Regexp, error) {
	if net.ParseIP(name) != nil {
		return nil, fmt.Errorf("'%s' is an IP address, not a DNS hostname", name)
	}
	if err := ValidateDNSName(name); err != nil {
		return nil, err
	}
	return regexp.MustCompile("^" + regexp.QuoteMeta(name) + "$"), nil
}

// CompileDNSSANPatterns compiles the patterns a leaf's DNS SANs may match,
// skipping empties so a stray "" does not become a rule of its own. No
// pattern at all admits no DNS SAN (issuer.CSRPolicy).
func CompileDNSSANPatterns(patterns []string) ([]*regexp.Regexp, error) {
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}
