package cmdsutil

import (
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/cdslaunchfile"
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

// ValidateDNSName is the launch file's literal RFC 1123 hostname rule.
func ValidateDNSName(s string) error {
	return cdslaunchfile.ValidateDNSName(s)
}
