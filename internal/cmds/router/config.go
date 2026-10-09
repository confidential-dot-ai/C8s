package router

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Backend is one proxied hop: a host:port address reached over http or https.
type Backend struct {
	Address    string
	Protocol   string
	ServerName string
}

// Config is the whole render input: typed data only, no nginx directive.
type Config struct {
	SANs           []string
	PublicCertFile string
	PublicKeyFile  string
	CertFile       string
	KeyFile        string
	MeshCAFile     string
	Backend        Backend
	ReadTimeout    string
	Resolver       string
	ACME           bool
}

// nginx expands a variable wherever these land, so neither a path nor an
// address may carry one.
var (
	sanPattern      = regexp.MustCompile(`^[A-Za-z0-9.*-]+$`)
	addressPattern  = regexp.MustCompile(`^[^\s{};/#$"]+:[0-9]+$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	filePattern     = regexp.MustCompile(`^/[^\s{};$"]+$`)
	durationPattern = regexp.MustCompile(`^[0-9]+(ms|s|m|h|d)?$`)
)

// Validate returns cfg with every derived value filled in, or the first input
// the renderer would otherwise interpolate unchecked.
func (c Config) Validate() (Config, error) {
	for _, san := range c.SANs {
		if !sanPattern.MatchString(san) {
			return Config{}, fmt.Errorf("--san %q may hold only letters, digits, dots, hyphens, and wildcards", san)
		}
	}
	files := map[string]string{
		"--public-cert": c.PublicCertFile,
		"--public-key":  c.PublicKeyFile,
		"--cert":        c.CertFile,
		"--key":         c.KeyFile,
		"--mesh-ca":     c.MeshCAFile,
	}
	for flag, file := range files {
		if err := validateFile(flag, file); err != nil {
			return Config{}, err
		}
	}
	if !durationPattern.MatchString(c.ReadTimeout) {
		return Config{}, fmt.Errorf("--backend-read-timeout must be an nginx time such as 3600s or 60m, got %q", c.ReadTimeout)
	}
	if err := validateResolver(c.Resolver); err != nil {
		return Config{}, err
	}
	if c.Backend.Address == "" {
		return c, nil
	}
	c.Backend = normalizeBackend(c.Backend)
	if err := validateCatchAll(c.Backend); err != nil {
		return Config{}, fmt.Errorf("--backend %w", err)
	}
	return c, nil
}

// normalizeBackend fills the verification name an https hop needs from the
// address host.
func normalizeBackend(backend Backend) Backend {
	if backend.Protocol == "https" && backend.ServerName == "" {
		backend.ServerName = serverNameFromAddress(backend.Address)
	}
	return backend
}

// validateCatchAll admits the two safe shapes for the front door's default
// backend: an adopted workload's Service, whose plaintext hop the node mesh
// wraps, or an address that authenticates itself over https.
func validateCatchAll(backend Backend) error {
	if err := validateAddress(backend.Address); err != nil {
		return err
	}
	if adoptedWorkload(backend.Address) {
		if backend.Protocol != "http" {
			return fmt.Errorf("address %q is an adopted workload's Service, which the node mesh wraps, so it is reached over http, got %q", backend.Address, backend.Protocol)
		}
		return nil
	}
	if backend.Protocol != "https" {
		return fmt.Errorf("address %q is not an adopted workload's Service, so it must authenticate itself over https, got %q", backend.Address, backend.Protocol)
	}
	return validateServerName(backend.ServerName)
}

func validateAddress(address string) error {
	if !addressPattern.MatchString(address) {
		return fmt.Errorf("address must be host:port without a scheme, whitespace, quotes, or any of ;{}/#$, got %q", address)
	}
	return nil
}

func validateServerName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("server name must be a hostname, got %q", name)
	}
	return nil
}

// adoptedWorkload reports whether the address is an operator-managed headless
// Service, c8s-<id>.<namespace>.svc.cluster.local:<port> (the shape
// webhook.WorkloadServiceFQDN builds), whose backing pod IPs churn.
func adoptedWorkload(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) != 5 || !slices.Equal(labels[2:], []string{"svc", "cluster", "local"}) {
		return false
	}
	if !strings.HasPrefix(labels[0], "c8s-") {
		return false
	}
	return dnsLabel(labels[0]) && dnsLabel(labels[1])
}

func dnsLabel(label string) bool {
	return len(validation.IsDNS1123Label(label)) == 0
}

// validateResolver accepts what nginx re-resolves backends at: a DNS name or
// an IP address, either with an optional port.
func validateResolver(resolver string) error {
	host := resolver
	if split, _, err := net.SplitHostPort(resolver); err == nil {
		host = split
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for label := range strings.SplitSeq(host, ".") {
		if !dnsLabel(label) {
			return fmt.Errorf("--resolver must be the DNS name or IP address nginx re-resolves backends at, got %q", resolver)
		}
	}
	return nil
}

// WatchedFiles are the files an nginx directive loads: the member credential
// and the CA it proxies with, plus the public pair the front door presents.
func (c Config) WatchedFiles() []string {
	var files []string
	for _, file := range []string{c.CertFile, c.KeyFile, c.MeshCAFile, c.PublicCertFile, c.PublicKeyFile} {
		if !slices.Contains(files, file) {
			files = append(files, file)
		}
	}
	return files
}

func validateFile(flag, file string) error {
	if !filePattern.MatchString(file) {
		return fmt.Errorf("%s must be an absolute path without whitespace, quotes, or any of ;{}$, got %q", flag, file)
	}
	return nil
}

// serverNameFromAddress is the SNI and verification name an address implies.
func serverNameFromAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
