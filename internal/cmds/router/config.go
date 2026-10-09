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

// Route is one path published ahead of the catch-all backend.
type Route struct {
	Path    string
	Match   string
	Backend Backend
	CORS    bool
}

// CORS is the policy added to every proxied location.
type CORS struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

// Allowlist is the built-in route to the loopback allowlist proxy. A zero
// ProxyPort publishes no such route.
type Allowlist struct {
	ProxyPort       int
	WriteRate       int
	WriteBurst      int
	WriteTotalRate  int
	WriteTotalBurst int
	ReadRate        int
	ReadBurst       int
}

// Discovery is the preflight metadata served to unattested clients. An empty
// Path publishes none of it.
type Discovery struct {
	Path        string
	File        string
	CDSCertPath string
	MeshCAPath  string
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
	Routes         []Route
	AttestPort     int
	Allowlist      Allowlist
	Discovery      Discovery
	CORS           CORS
	ACME           bool
}

// The ports nginx.conf.tmpl binds: the TLS front door, and the ACME mode's
// public :80 server with the loopback listener the acme sidecar answers
// HTTP-01 challenges on. A loopback sidecar port may take none of them.
const (
	httpsPort         = 8443
	acmeHTTPPort      = 8080
	acmeChallengePort = 8402
)

// allowlistLocations are the exact and prefix halves of the built-in route, so
// a lookalike path such as /allowlisted never reaches the loopback proxy.
var allowlistLocations = []string{"= /allowlist", "/allowlist/"}

// nginx expands a variable wherever these land, so neither a path nor an
// address may carry one.
var (
	sanPattern      = regexp.MustCompile(`^[A-Za-z0-9.*-]+$`)
	addressPattern  = regexp.MustCompile(`^[^\s{};/#$"]+:[0-9]+$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	filePattern     = regexp.MustCompile(`^/[^\s{};$"]+$`)
	durationPattern = regexp.MustCompile(`^[0-9]+(ms|s|m|h|d)?$`)
	uriPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9._~!&()*+,=:@%/-]*$`)
	originPattern   = regexp.MustCompile(`^https?://[A-Za-z0-9.-]+(:[0-9]+)?$`)
	tokenPattern    = regexp.MustCompile(`^[A-Za-z0-9!#%&'*+.^_|~-]+$`)
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
	if c.DialsABackend() {
		if err := validateResolver(c.Resolver); err != nil {
			return Config{}, err
		}
	}
	if c.Backend.Address != "" {
		c.Backend = normalizeBackend(c.Backend)
		if err := validateCatchAll(c.Backend); err != nil {
			return Config{}, fmt.Errorf("--backend %w", err)
		}
	}
	routes, err := normalizeRoutes(c.Routes)
	if err != nil {
		return Config{}, err
	}
	c.Routes = routes
	if err := c.validatePorts(); err != nil {
		return Config{}, err
	}
	if err := c.validateAllowlist(); err != nil {
		return Config{}, err
	}
	if err := c.validateDiscovery(); err != nil {
		return Config{}, err
	}
	if err := c.validateCORS(); err != nil {
		return Config{}, err
	}
	return c, c.validateLocations()
}

// normalizeRoutes fills each route's verification name and refuses a backend
// an explicit route may not reach: the adopted workload is the catch-all's
// alone, and every other route backend authenticates itself over https.
func normalizeRoutes(routes []Route) ([]Route, error) {
	normalized := make([]Route, 0, len(routes))
	for _, route := range routes {
		label := fmt.Sprintf("--route %s", route.Path)
		if !uriPathPattern.MatchString(route.Path) {
			return nil, fmt.Errorf("--route path %q must start with '/' and hold only URI path characters", route.Path)
		}
		if route.Match != "exact" && route.Match != "prefix" {
			return nil, fmt.Errorf("%s match must be exact or prefix, got %q", label, route.Match)
		}
		route.Backend = normalizeBackend(route.Backend)
		if err := validateAddress(route.Backend.Address); err != nil {
			return nil, fmt.Errorf("%s %w", label, err)
		}
		if route.Backend.Protocol != "https" {
			return nil, fmt.Errorf("%s must reach its backend over https, which authenticates it, got %q", label, route.Backend.Protocol)
		}
		if adoptedWorkload(route.Backend.Address) {
			return nil, fmt.Errorf("%s names an adopted workload's Service, which is reached as the catch-all backend over http, not as a route", label)
		}
		if err := validateServerName(route.Backend.ServerName); err != nil {
			return nil, fmt.Errorf("%s %w", label, err)
		}
		normalized = append(normalized, route)
	}
	return normalized, nil
}

// listeners are the ports nginx binds, which a loopback sidecar port must
// leave free: a location proxying to one of them would dial the front door.
func (c Config) listeners() []int {
	if c.ACME {
		return []int{httpsPort, acmeHTTPPort, acmeChallengePort}
	}
	return []int{httpsPort}
}

func (c Config) validatePorts() error {
	ports := map[string]int{
		"--attest-port":          c.AttestPort,
		"--allowlist-proxy-port": c.Allowlist.ProxyPort,
	}
	for flag, port := range ports {
		if port == 0 {
			continue
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s must be between 1 and 65535, got %d", flag, port)
		}
		if slices.Contains(c.listeners(), port) {
			return fmt.Errorf("%s must leave the ports nginx binds %v free, got %d", flag, c.listeners(), port)
		}
	}
	if c.AttestPort != 0 && c.AttestPort == c.Allowlist.ProxyPort {
		return fmt.Errorf("--attest-port and --allowlist-proxy-port must differ, got %d", c.AttestPort)
	}
	return nil
}

func (c Config) validateAllowlist() error {
	rates := map[string]int{
		"--allowlist-write-rate":        c.Allowlist.WriteRate,
		"--allowlist-write-burst":       c.Allowlist.WriteBurst,
		"--allowlist-write-total-rate":  c.Allowlist.WriteTotalRate,
		"--allowlist-write-total-burst": c.Allowlist.WriteTotalBurst,
		"--allowlist-read-rate":         c.Allowlist.ReadRate,
		"--allowlist-read-burst":        c.Allowlist.ReadBurst,
	}
	for flag, rate := range rates {
		if rate < 1 {
			return fmt.Errorf("%s must be positive, got %d", flag, rate)
		}
	}
	// The per-client budget stays inside the aggregate one, which is what
	// guards the single per-pod-IP bucket CDS meters this front door by.
	if c.Allowlist.WriteRate > c.Allowlist.WriteTotalRate {
		return fmt.Errorf("--allowlist-write-rate must not exceed --allowlist-write-total-rate (%d), got %d", c.Allowlist.WriteTotalRate, c.Allowlist.WriteRate)
	}
	if c.Allowlist.WriteBurst > c.Allowlist.WriteTotalBurst {
		return fmt.Errorf("--allowlist-write-burst must not exceed --allowlist-write-total-burst (%d), got %d", c.Allowlist.WriteTotalBurst, c.Allowlist.WriteBurst)
	}
	return nil
}

// validateDiscovery requires the document and the certificate it chains to be
// served together, and refuses a path nothing serves.
func (c Config) validateDiscovery() error {
	paths := map[string]string{
		"--discovery-path":          c.Discovery.Path,
		"--discovery-cds-cert-path": c.Discovery.CDSCertPath,
		"--discovery-mesh-ca-path":  c.Discovery.MeshCAPath,
	}
	for flag, path := range paths {
		if path != "" && !uriPathPattern.MatchString(path) {
			return fmt.Errorf("%s must start with '/' and hold only URI path characters, got %q", flag, path)
		}
	}
	if c.Discovery.Path == "" {
		if c.Discovery.CDSCertPath != "" || c.Discovery.MeshCAPath != "" {
			return fmt.Errorf("--discovery-cds-cert-path and --discovery-mesh-ca-path are served beside the discovery document, which needs --discovery-path")
		}
		return nil
	}
	if c.Discovery.CDSCertPath == "" {
		return fmt.Errorf("--discovery-cds-cert-path must serve the certificate a client chains the discovery document to")
	}
	return validateFile("--discovery-file", c.Discovery.File)
}

func (c Config) validateCORS() error {
	if c.CORS.MaxAge < 0 {
		return fmt.Errorf("--cors-max-age must not be negative, got %d", c.CORS.MaxAge)
	}
	if !c.CORSEnabled() {
		return nil
	}
	for _, origin := range c.CORS.AllowOrigins {
		if origin != "*" && !originPattern.MatchString(origin) {
			return fmt.Errorf("--cors-allow-origin %q must be \"*\" or a scheme://host[:port] URL", origin)
		}
	}
	if c.CORS.AllowCredentials && c.WildcardOrigin() {
		return fmt.Errorf(`--cors-allow-credentials is incompatible with the "*" origin: browsers reject that pair`)
	}
	lists := map[string][]string{
		"--cors-allow-method":  c.CORS.AllowMethods,
		"--cors-allow-header":  c.CORS.AllowHeaders,
		"--cors-expose-header": c.CORS.ExposeHeaders,
	}
	for flag, list := range lists {
		for _, value := range list {
			if !tokenPattern.MatchString(value) {
				return fmt.Errorf("%s %q must be an HTTP token", flag, value)
			}
		}
	}
	return nil
}

// location is one nginx location and what renders it, so a collision names
// both sides. nginx refuses a duplicate outright.
type location struct {
	key   string
	owner string
}

func (c Config) renderedLocations() []location {
	locations := []location{
		{
			key:   "/healthz",
			owner: "the health endpoint",
		},
	}
	if c.Backend.Address != "" {
		locations = append(locations, location{
			key:   "/",
			owner: "the catch-all backend",
		})
	}
	for _, key := range allowlistLocations {
		if c.Allowlist.ProxyPort != 0 {
			locations = append(locations, location{
				key:   key,
				owner: "the built-in allowlist relay",
			})
		}
	}
	if c.AttestPort != 0 {
		for _, key := range []string{"= /readyz", "/.well-known/c8s/"} {
			locations = append(locations, location{
				key:   key,
				owner: "the attestation sidecar",
			})
		}
	}
	for _, file := range c.StaticFiles() {
		locations = append(locations, location{
			key:   "= " + file.Path,
			owner: "the discovery document",
		})
	}
	for _, route := range c.Routes {
		locations = append(locations, location{
			key:   route.LocationKey(),
			owner: "--route " + route.Path,
		})
	}
	return locations
}

func (c Config) validateLocations() error {
	owners := make(map[string]string)
	for _, l := range c.renderedLocations() {
		owner, taken := owners[l.key]
		if taken {
			return fmt.Errorf("%s and %s both serve location %q", owner, l.owner, l.key)
		}
		owners[l.key] = l.owner
	}
	return nil
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
