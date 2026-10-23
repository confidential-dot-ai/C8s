package routes

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// Schema identifies the manifest format (D1).
const Schema = "c8s.routes/v1"

const (
	// Path is the CDS endpoint that stores and serves the signed manifest,
	// and the htu a write token for it carries (W2).
	Path = "/routes"
	// PublicationPath is where the automated ingress service publishes its
	// applied signed manifest (E4).
	PublicationPath = "/.well-known/c8s/routes"
)

const (
	maxRevision      = 1<<53 - 1 // D2
	maxMaxAgeSeconds = 1<<31 - 1 // D4
)

// MatchKind says how a route's path matches a request path.
type MatchKind string

// Match kinds (D6).
const (
	MatchExact  MatchKind = "exact"
	MatchPrefix MatchKind = "prefix"
)

// Manifest is a validated route manifest. Parse returns it read-only:
// holders share it, so none may modify it or the Hosts, Routes and anchors
// it holds.
type Manifest struct {
	Revision  uint64
	NotBefore time.Time
	MaxAge    time.Duration
	// Hosts is keyed by lower-case DNS host name. It may be empty.
	Hosts map[string]Host
}

// Host holds the routes of one host, in manifest order. The order carries no
// meaning (M2).
type Host struct {
	Routes []Route
}

// Route sends requests whose path matches Path under Match to Backend.
type Route struct {
	Path    string
	Match   MatchKind
	Backend Backend
}

// Backend is where a matched request goes: a workload backend when Workload
// is set, otherwise an address backend with ServerName and CA (D7).
type Backend struct {
	// Address is host:port. It is never evidence of identity (B2).
	Address string
	// Workload is the allowlist workload name the peer's named leaf must
	// carry (B1).
	Workload string
	// ServerName is the TLS server name an address backend must present.
	ServerName string
	// CA is the PEM bundle of trust anchors for an address backend.
	CA string

	anchors []*x509.Certificate
}

// Anchors returns the certificates parsed from CA, read-only like the
// Manifest. It is nil for a workload backend and for a Backend not produced
// by Parse.
func (b Backend) Anchors() []*x509.Certificate { return b.anchors }

// Digest returns the route digest of manifest bytes: SHA-256 of exactly
// those bytes.
func Digest(manifest []byte) [sha256.Size]byte {
	return sha256.Sum256(manifest)
}

// Parse validates manifest bytes against D1–D9 and returns the manifest. It
// rejects the whole manifest on the first failure (D9). Errors name the
// offending member and are safe to return to the client that wrote the
// manifest.
func Parse(manifest []byte) (*Manifest, error) {
	m, err := parse(manifest)
	if err != nil {
		return nil, fmt.Errorf("route manifest: %w", err)
	}
	return m, nil
}

func parse(data []byte) (*Manifest, error) {
	if err := strictjson.Validate(data); err != nil {
		return nil, err
	}
	top, err := members(data, "manifest", []string{"schema", "revision", "notBefore", "maxAgeSeconds", "hosts"}, nil)
	if err != nil {
		return nil, err
	}
	schema, err := stringValue(top["schema"], "schema")
	if err != nil {
		return nil, err
	}
	if schema != Schema {
		return nil, fmt.Errorf("schema: got %q, want %q", schema, Schema)
	}
	var m Manifest
	if m.Revision, err = integer(top["revision"], "revision", maxRevision); err != nil {
		return nil, err
	}
	notBefore, err := stringValue(top["notBefore"], "notBefore")
	if err != nil {
		return nil, err
	}
	if m.NotBefore, err = parseTimestamp(notBefore); err != nil {
		return nil, fmt.Errorf("notBefore: %w", err)
	}
	maxAge, err := integer(top["maxAgeSeconds"], "maxAgeSeconds", maxMaxAgeSeconds)
	if err != nil {
		return nil, err
	}
	m.MaxAge = time.Duration(maxAge) * time.Second
	if m.Hosts, err = parseHosts(top["hosts"]); err != nil {
		return nil, err
	}
	return &m, nil
}

// dateTime is the RFC 3339 §5.6 date-time grammar. time.Parse alone also
// accepts one-digit fields, comma fractions and offsets such as +24:00.
var dateTime = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:)(\d{2})(\.\d+)?([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)$`)

// parseTimestamp parses an RFC 3339 date-time; time.Parse checks the
// remaining field ranges. A leap second, allowed only at 23:59:60 UTC on
// 30 June or 31 December, reads as the next second.
func parseTimestamp(s string) (time.Time, error) {
	m := dateTime.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, errors.New("not an RFC 3339 date-time")
	}
	leap := m[2] == "60"
	if leap {
		m[2] = "59"
	}
	t, err := time.Parse(time.RFC3339, strings.ToUpper(m[1]+m[2]+m[3]+m[4]))
	if err != nil || !leap {
		return t, err
	}
	u := t.UTC()
	_, month, day := u.Date()
	halfYearEnd := month == time.June && day == 30 || month == time.December && day == 31
	if !halfYearEnd || u.Hour() != 23 || u.Minute() != 59 {
		return time.Time{}, errors.New("second 60 is only valid at 23:59 UTC on 30 June or 31 December")
	}
	return t.Add(time.Second), nil
}

func parseHosts(raw json.RawMessage) (map[string]Host, error) {
	if !isKind(raw, '{') {
		return nil, fmt.Errorf("hosts: must be an object")
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	hosts := make(map[string]Host, len(entries))
	// Sorted so that a manifest with several faults always reports the same one.
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		at := fmt.Sprintf("hosts[%q]", name)
		if err := CheckHost(name); err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		h, err := parseHost(entries[name], at)
		if err != nil {
			return nil, err
		}
		hosts[name] = h
	}
	return hosts, nil
}

func parseHost(raw json.RawMessage, at string) (Host, error) {
	obj, err := members(raw, at, []string{"routes"}, nil)
	if err != nil {
		return Host{}, err
	}
	at += ".routes"
	if !isKind(obj["routes"], '[') {
		return Host{}, fmt.Errorf("%s: must be a list", at)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(obj["routes"], &items); err != nil {
		return Host{}, fmt.Errorf("%s: %w", at, err)
	}
	if len(items) == 0 {
		return Host{}, fmt.Errorf("%s: must not be empty", at)
	}
	type key struct {
		path  string
		match MatchKind
	}
	seen := make(map[key]bool, len(items))
	routes := make([]Route, 0, len(items))
	for i, item := range items {
		r, err := parseRoute(item, fmt.Sprintf("%s[%d]", at, i))
		if err != nil {
			return Host{}, err
		}
		k := key{r.Path, r.Match}
		if seen[k] {
			return Host{}, fmt.Errorf("%s[%d]: another route has path %q and match %q", at, i, r.Path, r.Match) // D8
		}
		seen[k] = true
		routes = append(routes, r)
	}
	return Host{Routes: routes}, nil
}

func parseRoute(raw json.RawMessage, at string) (Route, error) {
	obj, err := members(raw, at, []string{"path", "match", "backend"}, nil)
	if err != nil {
		return Route{}, err
	}
	var r Route
	if r.Path, err = stringValue(obj["path"], at+".path"); err != nil {
		return Route{}, err
	}
	if err := checkRoutePath(r.Path); err != nil {
		return Route{}, fmt.Errorf("%s.path: %w", at, err)
	}
	match, err := stringValue(obj["match"], at+".match")
	if err != nil {
		return Route{}, err
	}
	r.Match = MatchKind(match)
	if r.Match != MatchExact && r.Match != MatchPrefix {
		return Route{}, fmt.Errorf("%s.match: got %q, want %q or %q", at, match, MatchExact, MatchPrefix)
	}
	if r.Backend, err = parseBackend(obj["backend"], at+".backend"); err != nil {
		return Route{}, err
	}
	return r, nil
}

// checkRoutePath enforces D6. An accepted path is its own NormalizePath
// result.
func checkRoutePath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New(`must begin with "/"`)
	case strings.ContainsAny(p, "?#%"):
		return errors.New(`must not contain "?", "#" or percent-encoding`)
	case strings.Contains(p, "//"):
		return errors.New(`must not contain "//"`)
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "." || seg == ".." {
			return errors.New(`must not contain a "." or ".." segment`)
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] != '/' && !pathChar(p[i]) {
			return fmt.Errorf("byte %q at offset %d is not allowed in a URI path", p[i], i)
		}
	}
	return nil
}

// parseBackend enforces D7, and with it D9: both backend forms verify the
// peer, and members rejects anything else, such as a protocol.
func parseBackend(raw json.RawMessage, at string) (Backend, error) {
	obj, err := members(raw, at, []string{"address"}, []string{"workload", "serverName", "ca"})
	if err != nil {
		return Backend{}, err
	}
	var b Backend
	if b.Address, err = stringValue(obj["address"], at+".address"); err != nil {
		return Backend{}, err
	}
	if err := checkAddress(b.Address); err != nil {
		return Backend{}, fmt.Errorf("%s.address: %w", at, err)
	}
	_, hasWorkload := obj["workload"]
	_, hasServerName := obj["serverName"]
	_, hasCA := obj["ca"]
	switch {
	case hasWorkload && !hasServerName && !hasCA:
		if b.Workload, err = stringValue(obj["workload"], at+".workload"); err != nil {
			return Backend{}, err
		}
		if !workloadname.Valid(b.Workload) {
			return Backend{}, fmt.Errorf("%s.workload: %q is not a valid allowlist workload name", at, b.Workload)
		}
	case !hasWorkload && hasServerName && hasCA:
		if b.ServerName, err = stringValue(obj["serverName"], at+".serverName"); err != nil {
			return Backend{}, err
		}
		if !validDNSName(b.ServerName, false) {
			return Backend{}, fmt.Errorf("%s.serverName: %q is not a DNS name", at, b.ServerName)
		}
		if numericFinalLabel(b.ServerName) {
			return Backend{}, fmt.Errorf("%s.serverName: %w", at, errNumericFinalLabel)
		}
		if b.CA, err = stringValue(obj["ca"], at+".ca"); err != nil {
			return Backend{}, err
		}
		if b.anchors, err = parseAnchors(b.CA); err != nil {
			return Backend{}, fmt.Errorf("%s.ca: %w", at, err)
		}
	default:
		return Backend{}, fmt.Errorf("%s: must have exactly one of workload, or serverName with ca", at)
	}
	return b, nil
}

func checkAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("must be host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil && !validDNSName(host, false) {
		return fmt.Errorf("host %q is neither an IP address nor a DNS name", host)
	}
	// SplitHostPort strips brackets from any host; D7 allows them only
	// around IPv6.
	if bracketed := strings.HasPrefix(addr, "["); bracketed != (ip != nil && strings.Contains(host, ":")) {
		return fmt.Errorf("host %q: brackets must enclose an IPv6 address, and only one", host)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 || port[0] == '0' {
		return fmt.Errorf("port %q is not a decimal integer from 1 to 65535", port)
	}
	return nil
}

// parseAnchors requires at least one CERTIFICATE block and nothing else but
// whitespace (D7).
func parseAnchors(bundle string) ([]*x509.Certificate, error) {
	const begin = "-----BEGIN "
	var certs []*x509.Certificate
	rest := []byte(bundle)
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte(begin)) {
			return nil, errors.New("data outside PEM blocks")
		}
		block, next := pem.Decode(rest)
		// pem.Decode skips a malformed block and returns a later one; refuse
		// that rather than ignore the skipped text.
		if block == nil || bytes.Count(rest[:len(rest)-len(next)], []byte(begin)) != 1 {
			return nil, errors.New("malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %q is not a CERTIFICATE", block.Type)
		}
		if len(block.Headers) != 0 {
			return nil, errors.New("PEM block has headers")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(certs), err)
		}
		certs = append(certs, cert)
		rest = next
	}
	if len(certs) == 0 {
		return nil, errors.New("must hold at least one CERTIFICATE block")
	}
	return certs, nil
}

// CheckAnchorsExclude returns an error if any address backend's ca holds one
// of excluded, such as the mesh CAs (B3, C3), or a certificate one of them
// signed. A certificate counts as held when its DER or its public key
// matches, since a re-issued certificate for the same key anchors the same
// chains. Pass the full trusted bundle, every rotation generation included:
// an omitted CA can still anchor mesh chains.
func (m *Manifest) CheckAnchorsExclude(excluded []*x509.Certificate) error {
	for _, name := range slices.Sorted(maps.Keys(m.Hosts)) {
		for i, r := range m.Hosts[name].Routes {
			for _, a := range r.Backend.anchors {
				for _, ex := range excluded {
					if a.Equal(ex) || bytes.Equal(a.RawSubjectPublicKeyInfo, ex.RawSubjectPublicKeyInfo) {
						return fmt.Errorf("route manifest: hosts[%q].routes[%d].backend.ca: holds excluded CA %q", name, i, ex.Subject)
					}
					if a.CheckSignatureFrom(ex) == nil {
						return fmt.Errorf("route manifest: hosts[%q].routes[%d].backend.ca: holds %q, issued by excluded CA %q", name, i, a.Subject, ex.Subject)
					}
				}
			}
		}
	}
	return nil
}

// members decodes a JSON object and requires its member names to be exactly
// required plus any of optional, compared case-sensitively.
func members(raw json.RawMessage, at string, required, optional []string) (map[string]json.RawMessage, error) {
	if !isKind(raw, '{') {
		return nil, fmt.Errorf("%s: must be an object", at)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s: %w", at, err)
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return nil, fmt.Errorf("%s: missing member %q", at, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(obj)) {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, fmt.Errorf("%s: unknown member %q", at, name) // D1
		}
	}
	return obj, nil
}

func stringValue(raw json.RawMessage, at string) (string, error) {
	var s string
	if !isKind(raw, '"') || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%s: must be a string", at)
	}
	return s, nil
}

// integer accepts a JSON number written as a decimal integer from 1 to
// limit. It rejects 1.0, 1e3 and 01.
func integer(raw json.RawMessage, at string, limit uint64) (uint64, error) {
	s := string(bytes.TrimSpace(raw))
	n, err := strconv.ParseUint(s, 10, 53) // every limit is at most 2^53-1
	if err != nil || s[0] == '0' || n > limit {
		return 0, fmt.Errorf("%s: must be an integer from 1 to %d", at, limit)
	}
	return n, nil
}

func isKind(raw json.RawMessage, first byte) bool {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	return len(raw) > 0 && raw[0] == first
}

var errNumericFinalLabel = errors.New("final label must not be numeric (it would parse as an IPv4 address)")

// CheckHost reports whether name can be a manifest host key (D5): a
// lower-case DNS name with no port, trailing dot or numeric final label.
func CheckHost(name string) error {
	if net.ParseIP(name) != nil {
		return errors.New("must not be an IP literal")
	}
	if !validDNSName(name, true) {
		return errors.New("not a lower-case DNS host name without port or trailing dot")
	}
	if numericFinalLabel(name) {
		return errNumericFinalLabel
	}
	return nil
}

// numericFinalLabel reports whether a WHATWG URL parser would read name as
// an IPv4 address: its last label is decimal, or 0x followed by hex digits.
func numericFinalLabel(name string) bool {
	last := name[strings.LastIndexByte(name, '.')+1:]
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') {
		return strings.Trim(last[2:], "0123456789abcdefABCDEF") == ""
	}
	return strings.Trim(last, "0123456789") == ""
}

// validDNSName reports whether name is an LDH host name of at most 253
// octets with no trailing dot. Non-ASCII names must be written as A-labels.
func validDNSName(name string, lowerOnly bool) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			case c >= 'A' && c <= 'Z' && !lowerOnly:
			default:
				return false
			}
		}
	}
	return true
}
