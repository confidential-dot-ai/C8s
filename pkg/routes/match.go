package routes

import (
	"cmp"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Table selects the route for a request. Build it with Compile; it is
// immutable and safe for concurrent use. A nil Table selects nothing.
type Table struct {
	hosts    map[string]hostTable
	patterns map[string]Pattern // by host suffix
	reserved []string
}

type hostTable struct {
	exact  map[string]Route
	prefix []Route // longest path first
}

// Compile builds the Table for m; a nil m selects nothing.
//
// reserved lists the paths of the router's protocol endpoints and built-in
// routes. On every host, a reserved path shadows the request paths that a
// prefix route at that path would match (M3), so the Table never selects a
// manifest route under it (M6). Compile panics if a reserved path is not its
// own NormalizePath result: reserved paths are constants, and a malformed one
// would shadow nothing without any error.
func Compile(m *Manifest, reserved []string) *Table {
	for _, r := range reserved {
		if n, ok := NormalizePath(r); !ok || n != r {
			panic(fmt.Sprintf("routes: reserved path %q is not normalized", r))
		}
	}
	t := &Table{hosts: map[string]hostTable{}, patterns: map[string]Pattern{}, reserved: slices.Clone(reserved)}
	if m == nil {
		return t
	}
	for _, p := range m.Patterns {
		t.patterns[p.HostSuffix] = p
	}
	for name, h := range m.Hosts {
		ht := hostTable{exact: map[string]Route{}}
		for _, r := range h.Routes {
			if r.Match == MatchExact {
				ht.exact[r.Path] = r
			} else {
				ht.prefix = append(ht.prefix, r)
			}
		}
		// D8 makes prefix paths unique, so this order is total and list
		// order cannot affect selection (M2).
		slices.SortFunc(ht.prefix, func(a, b Route) int { return cmp.Compare(len(b.Path), len(a.Path)) })
		t.hosts[name] = ht
	}
	return t
}

// Select returns the route for the server request r and the URL to forward
// it to: the normalized path (M4) with r's original query (B6). The caller
// sets the URL's Scheme and Host; its RequestURI is the upstream request
// target. A route a Pattern gives has an empty Backend.Address, which the
// caller resolves from Backend.AgentLabel. Select reports false when no route matches, and the router then
// answers 404 (M5).
//
// Select matches r.Host (M1) and the raw path bytes of r.RequestURI, never
// r.URL, which is already decoded. Only an origin-form request target can
// match.
func (t *Table) Select(r *http.Request) (Route, *url.URL, bool) {
	rawPath, query, hasQuery := strings.Cut(r.RequestURI, "?")
	route, path, ok := t.lookup(r.Host, rawPath)
	if !ok {
		return Route{}, nil, false
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		panic(fmt.Sprintf("routes: normalized path %q does not unescape: %v", path, err)) // NormalizePath emits only valid escapes
	}
	// RawPath keeps escapes such as %3F that re-encoding Path would change.
	return route, &url.URL{Path: decoded, RawPath: path, RawQuery: query, ForceQuery: hasQuery && query == ""}, true
}

// lookup selects the route for host, which may carry a port, and the raw
// request path. It returns the normalized path it matched.
func (t *Table) lookup(host, rawPath string) (Route, string, bool) {
	if t == nil {
		return Route{}, "", false
	}
	path, ok := NormalizePath(rawPath)
	if !ok {
		return Route{}, "", false
	}
	for _, r := range t.reserved {
		if prefixMatches(r, path) {
			return Route{}, "", false // M6
		}
	}
	host = canonicalHost(host)
	ht, ok := t.hosts[host] // M1
	if !ok {
		return t.pattern(host, path)
	}
	if r, ok := ht.exact[path]; ok { // M2 step 1
		return r, path, true
	}
	for _, r := range ht.prefix { // M2 step 2
		if prefixMatches(r.Path, path) {
			return r, path, true
		}
	}
	return Route{}, "", false
}

// pattern selects the route a Pattern gives host: its first label is the
// agent label, and the rest is the Pattern's host suffix. An exact host in the
// manifest shadows the Pattern. Whether an agent has the label is the
// router's to resolve.
func (t *Table) pattern(host, path string) (Route, string, bool) {
	label, suffix, ok := strings.Cut(host, ".")
	p, found := t.patterns[suffix]
	if !ok || !found || label == "" {
		return Route{}, "", false
	}
	return Route{
		Path:    "/",
		Match:   MatchPrefix,
		Backend: Backend{Workload: p.Workload, AgentLabel: label, AgentPort: p.Port},
	}, path, true
}

// prefixMatches implements M3: /admin matches /admin and /admin/users but
// not /administrator.
func prefixMatches(p, path string) bool {
	if !strings.HasPrefix(path, p) {
		return false
	}
	return len(path) == len(p) || strings.HasSuffix(p, "/") || path[len(p)] == '/'
}

// canonicalHost drops a port and lower-cases ASCII letters only, so that no
// Unicode case folding can turn a non-ASCII host into a manifest key.
func canonicalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	b := []byte(host)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
