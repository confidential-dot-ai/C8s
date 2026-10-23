package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
)

type manifestJSON struct {
	Schema        string              `json:"schema"`
	Revision      uint64              `json:"revision"`
	NotBefore     string              `json:"notBefore"`
	MaxAgeSeconds int64               `json:"maxAgeSeconds"`
	Hosts         map[string]hostJSON `json:"hosts"`
}

type hostJSON struct {
	Routes []routeJSON `json:"routes"`
}

type routeJSON struct {
	Path    string              `json:"path"`
	Match   pkgroutes.MatchKind `json:"match"`
	Backend backendJSON         `json:"backend"`
}

type backendJSON struct {
	Address    string `json:"address"`
	Workload   string `json:"workload,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	CA         string `json:"ca,omitempty"`
}

// Encode writes m as new manifest bytes. It authors a new revision; a stored
// manifest is never re-encoded, since its bytes are what the token signs.
func Encode(m *pkgroutes.Manifest) ([]byte, error) {
	doc := manifestJSON{
		Schema:        pkgroutes.Schema,
		Revision:      m.Revision,
		NotBefore:     m.NotBefore.UTC().Format(time.RFC3339Nano),
		MaxAgeSeconds: int64(m.MaxAge / time.Second),
		Hosts:         map[string]hostJSON{},
	}
	for name, h := range m.Hosts {
		rs := make([]routeJSON, 0, len(h.Routes))
		for _, r := range h.Routes {
			b := r.Backend
			rs = append(rs, routeJSON{Path: r.Path, Match: r.Match, Backend: backendJSON{
				Address: b.Address, Workload: b.Workload, ServerName: b.ServerName, CA: b.CA,
			}})
		}
		doc.Hosts[name] = hostJSON{Routes: rs}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AddRoute adds r to host, replacing a route with the same path and match
// (D8), and reports what it did.
func AddRoute(m *pkgroutes.Manifest, host string, r pkgroutes.Route) string {
	h := m.Hosts[host]
	h.Routes = slices.Clone(h.Routes)
	verb := "added"
	if i := slices.IndexFunc(h.Routes, func(x pkgroutes.Route) bool { return x.Path == r.Path && x.Match == r.Match }); i >= 0 {
		h.Routes[i] = r
		verb = "replaced"
	} else {
		h.Routes = append(h.Routes, r)
	}
	m.Hosts[host] = h
	return fmt.Sprintf("%s %s route %s %s", verb, r.Match, host, r.Path)
}

// removeRoute removes the route of host at path, matching match when set,
// and drops a host left without routes (D5).
func removeRoute(m *pkgroutes.Manifest, host, path string, match pkgroutes.MatchKind) (string, error) {
	h, ok := m.Hosts[host]
	if !ok {
		return "", fmt.Errorf("no host %q in the stored manifest", host)
	}
	var hits []int
	for i, r := range h.Routes {
		if r.Path == path && (match == "" || r.Match == match) {
			hits = append(hits, i)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no route %s %s in the stored manifest", host, path)
	case 1:
	default:
		return "", fmt.Errorf("%s %s has both an exact and a prefix route; pass --match exact or --match prefix", host, path)
	}
	removed := h.Routes[hits[0]]
	h.Routes = slices.Delete(slices.Clone(h.Routes), hits[0], hits[0]+1)
	if len(h.Routes) == 0 {
		delete(m.Hosts, host)
	} else {
		m.Hosts[host] = h
	}
	return fmt.Sprintf("removed %s route %s %s", removed.Match, host, path), nil
}
