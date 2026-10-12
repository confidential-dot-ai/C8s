package routes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// goldenDigest is the SHA-256 of testdata/example.json, the §5 example with
// a real certificate in place of the elided ca.
const goldenDigest = "f1790658f7afc5f54fcc533df858aec46930130c0456e6f16737ac1cc6e5b45a"

func readExample(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newCA returns a self-signed CA certificate for key, or for a fresh key
// when key is nil.
func newCA(t testing.TB, key *ecdsa.PrivateKey) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

// baseManifest returns a valid manifest as a JSON tree that tests edit.
func baseManifest(ca string) map[string]any {
	return map[string]any{
		"schema":        Schema,
		"revision":      12,
		"notBefore":     "2026-09-01T00:00:00Z",
		"maxAgeSeconds": 86400,
		"hosts": map[string]any{
			"app.example": map[string]any{
				"routes": []any{
					map[string]any{"path": "/", "match": "prefix", "backend": map[string]any{
						"address": "vllm.ai.svc.cluster.local:8443", "workload": "vllm",
					}},
					map[string]any{"path": "/admin", "match": "prefix", "backend": map[string]any{
						"address": "admin.ops.svc.cluster.local:8443", "serverName": "admin.ops.svc", "ca": ca,
					}},
				},
			},
		},
	}
}

func encode(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hostOf(m map[string]any) map[string]any {
	return m["hosts"].(map[string]any)["app.example"].(map[string]any)
}

func routeOf(m map[string]any, i int) map[string]any {
	return hostOf(m)["routes"].([]any)[i].(map[string]any)
}

func backendOf(m map[string]any, i int) map[string]any {
	return routeOf(m, i)["backend"].(map[string]any)
}

func TestParseExample(t *testing.T) {
	m, err := Parse(readExample(t))
	if err != nil {
		t.Fatalf("Parse(example) = %v, want nil", err)
	}
	if got, want := m.Revision, uint64(12); got != want {
		t.Errorf("Revision = %d, want %d", got, want)
	}
	if got, want := m.NotBefore, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", got, want)
	}
	if got, want := m.MaxAge, 24*time.Hour; got != want {
		t.Errorf("MaxAge = %v, want %v", got, want)
	}
	routes := m.Hosts["app.example"].Routes
	if len(routes) != 2 {
		t.Fatalf("len(Hosts[app.example].Routes) = %d, want 2", len(routes))
	}
	if got := routes[0]; got.Path != "/" || got.Match != MatchPrefix || got.Backend.Workload != "vllm" || got.Backend.Anchors() != nil {
		t.Errorf("Routes[0] = %+v, want prefix / to workload vllm", got)
	}
	admin := routes[1].Backend
	if admin.ServerName != "admin.ops.svc" || admin.Workload != "" || len(admin.Anchors()) != 1 {
		t.Errorf("Routes[1].Backend = %+v, want address backend admin.ops.svc with one anchor", admin)
	}
}

func TestDigestGolden(t *testing.T) {
	d := Digest(readExample(t))
	if got := hex.EncodeToString(d[:]); got != goldenDigest {
		t.Errorf("Digest(example) = %s, want %s", got, goldenDigest)
	}
}

// TestDigestExactBytes checks that two encodings of one manifest have
// different digests: the digest covers bytes, not meaning.
func TestDigestExactBytes(t *testing.T) {
	b := readExample(t)
	spaced := append([]byte(" "), b...)
	if _, err := Parse(spaced); err != nil {
		t.Fatalf("Parse(spaced example) = %v, want nil", err)
	}
	if Digest(spaced) == Digest(b) {
		t.Errorf("Digest(spaced example) = Digest(example), want different")
	}
}

func TestParseAccepts(t *testing.T) {
	ca, _, _ := newCA(t, nil)
	tests := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"D2 maximum revision", func(m map[string]any) { m["revision"] = 1<<53 - 1 }},
		{"D2 revision 1", func(m map[string]any) { m["revision"] = 1 }},
		{"D3 offset timestamp", func(m map[string]any) { m["notBefore"] = "2026-09-01T02:00:00.5+02:00" }},
		{"D4 maximum maxAgeSeconds", func(m map[string]any) { m["maxAgeSeconds"] = 1<<31 - 1 }},
		{"D5 empty hosts", func(m map[string]any) { m["hosts"] = map[string]any{} }},
		{"D5 A-label host", func(m map[string]any) {
			m["hosts"] = map[string]any{"xn--bcher-kva.example": hostOf(m)}
		}},
		{"D3 lower-case t and z", func(m map[string]any) { m["notBefore"] = "2026-09-01t00:00:00z" }},
		{"D3 leap second", func(m map[string]any) { m["notBefore"] = "2016-12-31T23:59:60Z" }},
		{"D3 unknown local offset", func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00-00:00" }},
		{"D5 0x label that is not hex", func(m map[string]any) { m["hosts"] = map[string]any{"0xrouter": hostOf(m)} }},
		{"D5 0x final label that is not hex", func(m map[string]any) { m["hosts"] = map[string]any{"app.0xg": hostOf(m)} }},
		{"D7 0x serverName that is not hex", func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin.0xrouter" }},
		{"D5 single-label host", func(m map[string]any) { m["hosts"] = map[string]any{"localhost": hostOf(m)} }},
		{"D5 numeric non-final label", func(m map[string]any) { m["hosts"] = map[string]any{"1.example": hostOf(m)} }},
		{"D6 dots inside a segment", func(m map[string]any) { routeOf(m, 1)["path"] = "/a.b/..c/.d" }},
		{"D6 trailing slash", func(m map[string]any) { routeOf(m, 1)["path"] = "/admin/" }},
		{"D6 sub-delims, colon and at", func(m map[string]any) { routeOf(m, 1)["path"] = "/a:b@c!$&'()*+,;=~" }},
		{"D7 IPv4 address", func(m map[string]any) { backendOf(m, 0)["address"] = "10.0.0.5:8443" }},
		{"D7 IPv6 address", func(m map[string]any) { backendOf(m, 0)["address"] = "[fd00::1]:443" }},
		{"D7 mixed-case server name", func(m map[string]any) { backendOf(m, 1)["serverName"] = "Admin.Ops.svc" }},
		{"D7 two anchors", func(m map[string]any) {
			other, _, _ := newCA(t, nil)
			backendOf(m, 1)["ca"] = ca + "\n" + other + "\n"
		}},
		{"D8 same path, other match", func(m map[string]any) {
			hostOf(m)["routes"] = append(hostOf(m)["routes"].([]any), map[string]any{
				"path": "/admin", "match": "exact", "backend": map[string]any{"address": "a:1", "workload": "w"},
			})
		}},
		{"D8 same route on two hosts", func(m map[string]any) {
			m["hosts"].(map[string]any)["other.example"] = hostOf(m)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := baseManifest(ca)
			tt.edit(m)
			b := encode(t, m)
			if _, err := Parse(b); err != nil {
				t.Errorf("Parse(%s) = %v, want nil", b, err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	ca, _, _ := newCA(t, nil)
	certBody := strings.TrimSuffix(strings.TrimPrefix(ca, "-----BEGIN CERTIFICATE-----\n"), "-----END CERTIFICATE-----\n")
	setHost := func(name string) func(m map[string]any) {
		return func(m map[string]any) { m["hosts"] = map[string]any{name: hostOf(m)} }
	}
	tests := []struct {
		name    string
		edit    func(m map[string]any)
		raw     string // replaces the encoded manifest when set
		wantErr string
	}{
		{name: "D1 not an object", raw: `[]`, wantErr: "must be an object"},
		{name: "D1 null", raw: `null`, wantErr: "must be an object"},
		{name: "D1 empty", raw: ``, wantErr: "route manifest: JSON document is empty or truncated"},
		{name: "D1 truncated", raw: `{"schema": `, wantErr: "route manifest: JSON document is empty or truncated"},
		{name: "D1 trailing data", raw: `{} {}`, wantErr: "exactly one JSON document"},
		{name: "D1 duplicate key", raw: `{"schema":"c8s.routes/v1","schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "duplicate"},
		{name: "D1 duplicate key written with an escape", raw: `{"schema":"c8s.routes/v1","sch\u0065ma":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "duplicate"},
		{name: "D1 duplicate route key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[{"path":"/","path":"/","match":"exact","backend":{"address":"a:1","workload":"w"}}]}}}`, wantErr: "duplicate"},
		{name: "D1 duplicate backend key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[{"path":"/","match":"exact","backend":{"address":"a:1","workload":"w","workload":"v"}}]}}}`, wantErr: "duplicate"},
		{name: "D1 nested duplicate key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[],"routes":[]}}}`, wantErr: "duplicate"},
		{name: "D1 missing schema", edit: func(m map[string]any) { delete(m, "schema") }, wantErr: `missing member "schema"`},
		{name: "D1 wrong schema", edit: func(m map[string]any) { m["schema"] = "c8s.routes/v2" }, wantErr: "schema"},
		{name: "D1 schema not a string", edit: func(m map[string]any) { m["schema"] = 1 }, wantErr: "schema: must be a string"},
		{name: "D1 schema null", edit: func(m map[string]any) { m["schema"] = nil }, wantErr: "schema: must be a string"},
		{name: "D1 unknown top-level member", edit: func(m map[string]any) { m["comment"] = "x" }, wantErr: `unknown member "comment"`},
		{name: "D1 member name in other case", edit: func(m map[string]any) { m["Revision"] = m["revision"]; delete(m, "revision") }, wantErr: `missing member "revision"`},
		{name: "D1 unknown host member", edit: func(m map[string]any) { hostOf(m)["cors"] = false }, wantErr: `unknown member "cors"`},
		{name: "D1 unknown route member", edit: func(m map[string]any) { routeOf(m, 0)["priority"] = 1 }, wantErr: `unknown member "priority"`},
		{name: "D1 unknown backend member", edit: func(m map[string]any) { backendOf(m, 0)["timeout"] = 1 }, wantErr: `unknown member "timeout"`},
		{name: "D2 revision 0", edit: func(m map[string]any) { m["revision"] = 0 }, wantErr: "revision"},
		{name: "D2 negative revision", edit: func(m map[string]any) { m["revision"] = -1 }, wantErr: "revision"},
		{name: "D2 revision 2^53", edit: func(m map[string]any) { m["revision"] = 1 << 53 }, wantErr: "revision"},
		{name: "D2 fractional revision", edit: func(m map[string]any) { m["revision"] = 1.5 }, wantErr: "revision"},
		{name: "D2 revision 1.0", raw: `{"schema":"c8s.routes/v1","revision":1.0,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "revision"},
		{name: "D2 revision 1e3", raw: `{"schema":"c8s.routes/v1","revision":1e3,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "revision"},
		{name: "D2 revision with leading zero", raw: `{"schema":"c8s.routes/v1","revision":01,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "invalid character in JSON at offset"},
		{name: "D2 revision as string", edit: func(m map[string]any) { m["revision"] = "12" }, wantErr: "revision"},
		{name: "D2 revision null", edit: func(m map[string]any) { m["revision"] = nil }, wantErr: "revision"},
		{name: "D3 date only", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01" }, wantErr: "notBefore"},
		{name: "D3 not a timestamp", edit: func(m map[string]any) { m["notBefore"] = "yesterday" }, wantErr: "notBefore"},
		{name: "D3 comma before fraction", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00,5Z" }, wantErr: "notBefore"},
		{name: "D3 one-digit hour", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T0:00:00Z" }, wantErr: "notBefore"},
		{name: "D3 offset hour 24", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+24:00" }, wantErr: "notBefore"},
		{name: "D3 offset minute 60", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+00:60" }, wantErr: "notBefore"},
		{name: "D3 offset without colon", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+0000" }, wantErr: "notBefore"},
		{name: "D3 empty fraction", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00.Z" }, wantErr: "notBefore"},
		{name: "D3 space separator", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01 00:00:00Z" }, wantErr: "notBefore"},
		{name: "D3 February 30", edit: func(m map[string]any) { m["notBefore"] = "2026-02-30T00:00:00Z" }, wantErr: "notBefore: parsing time \"2026-02-30T00:00:00Z\": day out of range"},
		{name: "D3 non-ASCII digit", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:0\u0661Z" }, wantErr: "notBefore"},
		{name: "D3 number", edit: func(m map[string]any) { m["notBefore"] = 1756684800 }, wantErr: "notBefore"},
		{name: "D4 zero", edit: func(m map[string]any) { m["maxAgeSeconds"] = 0 }, wantErr: "maxAgeSeconds"},
		{name: "D4 2^31", edit: func(m map[string]any) { m["maxAgeSeconds"] = 1 << 31 }, wantErr: "maxAgeSeconds"},
		{name: "D4 fractional", edit: func(m map[string]any) { m["maxAgeSeconds"] = 0.5 }, wantErr: "maxAgeSeconds"},
		{name: "D5 hosts not an object", edit: func(m map[string]any) { m["hosts"] = []any{} }, wantErr: "hosts: must be an object"},
		{name: "D5 hosts null", edit: func(m map[string]any) { m["hosts"] = nil }, wantErr: "hosts: must be an object"},
		{name: "D5 upper-case host", edit: setHost("App.example"), wantErr: "lower-case DNS host name"},
		{name: "D5 host with port", edit: setHost("app.example:443"), wantErr: "lower-case DNS host name"},
		{name: "D5 trailing dot", edit: setHost("app.example."), wantErr: "lower-case DNS host name"},
		{name: "D5 IPv4 literal", edit: setHost("10.0.0.1"), wantErr: "must not be an IP literal"},
		{name: "D5 IPv6 literal", edit: setHost("[::1]"), wantErr: "lower-case DNS host name"},
		{name: "D5 bare IPv6 literal", edit: setHost("::1"), wantErr: "must not be an IP literal"},
		{name: "D5 numeric final label", edit: setHost("app.123"), wantErr: "final label must not be numeric"},
		{name: "D5 hex final label", edit: setHost("app.0x7f"), wantErr: "final label must not be numeric"},
		{name: "D5 bare 0x final label", edit: setHost("app.0x"), wantErr: "final label must not be numeric"},
		{name: "D5 U-label", edit: setHost("bücher.example"), wantErr: "lower-case DNS host name"},
		{name: "D5 wildcard", edit: setHost("*.example"), wantErr: "lower-case DNS host name"},
		{name: "D5 underscore", edit: setHost("a_b.example"), wantErr: "lower-case DNS host name"},
		{name: "D5 leading hyphen", edit: setHost("-a.example"), wantErr: "lower-case DNS host name"},
		{name: "D5 empty label", edit: setHost("a..example"), wantErr: "lower-case DNS host name"},
		{name: "D5 label over 63 octets", edit: setHost(strings.Repeat("a", 64) + ".example"), wantErr: "lower-case DNS host name"},
		{name: "D5 name over 253 octets", edit: setHost(strings.Repeat("a.", 127) + "ab"), wantErr: "lower-case DNS host name"},
		{name: "D5 empty host name", edit: setHost(""), wantErr: "lower-case DNS host name"},
		{name: "D5 empty routes", edit: func(m map[string]any) { hostOf(m)["routes"] = []any{} }, wantErr: "must not be empty"},
		{name: "D5 routes missing", edit: func(m map[string]any) { delete(hostOf(m), "routes") }, wantErr: `missing member "routes"`},
		{name: "D5 routes null", edit: func(m map[string]any) { hostOf(m)["routes"] = nil }, wantErr: "must be a list"},
		{name: "D5 host not an object", edit: func(m map[string]any) { m["hosts"] = map[string]any{"a.example": []any{}} }, wantErr: "must be an object"},
		{name: "D6 relative path", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "admin" }, wantErr: `must begin with "/"`},
		{name: "D6 empty path", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "" }, wantErr: `must begin with "/"`},
		{name: "D6 query", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a?b" }, wantErr: "percent-encoding"},
		{name: "D6 fragment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a#b" }, wantErr: "percent-encoding"},
		{name: "D6 percent-encoding", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a%20b" }, wantErr: "percent-encoding"},
		{name: "D6 empty segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a//b" }, wantErr: `"//"`},
		{name: "D6 dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/./b" }, wantErr: "segment"},
		{name: "D6 trailing dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/." }, wantErr: "segment"},
		{name: "D6 dot-dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/../b" }, wantErr: "segment"},
		{name: "D6 root dot-dot", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/.." }, wantErr: "segment"},
		{name: "D6 space", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a b" }, wantErr: "not allowed in a URI path"},
		{name: "D6 raw non-ASCII", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/caf\u00e9" }, wantErr: "not allowed in a URI path"},
		{name: "D6 backslash", edit: func(m map[string]any) { routeOf(m, 1)["path"] = `/a\b` }, wantErr: "not allowed in a URI path"},
		{name: "D6 control byte", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a\tb" }, wantErr: "not allowed in a URI path"},
		{name: "D6 unknown match", edit: func(m map[string]any) { routeOf(m, 1)["match"] = "regex" }, wantErr: "match"},
		{name: "D6 upper-case match", edit: func(m map[string]any) { routeOf(m, 1)["match"] = "Prefix" }, wantErr: "match"},
		{name: "D6 missing match", edit: func(m map[string]any) { delete(routeOf(m, 1), "match") }, wantErr: `missing member "match"`},
		{name: "D6 missing path", edit: func(m map[string]any) { delete(routeOf(m, 1), "path") }, wantErr: `missing member "path"`},
		{name: "D6 missing backend", edit: func(m map[string]any) { delete(routeOf(m, 1), "backend") }, wantErr: `missing member "backend"`},
		{name: "D7 missing address", edit: func(m map[string]any) { delete(backendOf(m, 0), "address") }, wantErr: `missing member "address"`},
		{name: "D7 address without port", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm.ai.svc" }, wantErr: "host:port"},
		{name: "D7 address with empty host", edit: func(m map[string]any) { backendOf(m, 0)["address"] = ":8443" }, wantErr: "address"},
		{name: "D7 address with URL scheme", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "https://vllm:8443" }, wantErr: "address"},
		{name: "D7 port 0", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:0" }, wantErr: "port"},
		{name: "D7 port 65536", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:65536" }, wantErr: "port"},
		{name: "D7 port with leading zero", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:08443" }, wantErr: "port"},
		{name: "D7 named port", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:https" }, wantErr: "port"},
		{name: "D7 IPv6 zone", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "[fe80::1%eth0]:443" }, wantErr: "address"},
		{name: "D7 invalid workload name", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = "a/b" }, wantErr: "workload name"},
		{name: "D7 empty workload name", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = "" }, wantErr: "workload name"},
		{name: "D7 workload not a string", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = 1 }, wantErr: "workload: must be a string"},
		{name: "D7 workload and address backend", edit: func(m map[string]any) { backendOf(m, 1)["workload"] = "vllm" }, wantErr: "exactly one"},
		{name: "D7 serverName without ca", edit: func(m map[string]any) { delete(backendOf(m, 1), "ca") }, wantErr: "exactly one"},
		{name: "D7 ca without serverName", edit: func(m map[string]any) { delete(backendOf(m, 1), "serverName") }, wantErr: "exactly one"},
		{name: "D7 workload with ca", edit: func(m map[string]any) { backendOf(m, 0)["ca"] = ca }, wantErr: "exactly one"},
		{name: "D7 invalid serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin_ops" }, wantErr: "serverName"},
		{name: "D7 upper-case hex final label serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin.0X7F" }, wantErr: "serverName: final label must not be numeric"},
		{name: "D7 IP serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "10.0.0.1" }, wantErr: "serverName"},
		{name: "D7 empty ca", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = "" }, wantErr: "at least one CERTIFICATE"},
		{name: "D7 whitespace ca", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = " \n" }, wantErr: "at least one CERTIFICATE"},
		{name: "D7 ca with private key block", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = ca + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}, wantErr: "not a CERTIFICATE"},
		{name: "D7 ca with leading text", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = "subject=test\n" + ca }, wantErr: "outside PEM blocks"},
		{name: "D7 ca with trailing text", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = ca + "garbage" }, wantErr: "outside PEM blocks"},
		{name: "D7 ca with malformed block before a good one", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\n!!\n" + ca
		}, wantErr: "malformed PEM block"},
		{name: "D7 ca with PEM headers", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n" + certBody + "-----END CERTIFICATE-----\n"
		}, wantErr: "headers"},
		{name: "D7 ca with invalid DER", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}, wantErr: "certificate 0"},
		{name: "D7 ca not a string", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = []any{ca} }, wantErr: "ca: must be a string"},
		{name: "D8 duplicate path and match", edit: func(m map[string]any) {
			hostOf(m)["routes"] = append(hostOf(m)["routes"].([]any), map[string]any{
				"path": "/admin", "match": "prefix", "backend": map[string]any{"address": "a:1", "workload": "w"},
			})
		}, wantErr: `another route has path "/admin"`},
		{name: "D9 plaintext protocol", edit: func(m map[string]any) { backendOf(m, 0)["protocol"] = "http" }, wantErr: `unknown member "protocol"`},
		{name: "D9 backend without peer verification", edit: func(m map[string]any) { delete(backendOf(m, 0), "workload") }, wantErr: "exactly one"},
		{name: "D9 insecure skip verify", edit: func(m map[string]any) {
			delete(backendOf(m, 1), "ca")
			backendOf(m, 1)["insecureSkipVerify"] = true
		}, wantErr: `unknown member "insecureSkipVerify"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := []byte(tt.raw)
			if tt.edit != nil {
				m := baseManifest(ca)
				tt.edit(m)
				b = encode(t, m)
			}
			_, err := Parse(b)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse(%.200s) = %v, want error containing %q", b, err, tt.wantErr)
			}
		})
	}
}

func TestCheckAnchorsExclude(t *testing.T) {
	ca, caCert, caKey := newCA(t, nil)
	_, otherCert, _ := newCA(t, nil)
	_, reissued, _ := newCA(t, caKey)
	m, err := Parse(encode(t, baseManifest(ca)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		excluded []*x509.Certificate
		wantErr  bool
	}{
		{"no exclusions", nil, false},
		{"other CA", []*x509.Certificate{otherCert}, false},
		{"same certificate", []*x509.Certificate{otherCert, caCert}, true},
		{"same key, other certificate", []*x509.Certificate{reissued}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.CheckAnchorsExclude(tt.excluded)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAnchorsExclude(%s) = %v, want error %v", tt.name, err, tt.wantErr)
			}
		})
	}

	t.Run("intermediate issued by an excluded CA", func(t *testing.T) {
		m, err := Parse(encode(t, baseManifest(newIntermediate(t, caCert, caKey))))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.CheckAnchorsExclude([]*x509.Certificate{caCert}); err == nil || !strings.Contains(err.Error(), "issued by excluded CA") {
			t.Errorf("CheckAnchorsExclude(root of ca) = %v, want error containing %q", err, "issued by excluded CA")
		}
	})
}

// newIntermediate returns an intermediate CA certificate, with a fresh key,
// that parent and parentKey issued.
func newIntermediate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func FuzzParse(f *testing.F) {
	f.Add(readExample(f))
	f.Add([]byte(`{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`))
	f.Add([]byte(`{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[{"path":"/","match":"exact","backend":{"address":"a:1","workload":"w"}}]}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		if m.Revision < 1 || m.Revision > maxRevision || m.MaxAge < time.Second {
			t.Fatalf("Parse(%q) = revision %d, maxAge %v; want both in range", b, m.Revision, m.MaxAge)
		}
		for name, h := range m.Hosts {
			if checkHostKey(name) != nil || len(h.Routes) == 0 {
				t.Fatalf("Parse(%q) accepted host %q with %d routes", b, name, len(h.Routes))
			}
			for _, r := range h.Routes {
				if checkRoutePath(r.Path) != nil {
					t.Fatalf("Parse(%q) accepted path %q", b, r.Path)
				}
				if got, ok := NormalizePath(r.Path); !ok || got != r.Path {
					t.Fatalf("NormalizePath(%q) = %q, %v; want the manifest path unchanged", r.Path, got, ok)
				}
				if (r.Backend.Workload == "") == (r.Backend.ServerName == "") {
					t.Fatalf("Parse(%q) accepted backend %+v", b, r.Backend)
				}
			}
		}
		table := Compile(m, nil)
		for name, h := range m.Hosts {
			for _, r := range h.Routes {
				if _, _, ok := table.lookup(name, r.Path); !ok {
					t.Fatalf("lookup(%q, %q) matched nothing, want a route", name, r.Path)
				}
			}
		}
	})
}

func TestParseTimestampLeapSecond(t *testing.T) {
	tests := []struct {
		in   string
		want time.Time // zero means rejected
	}{
		{"2016-12-31T23:59:60Z", time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2015-06-30T23:59:60Z", time.Date(2015, 7, 1, 0, 0, 0, 0, time.UTC)},
		{"2016-12-31T18:59:60-05:00", time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2026-09-01T12:34:60Z", time.Time{}},
		{"2016-12-31T23:59:60+01:00", time.Time{}},
		{"2016-12-30T23:59:60Z", time.Time{}},
	}
	for _, tt := range tests {
		got, err := parseTimestamp(tt.in)
		if tt.want.IsZero() {
			if err == nil {
				t.Errorf("parseTimestamp(%q) = %v, want an error", tt.in, got)
			}
		} else if err != nil || !got.Equal(tt.want) {
			t.Errorf("parseTimestamp(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
		}
	}
}

// TestAnchorsCopies checks that a caller changing the certificates Anchors
// returns cannot change the trust material of a compiled Table.
func TestAnchorsCopies(t *testing.T) {
	m, err := Parse(readExample(t))
	if err != nil {
		t.Fatal(err)
	}
	table := Compile(m, nil)
	backend := func() Backend {
		r, _, ok := table.lookup("app.example", "/admin")
		if !ok {
			t.Fatal("lookup(app.example, /admin) matched nothing")
		}
		return r.Backend
	}
	want := backend().Anchors()[0].Raw
	got := backend().Anchors()[0]
	got.Raw[0] ^= 0xff
	got.PublicKey = nil
	got.IsCA = false
	m.Hosts["app.example"].Routes[1].Backend.Anchors()[0].Raw[1] ^= 0xff
	again := backend().Anchors()[0]
	if !bytes.Equal(again.Raw, want) || again.PublicKey == nil || !again.IsCA {
		t.Errorf("Anchors() after the caller changed earlier results = %x, want the parsed CA unchanged", again.Raw[:4])
	}
}
