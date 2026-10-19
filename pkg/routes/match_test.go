package routes

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
)

var testReserved = []string{"/allowlist", "/.well-known/c8s/", "/healthz"}

func route(path string, match MatchKind, workload string) Route {
	return Route{Path: path, Match: match, Backend: Backend{Address: workload + ":8443", Workload: workload}}
}

func testManifest(routes ...Route) *Manifest {
	return &Manifest{Revision: 1, Hosts: map[string]Host{
		"app.example":    {Routes: routes},
		"kelvin.example": {Routes: []Route{route("/", MatchPrefix, "kelvin")}},
	}}
}

var selectRoutes = []Route{
	route("/", MatchPrefix, "root"),
	route("/admin", MatchPrefix, "admin"),
	route("/admin/api", MatchPrefix, "api"),
	route("/admin/login", MatchExact, "login"),
	route("/static/", MatchPrefix, "static"),
	route("/healthz", MatchExact, "shadowed"),
	route("/exact", MatchExact, "exact"),
	route("/exact", MatchPrefix, "exact-prefix"),
}

func TestLookup(t *testing.T) {
	table := Compile(testManifest(selectRoutes...), testReserved)
	tests := []struct {
		name, host, path string
		wantWorkload     string // empty: no route
		wantPath         string
	}{
		{"M3 prefix equal", "app.example", "/admin", "admin", "/admin"},
		{"M3 prefix child", "app.example", "/admin/users", "admin", "/admin/users"},
		{"M3 prefix is not a string prefix", "app.example", "/administrator", "root", "/administrator"},
		{"M3 prefix with trailing slash", "app.example", "/static/app.js", "static", "/static/app.js"},
		{"M3 trailing-slash prefix needs the slash", "app.example", "/static", "root", "/static"},
		{"M3 root", "app.example", "/", "root", "/"},
		{"M2 longest prefix", "app.example", "/admin/api/v1", "api", "/admin/api/v1"},
		{"M2 exact before prefix", "app.example", "/admin/login", "login", "/admin/login"},
		{"M2 exact route is not a prefix", "app.example", "/admin/login/x", "admin", "/admin/login/x"},
		{"M2 exact beats prefix at same path", "app.example", "/exact", "exact", "/exact"},
		{"M2 prefix route at an exact route's path, child request", "app.example", "/exact/x", "exact-prefix", "/exact/x"},
		{"M1 host case-insensitive", "APP.Example", "/admin", "admin", "/admin"},
		{"M1 host port dropped", "app.example:443", "/admin", "admin", "/admin"},
		{"M1 host case and port", "App.Example:8443", "/", "root", "/"},
		{"M1 unknown host", "other.example", "/", "", ""},
		{"M1 trailing dot is another host", "app.example.", "/", "", ""},
		{"M1 empty host", "", "/", "", ""},
		{"M1 Kelvin sign does not fold to k", "Kelvin.example", "/", "", ""},
		{"M4 decoded before matching", "app.example", "/%61dmin", "admin", "/admin"},
		{"M4 dot segments resolved before matching", "app.example", "/static/../admin/", "admin", "/admin/"},
		{"M4 encoded dot-dot resolved before matching", "app.example", "/static/%2e%2e/admin", "admin", "/admin"},
		{"M4 empty segment matches nothing", "app.example", "//admin", "", ""},
		{"M4 inner empty segment matches nothing", "app.example", "/admin//users", "", ""},
		{"M4 trailing empty segment matches nothing", "app.example", "/admin//", "", ""},
		{"M4 trailing slash still matches the prefix route", "app.example", "/admin/", "admin", "/admin/"},
		{"M4 raw bytes, not a re-encoded URL path", "app.example", "/x|%2F..%2Fadmin", "", ""},
		{"M4 encoded slash matches nothing", "app.example", "/admin%2Fusers", "", ""},
		{"M4 dot-dot above root matches nothing", "app.example", "/../admin", "", ""},
		{"M6 reserved exact path", "app.example", "/allowlist", "", ""},
		{"M6 reserved path child", "app.example", "/allowlist/workloads/x", "", ""},
		{"M6 reserved trailing-slash prefix", "app.example", "/.well-known/c8s/routes", "", ""},
		{"M6 manifest route under reserved path", "app.example", "/healthz", "", ""},
		{"M6 reserved path reached by dot segments", "app.example", "/admin/../allowlist", "", ""},
		{"M6 reserved path reached by encoding", "app.example", "/%61llowlist", "", ""},
		{"M6 not reserved: string prefix only", "app.example", "/allowlistx", "root", "/allowlistx"},
		{"M6 not reserved: sibling", "app.example", "/healthz-ui", "root", "/healthz-ui"},
		{"M6 reserved on every host", "kelvin.example", "/allowlist", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, path, ok := table.lookup(tt.host, tt.path)
			if tt.wantWorkload == "" {
				if ok {
					t.Errorf("lookup(%q, %q) = %q, %q; want no route", tt.host, tt.path, r.Backend.Workload, path)
				}
				return
			}
			if !ok || r.Backend.Workload != tt.wantWorkload || path != tt.wantPath {
				t.Errorf("lookup(%q, %q) = %q, %q, %v; want %q, %q, true", tt.host, tt.path, r.Backend.Workload, path, ok, tt.wantWorkload, tt.wantPath)
			}
		})
	}
}

// TestLookupIgnoresRouteOrder checks M2's last clause over every rotation and
// the reversal of the route list.
func TestLookupIgnoresRouteOrder(t *testing.T) {
	paths := []string{"/", "/admin", "/admin/api", "/admin/api/x", "/admin/login", "/admin/login/x", "/static/a", "/exact", "/exact/y", "/zzz"}
	want := Compile(testManifest(selectRoutes...), testReserved)
	var orders [][]Route
	for i := range selectRoutes {
		orders = append(orders, append(append([]Route{}, selectRoutes[i:]...), selectRoutes[:i]...))
	}
	reversed := make([]Route, 0, len(selectRoutes))
	for i := len(selectRoutes) - 1; i >= 0; i-- {
		reversed = append(reversed, selectRoutes[i])
	}
	orders = append(orders, reversed)
	for i, order := range orders {
		got := Compile(testManifest(order...), testReserved)
		for _, p := range paths {
			wr, _, wok := want.lookup("app.example", p)
			gr, _, gok := got.lookup("app.example", p)
			if wok != gok || wr.Backend.Workload != gr.Backend.Workload {
				t.Errorf("order %d: lookup(app.example, %q) = %q, %v; want %q, %v", i, p, gr.Backend.Workload, gok, wr.Backend.Workload, wok)
			}
		}
	}
}

func TestLookupNilTable(t *testing.T) {
	var table *Table
	if r, path, ok := table.lookup("app.example", "/"); ok {
		t.Errorf("(*Table)(nil).lookup(app.example, /) = %+v, %q, true; want no route", r, path)
	}
}

func TestLookupEmptyHosts(t *testing.T) {
	table := Compile(&Manifest{Revision: 1, Hosts: map[string]Host{}}, nil)
	if r, path, ok := table.lookup("app.example", "/"); ok {
		t.Errorf("lookup(app.example, /) with no hosts = %+v, %q, true; want no route", r, path)
	}
}

func TestCompileNilManifest(t *testing.T) {
	if r, path, ok := Compile(nil, testReserved).lookup("app.example", "/"); ok {
		t.Errorf("Compile(nil).lookup(app.example, /) = %+v, %q, true; want no route", r, path)
	}
}

func TestCompileRejectsUnnormalizedReserved(t *testing.T) {
	for _, r := range []string{"", "allowlist", "/a/../b", "/%61", "/a//b", "/a%2fb"} {
		t.Run(r, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("Compile(_, [%q]) did not panic, want a panic", r)
				}
			}()
			Compile(nil, []string{r})
		})
	}
}

// TestSelectForwards checks the request target an upstream receives through
// a reverse proxy that routes with Select (B6), and that a request matching
// no route never reaches it (M5).
func TestSelectForwards(t *testing.T) {
	var mu sync.Mutex
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.RequestURI)
		mu.Unlock()
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	table := Compile(testManifest(selectRoutes...), testReserved)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, u, ok := table.Select(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		u.Scheme, u.Host = target.Scheme, target.Host
		(&httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.Out.URL = u }}).ServeHTTP(w, r)
	}))
	defer router.Close()

	tests := []struct {
		target string
		want   string // empty: 404, upstream not reached
	}{
		{"/admin/users?b=1&a=%2F", "/admin/users?b=1&a=%2F"},
		{"/%61dmin/a%3fb", "/admin/a%3Fb"},
		{"/static/../admin/x;y=1!", "/admin/x;y=1!"},
		{"/a?", "/a?"},
		{"/admin/%E2%82%AC", "/admin/%E2%82%AC"},
		{"/x|%2F..%2Fadmin", ""},
		{"//admin", ""},
		{"/admin%2Fusers", ""},
		{"/../admin", ""},
		{"/allowlist", ""},
		{"/%61llowlist?x=1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			mu.Lock()
			got = nil
			mu.Unlock()
			conn, err := net.Dial("tcp", router.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("GET " + tt.target + " HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if tt.want == "" {
				if resp.StatusCode != http.StatusNotFound || len(got) != 0 {
					t.Errorf("GET %s = %d, upstream saw %q; want 404 and no upstream request", tt.target, resp.StatusCode, got)
				}
				return
			}
			if resp.StatusCode != http.StatusOK || len(got) != 1 || got[0] != tt.want {
				t.Errorf("GET %s = %d, upstream saw %q; want 200 and %q", tt.target, resp.StatusCode, got, tt.want)
			}
		})
	}
}

func TestSelectNeedsOriginForm(t *testing.T) {
	table := Compile(testManifest(selectRoutes...), testReserved)
	for _, uri := range []string{"", "*", "http://app.example/admin"} {
		r := &http.Request{Host: "app.example", RequestURI: uri, URL: &url.URL{Path: "/admin"}}
		if _, u, ok := table.Select(r); ok {
			t.Errorf("Select(RequestURI %q) = %v, true; want no route", uri, u)
		}
	}
	if _, u, ok := (*Table)(nil).Select(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Errorf("(*Table)(nil).Select(/) = %v, true; want no route", u)
	}
}
