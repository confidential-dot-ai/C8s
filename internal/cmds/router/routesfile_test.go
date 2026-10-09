package router

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRoutes puts a routes file on disk and returns its path.
func writeRoutes(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validRoutes = `{
  "backend": {"address": "c8s-vllm.default.svc.cluster.local:8000", "protocol": "http"},
  "routes": [{"path": "/v1/models", "match": "exact",
    "backend": {"address": "cds.c8s-system.svc.cluster.local:8443", "protocol": "https"}}]
}`

func TestRoutesFileRendersTheSameShapeAsTheFlags(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{}
	loaded, err := readRoutesFile(cfg, writeRoutes(t, validRoutes))
	if err != nil {
		t.Fatalf("readRoutesFile: %v", err)
	}
	conf, err := Render(loaded)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"set $backend_addr c8s-vllm.default.svc.cluster.local:8000;",
		"location = /v1/models {",
		"proxy_ssl_verify on;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
}

// A baked front door can be built with no backend at all: its flags name the
// resolver, and the first backend arrives in the routes file at runtime. The
// resolver is what makes that work — without one, a name the image was not
// built with has nothing to resolve it.
func TestRoutesFileAddsTheFirstBackend(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{}
	cfg.Routes = nil
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("a front door built with no backend does not start: %v", err)
	}
	loaded, err := readRoutesFile(cfg, writeRoutes(t, validRoutes))
	if err != nil {
		t.Fatalf("a routes file naming the first backend was refused: %v", err)
	}
	conf, err := Render(loaded)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(conf, "c8s-vllm.default.svc.cluster.local:8000") {
		t.Error("the backend the file added is not in the configuration")
	}
	unresolved := cfg
	unresolved.Resolver = ""
	if _, err := readRoutesFile(unresolved, writeRoutes(t, validRoutes)); err == nil {
		t.Error("a routes file naming a backend was accepted with no resolver")
	}
}

// The file goes through the flags' refusals: it carries data, never a
// directive, and never a hop the flags would refuse.
func TestRoutesFileRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "not JSON",
			body: "backend: vllm:8000",
			want: "routes.json",
		},
		{
			name: "unknown field",
			body: `{"directives": "return 200"}`,
			want: "unknown field",
		},
		{
			name: "plaintext route",
			body: `{"routes": [{"path": "/x", "match": "prefix",
				"backend": {"address": "svc.c8s-system.svc.cluster.local:8080", "protocol": "http"}}]}`,
			want: "must reach its backend over https",
		},
		{
			name: "route carrying a directive",
			body: `{"routes": [{"path": "/x; return 200", "match": "prefix",
				"backend": {"address": "svc.c8s-system.svc.cluster.local:8443", "protocol": "https"}}]}`,
			want: "--route path",
		},
		{
			name: "plaintext catch-all that is not an adopted workload",
			body: `{"backend": {"address": "vllm.default.svc:8000", "protocol": "http"}}`,
			want: "must authenticate itself over https",
		},
		{
			name: "address carrying an nginx variable",
			body: `{"backend": {"address": "$host:8000", "protocol": "http"}}`,
			want: "--backend address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Backend = Backend{}
			_, err := readRoutesFile(cfg, writeRoutes(t, tc.body))
			if err == nil {
				t.Fatal("readRoutesFile accepted the file")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// A file the renderer refuses, and one nginx itself refuses, both leave the
// configuration on disk untouched, so the front door keeps serving what it
// has and a restart comes up on it too.
func TestRoutesFileKeepsTheLastGoodConfiguration(t *testing.T) {
	dir, _ := fakeNginx(t)
	nginx := filepath.Join(dir, "nginx")
	path := writeRoutes(t, validRoutes)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	front := frontDoor{
		cfg:        validConfig(),
		routesFile: path,
		conf:       conf,
	}
	if err := front.rerender(context.Background(), nginx); err != nil {
		t.Fatalf("rerender: %v", err)
	}
	good, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"routes": [{"path": "/x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := front.rerender(context.Background(), nginx); err == nil {
		t.Fatal("rerender accepted a file the renderer refuses")
	}
	// Valid route data whose configuration nginx will not load: the staged
	// file is tested before it replaces the live one.
	if err := os.WriteFile(path, []byte(validRoutes), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refuse"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := front.rerender(context.Background(), nginx); err == nil {
		t.Fatal("rerender replaced the live configuration with one nginx refuses")
	}
	after, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(good) {
		t.Error("a refused file replaced the configuration nginx is serving")
	}
}

// A valid file is the whole route set: a backend it no longer names is gone
// from the rendered configuration.
func TestRoutesFileRemovesAWithdrawnRoute(t *testing.T) {
	path := writeRoutes(t, validRoutes)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	front := frontDoor{
		cfg:        validConfig(),
		routesFile: path,
		conf:       conf,
	}
	dir, _ := fakeNginx(t)
	nginx := filepath.Join(dir, "nginx")
	if err := front.rerender(context.Background(), nginx); err != nil {
		t.Fatalf("rerender: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"backend": {"address": "c8s-vllm.default.svc.cluster.local:8000", "protocol": "http"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := front.rerender(context.Background(), nginx); err != nil {
		t.Fatalf("rerender: %v", err)
	}
	after, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "/v1/models") {
		t.Error("a route the file removed is still in the configuration")
	}
}

// The file is the baked lane's source and the flags are the install lane's.
func TestRoutesFileRefusesTheFlagsBeside(t *testing.T) {
	cmd := NewCmd()
	if err := cmd.Flags().Parse([]string{"--routes-file=/mnt/c8s-data/router-routes/routes.json", "--backend=vllm:8000"}); err != nil {
		t.Fatal(err)
	}
	if err := requireOneRouteSource(cmd); err == nil {
		t.Fatal("a front door took both route sources")
	}
}
