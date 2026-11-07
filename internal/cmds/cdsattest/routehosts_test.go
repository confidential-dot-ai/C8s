package cdsattest

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

func TestRouteHostsWriter(t *testing.T) {
	if routeHostsWriter("", slog.Default()) != nil {
		t.Fatal("a writer without a path")
	}
	path := filepath.Join(t.TempDir(), "hosts")
	write := routeHostsWriter(path, slog.Default())
	applied := func(hosts ...string) *routing.Applied {
		m := &routes.Manifest{Hosts: map[string]routes.Host{}}
		for _, h := range hosts {
			m.Hosts[h] = routes.Host{}
		}
		return &routing.Applied{Manifest: m}
	}
	read := func() string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	write(applied())
	if got := read(); got != "" {
		t.Fatalf("empty manifest wrote %q", got)
	}
	write(applied("b.example.com", "a.example.com"))
	if got := read(); got != "a.example.com\nb.example.com\n" {
		t.Fatalf("hosts file = %q", got)
	}
	// An unchanged set is not rewritten.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	write(applied("a.example.com", "b.example.com"))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rewrote an unchanged set")
	}
	write(applied("a.example.com"))
	if got := read(); got != "a.example.com\n" {
		t.Fatalf("after removal = %q", got)
	}
}
