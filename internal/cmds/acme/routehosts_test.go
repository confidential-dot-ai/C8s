package acme

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The names the certificate covers are the launch hostnames plus the hosts of
// the route manifest the router applied, deduplicated and sorted; a name no
// certificate can carry is left out rather than failing the whole order.
func TestCertificateNamesMergeTheRouteHosts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hosts string // unset writes no file: the router has applied no manifest
		want  []string
	}{
		{
			name: "no manifest applied",
			want: []string{"infer.lb.example.com", "lb.example.com"},
		},
		{
			name:  "manifest hosts beside the launch names",
			hosts: "route.example\nlb.example.com\n",
			want:  []string{"infer.lb.example.com", "lb.example.com", "route.example"},
		},
		{
			name:  "a name no certificate can carry",
			hosts: "*.example\nroute.example\n",
			want:  []string{"infer.lb.example.com", "lb.example.com", "route.example"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newManager("", "", t.TempDir(), t.TempDir(), testDomains, slog.Default())
			mgr.routeHostsFile = filepath.Join(t.TempDir(), "hosts")
			if tc.hosts != "" {
				if err := os.WriteFile(mgr.routeHostsFile, []byte(tc.hosts), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			mgr.refreshDomains()
			if !slices.Equal(mgr.domains, tc.want) {
				t.Fatalf("certificate names = %v, want %v", mgr.domains, tc.want)
			}
		})
	}
}

// A hosts file that cannot be read leaves the names in place, so no order
// follows a read failure.
func TestUnreadableRouteHostsKeepTheNames(t *testing.T) {
	mgr := newManager("", "", t.TempDir(), t.TempDir(), testDomains, slog.Default())
	mgr.routeHostsFile = filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(mgr.routeHostsFile, []byte("route.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr.refreshDomains()
	applied := slices.Clone(mgr.domains)

	if err := os.Remove(mgr.routeHostsFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mgr.routeHostsFile, 0o700); err != nil {
		t.Fatal(err)
	}
	mgr.refreshDomains()
	if !slices.Equal(mgr.domains, applied) {
		t.Fatalf("certificate names = %v, want the applied %v", mgr.domains, applied)
	}
}

// A manifest host reaches the certificate without a relaunch, and a name set
// the certificate already covers orders nothing.
func TestRouteHostsReorderTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	mgr.routeHostsFile = filepath.Join(t.TempDir(), "hosts")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr.refreshDomains()
	mgr.ensure(ctx)
	issued := readFile(t, mgr.certPath())

	mgr.refreshDomains()
	mgr.ensure(ctx)
	if string(readFile(t, mgr.certPath())) != string(issued) {
		t.Fatal("an unchanged name set ordered another certificate")
	}

	if err := os.WriteFile(mgr.routeHostsFile, []byte("route.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr.refreshDomains()
	mgr.ensure(ctx)
	leaf, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"infer.lb.example.com", "lb.example.com", "route.example"}
	got := slices.Sorted(slices.Values(leaf.DNSNames))
	if !slices.Equal(got, want) {
		t.Fatalf("certificate covers %v, want %v", got, want)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A route hosts file paces the run loop at the retry interval, so a host the
// manifest adds reaches the certificate within a minute.
func TestRouteHostsPaceTheRunLoop(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)
	if mgr.pace() != mgr.recheck {
		t.Fatalf("pace without a route hosts file = %v, want %v", mgr.pace(), mgr.recheck)
	}
	mgr.routeHostsFile = filepath.Join(t.TempDir(), "hosts")
	if mgr.pace() != mgr.retry {
		t.Fatalf("pace with a route hosts file = %v, want %v", mgr.pace(), mgr.retry)
	}
}
