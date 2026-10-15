package nriimagepolicy

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The advertise host is what CDS dials back. Getting it wrong took the plugin
// down on a stock install once already: route inference against the chart's
// default CDS URL (the NodePort on loopback) yields loopback, which is not a
// routable address. These pin each source and that regression.
func TestDigestsAdvertiseHost(t *testing.T) {
	const loopbackCDS = "https://127.0.0.1:30808"

	t.Run("explicit config wins", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.AdvertiseHost = "10.1.2.3"
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.1.2.3" {
			t.Fatalf("host = %q, err = %v; want 10.1.2.3", got, err)
		}
	})

	t.Run("installer node-ip file is used when config is empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, NodeIPFile), []byte("10.4.5.6\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = dir
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.4.5.6" {
			t.Fatalf("host = %q, err = %v; want 10.4.5.6", got, err)
		}
	})

	t.Run("environment is the last source, for the baked node image", func(t *testing.T) {
		t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "10.7.8.9")
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir() // no node-ip file
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.7.8.9" {
			t.Fatalf("host = %q, err = %v; want 10.7.8.9", got, err)
		}
	})

	// The regression: with no source at all, inference runs against a loopback
	// CDS URL and yields loopback, which must be rejected rather than
	// advertised. It fails here, at startup, not as an unreachable callback.
	t.Run("loopback CDS URL alone is rejected", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir()
		cfg.Allowlist.Pull.URL = loopbackCDS
		if got, err := digestsAdvertiseHost(cfg); err == nil {
			t.Fatalf("host = %q, want an error: loopback is not an address CDS can dial back", got)
		}
	})
}

// Components trust node-ip as their verifier address, so it comes from the
// host's own view, never from a pod.
func TestPublishNodeIP(t *testing.T) {
	hostInterface := func(ip net.IP, err error) {
		orig := chooseHostInterface
		chooseHostInterface = func() (net.IP, error) { return ip, err }
		t.Cleanup(func() { chooseHostInterface = orig })
	}
	for _, tc := range []struct {
		name          string
		advertiseHost string
		hostIP        net.IP
		hostErr       error
		want          string // "" means no file
	}{
		{name: "host interface", hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "advertise host IP wins", advertiseHost: "192.0.2.20", hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.20\n"},
		{name: "advertise hostname is not an address", advertiseHost: "node-a.example", hostIP: net.ParseIP("2001:db8::1"), want: "2001:db8::1\n"},
		{name: "no address removes a stale file", hostErr: errors.New("no route")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostInterface(tc.hostIP, tc.hostErr)
			cfg := &config{}
			cfg.WorkloadClaims.SocketDir = t.TempDir()
			cfg.WorkloadClaims.AdvertiseHost = tc.advertiseHost
			path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
			if err := os.WriteFile(path, []byte("203.0.113.66\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			err := publishNodeIP(cfg)
			if (err != nil) != (tc.want == "") {
				t.Fatalf("publishNodeIP() error = %v, want error %t", err, tc.want == "")
			}
			got, readErr := os.ReadFile(path)
			if tc.want == "" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("node-ip = %q, %v; want it removed", got, readErr)
				}
				return
			}
			if string(got) != tc.want {
				t.Fatalf("node-ip = %q, want %q", got, tc.want)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("stat node-ip = %v, %v; want mode 0644", info, err)
			}
		})
	}
}
