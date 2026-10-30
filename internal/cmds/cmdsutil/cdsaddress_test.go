package cmdsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The node's endpoint mount decides, and an argument beside it is refused: a
// pod must not be able to be pointed at a CDS of the control plane's choosing.
func TestResolveCDSAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mounted  string
		supplied string
		want     string
		wants    string
	}{
		{
			name:     "no mount, the caller's own argument",
			supplied: "https://cds.c8s-system.svc:8443",
		},
		{
			name:    "the node's endpoint",
			mounted: string(FormatCDSAddress("10.1.2.3:30808")),
			want:    "https://10.1.2.3:30808",
		},
		{
			name:    "the node's endpoint as a name",
			mounted: string(FormatCDSAddress("cds.example.org:8443")),
			want:    "https://cds.example.org:8443",
		},
		{
			name:     "an argument beside the node's endpoint",
			mounted:  "10.1.2.3:30808\n",
			supplied: "https://attacker.svc:8443",
			wants:    "remove --cds-url",
		},
		{
			name:    "an endpoint with no port",
			mounted: "cds.c8s-system.svc\n",
			wants:   "must be <host>:<port>",
		},
		{
			name:    "an endpoint on port 0",
			mounted: "10.1.2.3:0\n",
			wants:   "no CDS serves on",
		},
		{
			name:    "an endpoint that is a URL",
			mounted: "https://cds.example.org:8443\n",
			wants:   "must be <host>:<port>",
		},
		{
			name:    "an empty endpoint",
			mounted: "  \n",
			wants:   "names no address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cds-address")
			if tc.mounted != "" {
				if err := os.WriteFile(path, []byte(tc.mounted), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			address, fromNode, err := ResolveCDSAddress(path, tc.supplied)
			switch {
			case tc.wants != "":
				if err == nil || !strings.Contains(err.Error(), tc.wants) {
					t.Fatalf("error = %v, want it to name %q", err, tc.wants)
				}
			case err != nil:
				t.Fatalf("ResolveCDSAddress: %v", err)
			case tc.want == "":
				if fromNode {
					t.Fatalf("endpoint %q came from a node that mounts none", address)
				}
			case !fromNode:
				t.Fatal("the node's endpoint was not read")
			case CDSURL(address) != tc.want:
				t.Fatalf("url = %q, want %q", CDSURL(address), tc.want)
			}
		})
	}
}

// Where this cluster's CDS serves is one host and one port: the host a name
// a client resolves or an address it dials as it stands, so a node's packet
// rules can admit the port and nothing wider.
func TestSplitCDSAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		host    string
		port    uint16
		wants   string
	}{
		{address: "10.9.9.9:8443", host: "10.9.9.9", port: 8443},
		{address: "cds.example.org:8443", host: "cds.example.org", port: 8443},
		{address: "cds:8443", host: "cds", port: 8443},
		{address: "10.9.9.9", wants: "must be <host>:<port>"},
		{address: "cds.example.org", wants: "must be <host>:<port>"},
		{address: "10.9.9.9:0", wants: "no CDS serves on"},
		{address: "10.9.9.9:https", wants: "no CDS serves on"},
		{address: "10.9.9.9:70000", wants: "no CDS serves on"},
		{address: "127.0.0.1:8443", host: "127.0.0.1", port: 8443},
		{address: "[2001:db8::1]:8443", wants: "must be an IPv4 address"},
		{address: "CDS.example.org:8443", wants: "lowercase DNS name"},
		{address: "cds_one.example.org:8443", wants: "lowercase DNS name"},
		{address: ":8443", wants: "lowercase DNS name"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			host, port, err := SplitCDSAddress(tc.address)
			if tc.wants != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wants) {
					t.Fatalf("error = %v, want it to name %q", err, tc.wants)
				}
				return
			}
			if err != nil || host != tc.host || port != tc.port {
				t.Fatalf("host, port = %q, %d, %v; want %q, %d", host, port, err, tc.host, tc.port)
			}
		})
	}
}

// A measured config names the CDS by URL, and what a node's rules and its
// clients need out of it is the endpoint.
func TestCDSURLAddress(t *testing.T) {
	for _, tc := range []struct {
		url   string
		want  string
		wants string
	}{
		{url: "https://cds.example.org:8443", want: "cds.example.org:8443"},
		{url: "https://10.9.9.9:8443", want: "10.9.9.9:8443"},
		{url: "http://10.9.9.9:8443", wants: "must use https"},
		{url: "https://10.9.9.9", wants: "must be <host>:<port>"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			address, err := CDSURLAddress(tc.url)
			if tc.wants != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wants) {
					t.Fatalf("error = %v, want it to name %q", err, tc.wants)
				}
				return
			}
			if err != nil || address != tc.want {
				t.Fatalf("address = %q, %v; want %q", address, err, tc.want)
			}
		})
	}
}
