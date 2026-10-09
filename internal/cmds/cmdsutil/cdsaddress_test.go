package cmdsutil

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The node's endpoint mount decides, and an argument beside it is refused: a
// pod must not be able to be pointed at a CDS of the control plane's choosing.
func TestResolveCDSEndpoint(t *testing.T) {
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
			mounted: string(FormatCDSAddress(netip.MustParseAddrPort("10.1.2.3:30808"))),
			want:    "https://10.1.2.3:30808",
		},
		{
			name:     "an argument beside the node's endpoint",
			mounted:  "10.1.2.3:30808\n",
			supplied: "https://attacker.svc:8443",
			wants:    "remove --cds-url",
		},
		{
			name:    "an endpoint that is no address",
			mounted: "cds.c8s-system.svc\n",
			wants:   "node policy",
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
			endpoint, fromNode, err := ResolveCDSEndpoint(path, tc.supplied)
			switch {
			case tc.wants != "":
				if err == nil || !strings.Contains(err.Error(), tc.wants) {
					t.Fatalf("error = %v, want it to name %q", err, tc.wants)
				}
			case err != nil:
				t.Fatalf("ResolveCDSEndpoint: %v", err)
			case tc.want == "":
				if fromNode {
					t.Fatalf("endpoint %v came from a node that mounts none", endpoint)
				}
			case !fromNode:
				t.Fatal("the node's endpoint was not read")
			case CDSURL(endpoint) != tc.want:
				t.Fatalf("url = %q, want %q", CDSURL(endpoint), tc.want)
			}
		})
	}
}
