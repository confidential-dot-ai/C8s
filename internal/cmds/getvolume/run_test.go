package getvolume

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestParseVolumeSpec(t *testing.T) {
	got, err := parseVolumeSpec("weights=/tenant-a/volumes/weights")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "weights" || got.Path != "/tenant-a/volumes/weights" {
		t.Fatalf("got %+v", got)
	}

	for _, spec := range []string{
		"",                              // no pair
		"weights",                       // no path
		"=/tenant-a/volumes/weights",    // no name
		"WEIGHTS=/tenant-a/vol",         // not a dns-1123 label
		"we/ights=/tenant-a/vol",        // a path, not a name
		"thirteenchars=/tenant-a/vol",   // longer than a serial holds
		"weights=tenant-a/volumes/w",    // path is not absolute
		"weights=/tenant-a/../etc/pass", // path escapes
	} {
		if _, err := parseVolumeSpec(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}

// The name rides in a virtio serial, so the cap the daemon enforces has to be
// the one admission and the sidecar enforce.
func TestParseVolumeSpecAcceptsTheLongestServableName(t *testing.T) {
	name := strings.Repeat("a", 12)
	if _, err := parseVolumeSpec(name + "=/tenant-a/volumes/x"); err != nil {
		t.Fatalf("rejected a 12-character name: %v", err)
	}
}

func validConfig() config {
	return config{
		CDSURL:            "https://cds.example",
		AttestationApiURL: "http://127.0.0.1:8400",
		Attempts:          60,
		RetryInterval:     5 * time.Second,
		RequestTimeout:    10 * time.Second,
		InventoryTimeout:  5 * time.Second,
		SocketDir:         "/run/c8s/workload-claims",
		Volumes:           []volumeRequest{{Name: "weights", Path: "/tenant-a/volumes/weights"}},
	}
}

func TestValidate(t *testing.T) {
	cfg := validConfig()
	if err := validate(&cfg); err != nil {
		t.Fatalf("rejected a complete config: %v", err)
	}

	for name, mutate := range map[string]func(*config){
		"cds url":           func(c *config) { c.CDSURL = "" },
		"plaintext cds url": func(c *config) { c.CDSURL = "http://cds.example" },
		"attestation api":   func(c *config) { c.AttestationApiURL = "" },
		"no volumes":        func(c *config) { c.Volumes = nil },
		"socket dir":        func(c *config) { c.SocketDir = "" },
		"attempts":          func(c *config) { c.Attempts = 0 },
		"retry interval":    func(c *config) { c.RetryInterval = 0 },
		"request timeout":   func(c *config) { c.RequestTimeout = 0 },
		"inventory timeout": func(c *config) { c.InventoryTimeout = 0 },
		"repeated name": func(c *config) {
			c.Volumes = append(c.Volumes, volumeRequest{Name: "weights", Path: "/tenant-a/volumes/other"})
		},
	} {
		cfg := validConfig()
		mutate(&cfg)
		if err := validate(&cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateTrimsURL(t *testing.T) {
	cfg := validConfig()
	cfg.CDSURL = "https://cds.example/"
	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.CDSURL != "https://cds.example" {
		t.Fatalf("CDSURL = %q, want the trailing slash gone", cfg.CDSURL)
	}
}

func TestNewCmdHasTheSidecarFlags(t *testing.T) {
	cmd := NewCmd()
	for _, flag := range []string{"cds-url", "attestation-api-url", "cert", "key", "volume", "socket-dir", "attempts"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing --%s", flag)
		}
	}
}

func TestValidateSocketDirOnlyRequiredOnNodeCVM(t *testing.T) {
	cfg := validConfig()
	cfg.SocketDir = ""
	if err := validate(&cfg); err == nil {
		t.Error("node-CVM accepted a config with no socket dir")
	}

}

// The daemon endpoint uses the node socket directory and the unix-transport
// placeholder, rather than posting the key blob to a network address.
func TestDaemonClientSelectsCompiledShape(t *testing.T) {
	_, base := daemonClient(config{SocketDir: "/run/c8s/workload-claims"})
	if base != "http://volumed" {
		t.Errorf("node-CVM base = %q, want the unix-transport placeholder", base)
	}
}

// A malformed RTMR pin is a typo in rendered config; pinning nothing is not
// an acceptable fallback for it.
func TestRunRejectsBadRTMRs(t *testing.T) {
	cfg := validConfig()
	cfg.RTMRs = []string{"nope"}
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "--rtmrs") {
		t.Fatalf("err = %v, want an RTMR-parse failure", err)
	}
}

// openAll builds the client before it asks for anything, so a leaf that is
// not on disk yet surfaces there.
func TestOpenAllWithoutLeaf(t *testing.T) {
	cfg := validConfig()
	cfg.CertPath = filepath.Join(t.TempDir(), "absent.crt")
	cfg.KeyPath = filepath.Join(t.TempDir(), "absent.key")
	if err := openAll(context.Background(), cfg, armtls.Pins{}); err == nil {
		t.Fatal("a missing leaf was accepted")
	}
}
