package sidecar

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Where the node mounts its CDS policy, the sidecar's client re-reads it on a
// pin miss (a static transport would keep the launch-time pins for life).
func TestNewClientFollowsTheNodePolicy(t *testing.T) {
	certPath, keyPath, _ := testutil.WriteLeaf(t, t.TempDir())
	cfg := testConfig("https://cds.example")
	cfg.CertPath, cfg.KeyPath = certPath, keyPath
	saved := nodePinsPath
	t.Cleanup(func() { nodePinsPath = saved })

	nodePinsPath = filepath.Join(t.TempDir(), "absent.json")
	client, _, err := NewClient(cfg, armtls.Pins{})
	if err != nil {
		t.Fatal(err)
	}
	if _, static := client.Transport.(*http.Transport); !static {
		t.Fatal("no node policy, yet the transport refreshes")
	}

	policy, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	nodePinsPath = filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(nodePinsPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	client, _, err = NewClient(cfg, armtls.Pins{})
	if err != nil {
		t.Fatal(err)
	}
	if _, static := client.Transport.(*http.Transport); static {
		t.Fatal("the node mounts its policy, yet the transport is static")
	}
	if err := os.WriteFile(nodePinsPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewClient(cfg, armtls.Pins{}); err == nil {
		t.Fatal("an unreadable node policy accepted")
	}
}
