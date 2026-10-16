package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

// The pod role rewrites the baked config at boot (nodeservices.preparePod).
// Load that output here so the rewrite cannot drift from the plugin schema.
func TestNodeImagePodRoleConfig_LoadsBaseOnlyAndEnforces(t *testing.T) {
	root := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/lib/c8s/image-policy.yaml", []byte(renderNodeImagePolicy(t)))
	pins, err := refvalues.Load("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	pins.Family = "sev-snp"
	pins.Images = pins.Images[:1]
	pins.Images[0].Registers = nil
	policy, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	write(launchconfig.Dir+"/peers.json", policy)
	write(launchconfig.Dir+"/cds.json", policy)
	doc := &launchconfig.Document{
		Role:      launchconfig.Pod,
		Image:     launchconfig.Image{Platform: "snp"},
		Node:      launchconfig.Node{Name: "p-pod"},
		Workloads: `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`,
		Pod: &launchconfig.PodSpec{UID: "u1", Namespace: "tenant", Name: "app",
			Manifest: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[{"name":"app","image":"busybox"}]}}`},
	}
	if err := nodeservices.Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatalf("pod-role config does not load: %v", err)
	}
	if cfg.PullEnabled() || cfg.Allowlist.NodeTCB || cfg.sandboxMode() != SandboxEnforce || !cfg.Policy.FatalExisting {
		t.Fatalf("pod-role config: pull=%v node_tcb=%v sandbox=%v fatal_existing=%v",
			cfg.PullEnabled(), cfg.Allowlist.NodeTCB, cfg.sandboxMode(), cfg.Policy.FatalExisting)
	}
}
