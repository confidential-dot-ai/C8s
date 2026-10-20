package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The pod role rewrites the baked config at boot (nodeservices.preparePod).
// Load that output here so the rewrite cannot drift from the plugin schema.
// A TDX pod measures its images: the rewrite must keep the baked
// workload_claims.socket_dir the measure.rtmr3 validation requires.
func TestNodeImagePodRoleConfig_LoadsBaseOnlyAndEnforces(t *testing.T) {
	for _, platform := range []string{"snp", "tdx"} {
		t.Run(platform, func(t *testing.T) { testNodeImagePodRoleConfig(t, platform) })
	}
}

func testNodeImagePodRoleConfig(t *testing.T, platform string) {
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
	// The pins are TDX pins; an SNP pod has no register pins.
	pins.Images = pins.Images[:1]
	if platform == "snp" {
		pins.Family = teetypes.FamilySNP
		pins.Images[0].Registers = nil
	}
	policy, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	write(launchconfig.Dir+"/peers.json", policy)
	write(launchconfig.Dir+"/cds.json", policy)
	doc := &launchconfig.Document{
		Role:      launchconfig.Pod,
		Image:     launchconfig.Image{Platform: platform},
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
	if cfg.Measure.RTMR3 != (platform == "tdx") {
		t.Fatalf("measure.rtmr3 = %v on %s", cfg.Measure.RTMR3, platform)
	}
	if cfg.Measure.RTMR3 && cfg.WorkloadClaims.SocketDir != filepath.Dir(armtls.NodeJournal) {
		t.Fatalf("socket_dir = %q: the pod journal would not be where its readers look", cfg.WorkloadClaims.SocketDir)
	}
}
