package nriimagepolicy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The pod role rewrites the baked config at boot (nodeservices.preparePod).
// Load that output here so the rewrite cannot drift from the plugin schema.
// A pod measures its images: the rewrite must keep the baked
// workload_claims.socket_dir the measure.rtmr3 validation requires.
func TestNodeImagePodRoleConfig_LoadsBaseOnlyAndEnforces(t *testing.T) {
	testNodeImagePodRoleConfig(t, "tdx")
}

// A platform without a runtime register cannot measure the pod, so
// preparation refuses it rather than writing a policy that measures nothing.
func TestNodeImagePodRoleConfig_RefusesSNP(t *testing.T) {
	root, doc := podRoleInputs(t, "snp")
	err := nodeservices.Prepare(root, doc)
	if err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml")); !os.IsNotExist(err) {
		t.Fatalf("pod-role config written without measurement: %v", err)
	}
}

// podRoleInputs stages the baked policy, the pins and a pod document of the
// given platform under a fresh root, as the initrd leaves them for Prepare.
func podRoleInputs(t *testing.T, platform string) (string, *launchconfig.Document) {
	t.Helper()
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
	write("usr/lib/c8s/image-policy.yaml", []byte(nriimagepolicy.RenderNodeImagePolicy(t)))
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
	return root, doc
}

func testNodeImagePodRoleConfig(t *testing.T, platform string) {
	root, doc := podRoleInputs(t, platform)
	if err := nodeservices.Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	cfg, err := nriimagepolicy.LoadConfig(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatalf("pod-role config does not load: %v", err)
	}
	if cfg.PullEnabled() || cfg.Allowlist.NodeTCB || nriimagepolicy.SandboxModeOf(cfg) != nriimagepolicy.SandboxEnforce || !cfg.Policy.FatalExisting {
		t.Fatalf("pod-role config: pull=%v node_tcb=%v sandbox=%v fatal_existing=%v",
			cfg.PullEnabled(), cfg.Allowlist.NodeTCB, nriimagepolicy.SandboxModeOf(cfg), cfg.Policy.FatalExisting)
	}
	if !cfg.Measure.RTMR3 {
		t.Fatalf("measure.rtmr3 = %v on %s", cfg.Measure.RTMR3, platform)
	}
	if cfg.WorkloadClaims.SocketDir != filepath.Dir(armtls.NodeJournal) {
		t.Fatalf("socket_dir = %q: the pod journal would not be where its readers look", cfg.WorkloadClaims.SocketDir)
	}
}
