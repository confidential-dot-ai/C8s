package nriimagepolicy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The pod role rewrites the baked config at boot (nodeservices.preparePod).
// Load that output here so the rewrite cannot drift from the plugin schema.
// A pod measures its images: the rewrite must keep the baked
// workload_claims.socket_dir the measure.rtmr3 validation requires.
func TestNodeImagePodRoleConfig_LoadsBaseAndPullAndEnforces(t *testing.T) {
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

const podImageDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// podRoleInputs stages the baked policy, the pins and a pod document of the
// given platform under a fresh root, as the initrd leaves them for Prepare.
func podRoleInputs(t *testing.T, platform string) (string, *launchconfig.Document) {
	t.Helper()
	// Successful guest preparation reads the Linux uplink's route and MTU.
	// Keep these integration tests on that real path; pure rendering and
	// invalid-network cases are covered by the node-services unit tests.
	if platform == "tdx" && runtime.GOOS != "linux" {
		t.Skip("Pod guest preparation requires Linux network discovery")
	}
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
	baked := nriimagepolicy.RenderNodeImagePolicy(t)
	if strings.Count(baked, `platform: "snp"`) != 1 {
		t.Fatal("rendered fixture must contain exactly one platform setting")
	}
	baked = strings.Replace(baked, `platform: "snp"`, `platform: "`+platform+`"`, 1)
	write("usr/lib/c8s/image-policy.yaml", []byte(baked))
	cni, err := os.ReadFile("../../../node-guest-image/c8s/mkosi.extra/usr/lib/c8s/pod-runtime/cni/10-c8s-pod.conflist")
	if err != nil {
		t.Fatal(err)
	}
	write("usr/lib/c8s/pod-runtime/cni/10-c8s-pod.conflist", cni)
	pins, err := refvalues.Load("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	// The server and Pod launch authorities stay distinct.
	serverKey, podKey := string(pins.Images[0].Anchor), string(pins.Images[1].Anchor)
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
	containers := []string{}
	for _, name := range []string{"app", "unknown"} {
		containers = append(containers, fmt.Sprintf(`{"name":%q,"image":"busybox@%s"}`, name, podImageDigest))
	}
	for _, name := range []string{"served", "cached"} {
		containers = append(containers, fmt.Sprintf(`{"name":%q,"image":"busybox@%s"}`, name, nriimagepolicy.PodBootstrapServedDigest))
	}
	doc := &launchconfig.Document{
		Role:                 launchconfig.Pod,
		Server:               launchconfig.ServerConfig{Address: "10.1.2.3", OperatorPublicKey: serverKey},
		PodOperatorPublicKey: podKey,
		Image:                launchconfig.Image{Platform: platform},
		Node:                 launchconfig.Node{Name: "p-pod"},
		Workloads:            `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"` + podImageDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`,
		Pod: &launchconfig.PodSpec{UID: "u1", Namespace: "tenant", Name: "app",
			Manifest: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[` + strings.Join(containers, ",") + `]}}`},
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
	if !cfg.PullEnabled() || cfg.Allowlist.NodeTCB || nriimagepolicy.SandboxModeOf(cfg) != nriimagepolicy.SandboxEnforce || !cfg.Policy.FatalExisting {
		t.Fatalf("pod-role config: pull=%v node_tcb=%v sandbox=%v fatal_existing=%v",
			cfg.PullEnabled(), cfg.Allowlist.NodeTCB, nriimagepolicy.SandboxModeOf(cfg), cfg.Policy.FatalExisting)
	}
	if !cfg.Measure.RTMR3 {
		t.Fatalf("measure.rtmr3 = %v on %s", cfg.Measure.RTMR3, platform)
	}
	if cfg.WorkloadClaims.SocketDir != filepath.Dir(armtls.NodeJournal) {
		t.Fatalf("socket_dir = %q: the pod journal would not be where its readers look", cfg.WorkloadClaims.SocketDir)
	}
	if cfg.Mesh == nil || cfg.Pod == nil || len(cfg.Mesh.ExemptNamespaces) != 0 || len(cfg.Mesh.Roles) != 1 {
		t.Fatal("pod-role config must keep the endpoint's mesh floor without node exemptions")
	}
	if cfg.Mesh.Roles[0].Name != workloadclaims.MeshRole || cfg.Mesh.Roles[0].UID != workloadclaims.MeshUID {
		t.Fatalf("mesh role = %+v", cfg.Mesh.Roles)
	}
	floor, err := nriimagepolicy.LoadMeshFloor(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatalf("pod-role floor does not load: %v", err)
	}
	if !floor.PodRole {
		t.Fatal("the runtime wrapper would read the pod-role policy as a node's and refuse root")
	}
	base := cfg.Allowlist.Base.Workloads
	endpoint := base["c8s-mesh-endpoint"].Containers
	if len(base) != 2 || base["app"].Containers[0].Role != "" || len(endpoint) != 1 || endpoint[0].Role != workloadclaims.MeshRole || endpoint[0].Digest.String() != nriimagepolicy.MeshImageDigest {
		t.Fatalf("base = %+v, want signed app and measured endpoint", base)
	}
	// This helper checks the preliminary allowlist decision. The full Run
	// test below proves that adjustment validation still requires the mesh.
	if err := nriimagepolicy.AdmitsCreation(cfg, doc.Pod.Namespace, "busybox@"+podImageDigest, podImageDigest); err != nil {
		t.Fatalf("signed workload refused by the prepared allowlist: %v", err)
	}
}

// Exercise the prepared policy through the production startup path and an NRI
// runtime connection, including admission before CDS becomes available.
func TestNodeImagePodRoleConfig_StartsAndRetainsServedPolicy(t *testing.T) {
	root, doc := podRoleInputs(t, "tdx")
	if err := nodeservices.Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	cfg, err := nriimagepolicy.LoadConfig(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	nriimagepolicy.AssertPodBootstrap(t, cfg, root, []byte(doc.PodOperatorPublicKey), podImageDigest)
}
