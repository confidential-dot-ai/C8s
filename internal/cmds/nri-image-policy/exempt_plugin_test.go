package nriimagepolicy

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
)

// exemptPlugin builds a fail-closed plugin (base allowlist admits pushDigestA)
// whose listed namespaces admit digests. An attempted kill panics by name.
func exemptPlugin(t *testing.T, digests map[string][]string, namespaces ...string) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base-image"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			ExemptNamespaces:      namespaces,
			ExemptDigests:         digests,
		},
	}
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
		mesh:       newMeshGate(*meshRoles(), discardLogger()),
	}
	p.inventory = newAdmissionInventory("/proc")
	return p
}

// A non-base image an exempt namespace's digest set holds is admitted there.
func TestExempt_ConfiguredDigestAdmits(t *testing.T) {
	p := exemptPlugin(t, map[string][]string{"kube-system": {pushDigestB}}, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "coredns")
	ctr := makeCtrWithImage(pod.Id, "coredns", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("a configured kube-system digest must be admitted: %v", err)
	}
}

// A non-base image outside the set is denied in the exempt namespace.
func TestExempt_UnconfiguredDigestDeniedInExemptNamespace(t *testing.T) {
	p := exemptPlugin(t, map[string][]string{"kube-system": {pushDigestC}}, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "pod")
	ctr := makeCtrWithImage(pod.Id, "evil", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("an unconfigured non-base image in an exempt namespace must be denied")
	}
}

// The set is namespace-scoped: a digest kube-system admits does not admit the
// same image in a tenant namespace.
func TestExempt_ConfiguredDigestNotAdmittedInTenantNamespace(t *testing.T) {
	p := exemptPlugin(t, map[string][]string{"kube-system": {pushDigestB}}, "kube-system")
	p.SetReady()

	pod := makePod("default", "tenant")
	ctr := makeCtrWithImage(pod.Id, "c", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("a digest kube-system admits must not admit in a tenant namespace")
	}
}

// A running container in an exempt namespace whose digest the set does not hold
// is denied at create but never killed: stopping a platform container can cut
// the node.
func TestExempt_CheckExistingDoesNotKillExemptNamespace(t *testing.T) {
	p := exemptPlugin(t, map[string][]string{"kube-system": {pushDigestA}}, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "pod")
	drifted := makeCtrWithImage(pod.Id, "drift", "registry/repo@"+pushDigestB) // outside the set, not base

	// The unset stop hook panics if a kill is attempted.
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{drifted}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
}

// A reboot gates every container on the plugin, so Synchronize sees an empty
// node and the config alone says what the namespace admits.
func TestExempt_RebootAdmitsFromConfig(t *testing.T) {
	p := exemptPlugin(t, map[string][]string{"kube-system": {pushDigestB}}, "kube-system")
	p.SetReady()
	if _, err := p.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	pod := makePod("kube-system", "azure-cns")
	initCtr := makeCtrWithImage(pod.Id, "init-cns", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, initCtr); err != nil {
		t.Fatalf("an exempt digest must still admit after a reboot: %v", err)
	}
	drifted := makeCtrWithImage(pod.Id, "drift", "registry/repo@"+pushDigestC)
	if _, _, err := createAndStart(p, context.Background(), pod, drifted); err == nil {
		t.Fatal("a digest outside the set must be denied after a reboot")
	}
}

// Without exempt namespaces the plugin is unchanged: a non-base image in
// kube-system is killed by enforce_existing.
func TestExempt_NoExemptNamespacesIsNoop(t *testing.T) {
	p := exemptPlugin(t, nil) // no namespaces
	p.SetReady()

	var killed []string
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		return nil
	}}

	pod := makePod("kube-system", "pod")
	running := makeCtrWithImage(pod.Id, "c", "registry/repo@"+pushDigestB)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{running}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	if len(killed) != 1 || killed[0] != running.Id {
		t.Fatalf("without an exemption a non-base kube-system image is still killed, got %v", killed)
	}
}
