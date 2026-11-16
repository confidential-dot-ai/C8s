package nriimagepolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
)

// exemptPlugin builds a fail-closed plugin (base allowlist admits pushDigestA)
// whose listed namespaces admit repositories. An attempted kill panics by name.
func exemptPlugin(t *testing.T, repositories ExemptRepositories, namespaces ...string) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base-image"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			ExemptNamespaces:      namespaces,
			ExemptRepositories:    repositories,
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

// A non-base image an exempt namespace's repository set names is admitted
// there, at any digest: the provider rotates its add-on images.
func TestExempt_ConfiguredRepositoryAdmits(t *testing.T) {
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}}, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "coredns")
	ctr := makeCtrWithImage(pod.Id, "coredns", "mcr.microsoft.com/oss/kubernetes/coredns@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("a configured kube-system repository must be admitted: %v", err)
	}
}

// A non-base image outside the set is denied in the exempt namespace.
func TestExempt_UnconfiguredRepositoryDeniedInExemptNamespace(t *testing.T) {
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}}, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "pod")
	ctr := makeCtrWithImage(pod.Id, "evil", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("an unconfigured non-base image in an exempt namespace must be denied")
	}
}

// A tag the node resolves to no digest is admitted under its prefix: that is
// what a provider image pre-loaded in the node image reports.
func TestExempt_UnresolvableTagAdmitsUnderItsPrefix(t *testing.T) {
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}}, "kube-system")
	p.SetReady()
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		return "", errors.New("no such image in the content store")
	}}

	pod := makePod("kube-system", "kube-proxy")
	ctr := makeCtrWithImage(pod.Id, "kube-proxy", "mcr.microsoft.com/oss/kubernetes/kube-proxy:v1.31.0")
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("an unresolvable tag under an exempt prefix must be admitted: %v", err)
	}

	beside := makeCtrWithImage(pod.Id, "csi", "mcr.microsoft.com/oss/kubernetes-csi/azuredisk:v1.33.0")
	if _, _, err := createAndStart(p, context.Background(), pod, beside); err == nil {
		t.Fatal("a repository beside the prefix's path must be denied")
	}
}

// The set is namespace-scoped: a repository kube-system admits does not admit
// the same image in a tenant namespace.
func TestExempt_ConfiguredRepositoryNotAdmittedInTenantNamespace(t *testing.T) {
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}}, "kube-system")
	p.SetReady()

	pod := makePod("default", "tenant")
	ctr := makeCtrWithImage(pod.Id, "c", "mcr.microsoft.com/oss/kubernetes/coredns@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("a repository kube-system admits must not admit in a tenant namespace")
	}
}

// A running container in an exempt namespace the set does not name is denied at
// create but never killed: stopping a platform container can cut the node.
func TestExempt_CheckExistingDoesNotKillExemptNamespace(t *testing.T) {
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}}, "kube-system")
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
	p := exemptPlugin(t, ExemptRepositories{"kube-system": {"mcr.microsoft.com/containernetworking/"}}, "kube-system")
	p.SetReady()
	if _, err := p.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	pod := makePod("kube-system", "azure-cns")
	initCtr := makeCtrWithImage(pod.Id, "init-cns", "mcr.microsoft.com/containernetworking/azure-ipam@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, initCtr); err != nil {
		t.Fatalf("an exempt repository must still admit after a reboot: %v", err)
	}
	drifted := makeCtrWithImage(pod.Id, "drift", "registry/repo@"+pushDigestC)
	if _, _, err := createAndStart(p, context.Background(), pod, drifted); err == nil {
		t.Fatal("a repository outside the set must be denied after a reboot")
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
