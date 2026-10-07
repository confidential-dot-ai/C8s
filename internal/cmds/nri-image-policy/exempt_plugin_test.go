package nriimagepolicy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
)

// exemptPlugin builds a fail-closed base plugin (base allowlist admits pushDigestA)
// whose listed namespaces are admitted by a captured digest snapshot at
// snapshotPath. The containerd stop hook is unset, so any kill panics by name.
func exemptPlugin(t *testing.T, snapshotPath string, namespaces ...string) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base-image"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			ExemptNamespaces:      namespaces,
			ExemptSnapshotPath:    snapshotPath,
		},
	}
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
		mesh:       newMeshGate(nil, discardLogger()),
	}
	p.inventory = newAdmissionInventory("/proc")
	return p
}

// A non-base image running in an exempt namespace when the plugin connects is
// captured, persisted, and admitted on a later create — without a kill, since
// the running container is downgraded to skip during the same Synchronize.
func TestExempt_CaptureAtSyncAdmitsLaterCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	p := exemptPlugin(t, path, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "coredns")
	running := makeCtrWithImage(pod.Id, "coredns", "registry/repo@"+pushDigestB)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{running}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot not persisted: %v", err)
	}
	if !p.exempt.Load().admits("kube-system", pushDigestB) {
		t.Fatal("the running kube-system digest was not captured")
	}

	next := makeCtrWithImage(pod.Id, "coredns-2", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, next); err != nil {
		t.Fatalf("a captured kube-system image must be admitted on create: %v", err)
	}
}

// A non-base image never captured in an exempt namespace is denied there.
func TestExempt_UncapturedDigestDeniedInExemptNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	p := exemptPlugin(t, path, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "pod")
	captured := makeCtrWithImage(pod.Id, "captured", "registry/repo@"+pushDigestC)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{captured}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	uncaptured := makeCtrWithImage(pod.Id, "evil", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), pod, uncaptured); err == nil {
		t.Fatal("an uncaptured non-base image in an exempt namespace must be denied")
	}
}

// The capture is namespace-scoped: a digest captured in kube-system does not
// admit the same digest in a tenant namespace.
func TestExempt_CapturedDigestNotAdmittedInTenantNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	p := exemptPlugin(t, path, "kube-system")
	p.SetReady()

	ksPod := makePod("kube-system", "ks")
	ks := makeCtrWithImage(ksPod.Id, "c", "registry/repo@"+pushDigestB)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{ksPod}, []*api.Container{ks}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	tenantPod := makePod("default", "tenant")
	tenant := makeCtrWithImage(tenantPod.Id, "c", "registry/repo@"+pushDigestB)
	if _, _, err := createAndStart(p, context.Background(), tenantPod, tenant); err == nil {
		t.Fatal("a kube-system-captured digest must not admit in a tenant namespace")
	}
}

// A running container in an exempt namespace whose digest is not in the frozen
// snapshot is denied at create but never killed: stopping a platform container
// can cut the node.
func TestExempt_CheckExistingDoesNotKillExemptNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	pre := newExemptSnapshot([]string{"kube-system"})
	pre.add("kube-system", pushDigestA)
	if err := pre.persist(path); err != nil {
		t.Fatal(err)
	}

	p := exemptPlugin(t, path, "kube-system")
	p.SetReady()

	pod := makePod("kube-system", "pod")
	drifted := makeCtrWithImage(pod.Id, "drift", "registry/repo@"+pushDigestB) // not in snapshot, not base

	// The unset stop hook panics if a kill is attempted.
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{drifted}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
}

// A reboot gates every container on the plugin, so Synchronize sees an empty
// node; the frozen snapshot must be loaded from disk, not recaptured to empty.
func TestExempt_RebootLoadsPersistedNotRecaptured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	pre := newExemptSnapshot([]string{"kube-system"})
	pre.add("kube-system", pushDigestA)
	if err := pre.persist(path); err != nil {
		t.Fatal(err)
	}

	p := exemptPlugin(t, path, "kube-system")
	if _, err := p.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	if !p.exempt.Load().admits("kube-system", pushDigestA) {
		t.Fatal("a reboot must load the frozen snapshot, not recapture an empty node")
	}
}

// An empty capture is not persisted: freezing it would deny every platform pod,
// so a later start recaptures instead.
func TestExempt_EmptyCaptureNotPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	p := exemptPlugin(t, path, "kube-system")

	// Nothing is running in kube-system at connect.
	pod := makePod("default", "tenant")
	tenant := makeCtrWithImage(pod.Id, "c", "registry/repo@"+pushDigestA)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{tenant}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an empty capture must not write a snapshot; stat err = %v", err)
	}
	if !p.exempt.Load().empty() {
		t.Fatal("an empty capture must leave the snapshot empty")
	}
}

// Without exempt namespaces the plugin is unchanged: no snapshot, and a
// non-base image in kube-system is still killed by enforce_existing.
func TestExempt_NoExemptNamespacesIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	p := exemptPlugin(t, path) // no namespaces
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

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no snapshot must be written when exempt_namespaces is empty")
	}
	if p.exempt.Load() != nil {
		t.Fatal("p.exempt must stay nil without exempt namespaces")
	}
	if len(killed) != 1 || killed[0] != running.Id {
		t.Fatalf("without an exemption a non-base kube-system image is still killed, got %v", killed)
	}
}
