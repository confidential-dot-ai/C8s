package nriimagepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestInventoryPreservesUnavailableMountEvidence(t *testing.T) {
	digest, err := types.ParseDigest(digestApp)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pod  *api.PodSandbox
	}{
		{name: "missing pod metadata"},
		{name: "observed empty spec", pod: &api.PodSandbox{Id: "pod", Uid: "uid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &plugin{
				inventory: newAdmissionInventory(t.TempDir()),
				mesh:      newMeshGate(nil, discardLogger()),
			}
			ctr := &api.Container{Id: "ctr", PodSandboxId: "pod", Args: []string{"/app"}}
			p.recordDigest(ctr, digestApp, observedMounts(tc.pod, ctr))
			_, reported, known, err := p.inventory.DigestsForSandbox("pod")
			if err != nil || !known || len(reported) != 1 {
				t.Fatalf("inventory = %+v, %v, %v", reported, known, err)
			}
			// Exercise the wire representation consumed by secret release too.
			wire, err := json.Marshal(reported)
			if err != nil {
				t.Fatal(err)
			}
			var decoded []workloadclaims.SandboxContainer
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, policy := range []string{allowlist.PolicyDeny, allowlist.PolicyExact} {
				al := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{
					"app": {Containers: []allowlist.Container{{Digest: digest,
						Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
						Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
						Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyAny},
						Mounts:  allowlist.MountPolicy{Policy: policy},
					}}},
				}}
				_, _, err := al.MatchWorkload(secrets.WorkloadContainers(al, decoded))
				if tc.pod == nil && !errors.Is(err, allowlist.ErrNoMatch) {
					t.Fatalf("%s accepted unavailable mount evidence: %v", policy, err)
				}
				if tc.pod != nil && err != nil {
					t.Fatalf("%s refused observed empty mounts: %v", policy, err)
				}
			}
		})
	}
}

// sandboxDigestsFor walks the production path CDS drives: bind the caller by
// kernel credentials to its sandbox, then list what that sandbox runs.
func sandboxDigestsFor(b *admissionInventory, pid int) ([]string, error) {
	sandboxID, err := b.sandboxForPeer(workloadclaims.PeerForPID(pid))
	if err != nil {
		return nil, err
	}
	digests, _, known, err := b.DigestsForSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, fmt.Errorf("sandbox %s unknown", sandboxID)
	}
	return digests, nil
}

const (
	digestApp   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestApp2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digestOther = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	// CRI container IDs are 64-hex (what the cgroup path carries).
	cidGetCert = "1111111111111111111111111111111111111111111111111111111111111111"
	cidApp1    = "aaaa111111111111111111111111111111111111111111111111111111111111"
	cidApp2    = "bbbb222222222222222222222222222222222222222222222222222222222222"
	cidOther   = "cccc333333333333333333333333333333333333333333333333333333333333"
)

// writeCgroup creates <procRoot>/<pid>/cgroup naming containerID.
func writeCgroup(t *testing.T, procRoot string, pid int, containerID string) {
	t.Helper()
	dir := filepath.Join(procRoot, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods.slice/.../cri-containerd-" + containerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// A get-cert caller in pod P resolves to P's sandbox, whose inventory is P's
// containers — the injected sidecar included, and never another pod's.
func TestInventoryResolvesPodAndIsolatesOtherPods(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const (
		pod1 = "sandbox-1"
		pod2 = "sandbox-2"
	)
	// pod1: get-cert sidecar + two app containers.
	b.record(cidGetCert, pod1, "c8s-cert", digestOther, nil, nil)
	b.record(cidApp1, pod1, "app", digestApp, nil, nil)
	b.record(cidApp2, pod1, "worker", digestApp2, nil, nil)
	// pod2: a different app; must never appear in pod1's answer.
	b.record(cidOther, pod2, "app", digestOther, nil, nil)

	// The caller is the get-cert process in pod1.
	writeCgroup(t, procRoot, 4242, cidGetCert)

	got, err := sandboxDigestsFor(b, 4242)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{digestOther, digestApp, digestApp2}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("digests = %v, want %v (pod1's containers incl. sidecar, no pod2)", got, want)
	}
}

func TestInventoryRejectsUntrackedAndZeroPID(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)

	if _, err := sandboxDigestsFor(b, 0); err == nil {
		t.Fatal("peer pid 0 accepted (node-CVM must bind the caller)")
	}
	writeCgroup(t, procRoot, 55, cidOther)
	if _, err := sandboxDigestsFor(b, 55); err == nil {
		t.Fatal("untracked caller container accepted")
	}
}

// The nesting attack (review finding #1): a caller in pod2 creates a child
// cgroup named with pod1's app container ID. The inventory must resolve the
// shallowest tracked container (pod2's own get-cert), NOT the nested pod1 ID,
// so it returns pod2's digests — never pod1's.
func TestInventoryRejectsNestedVictimCgroup(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const pod1, pod2 = "sandbox-1", "sandbox-2"
	b.record(cidApp1, pod1, "app", digestApp, nil, nil) // victim's app in pod1
	b.record(cidGetCert, pod2, "c8s-cert", digestOther, nil, nil)
	b.record(cidApp2, pod2, "app", digestApp2, nil, nil) // attacker's own app in pod2

	// Attacker's process: its real scope is cidGetCert (pod2), with a nested
	// child cgroup named cidApp1 (pod1's container).
	dir := filepath.Join(procRoot, "999")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods/.../cri-containerd-" + cidGetCert + ".scope/" + cidApp1 + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := sandboxDigestsFor(b, 999)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, digestApp) {
		t.Fatalf("nested victim cgroup leaked pod1's digest: %v", got)
	}
	if !slices.Contains(got, digestApp2) {
		t.Fatalf("attacker's own pod2 digests missing: %v", got)
	}
}

// An unresolved digest must fail the whole answer: serving the siblings that
// did resolve would pass a subset off as the sandbox's whole image set.
func TestInventoryRefusesUnresolvedDigest(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const pod1 = "sandbox-1"
	b.record(cidGetCert, pod1, "c8s-cert", digestOther, nil, nil)
	b.record(cidApp1, pod1, "app", digestApp, nil, nil)
	b.record(cidApp2, pod1, "worker", "", nil, nil) // resolve failed at admission
	writeCgroup(t, procRoot, 4242, cidGetCert)

	if _, err := sandboxDigestsFor(b, 4242); err == nil {
		t.Fatal("served a subset of the sandbox's images as if it were the whole set")
	}
}

// A removed container leaves caller resolution but stays in the sandbox's
// admission record. Dropping it would let a pod hide a container by arranging
// for it to be absent when asked — kubelet removes and recreates a container
// across a CrashLoopBackOff, so that window is free (docs/secrets.md).
func TestInventoryRemoveKeepsAdmissionRecord(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)
	writeCgroup(t, procRoot, 77, cidGetCert)

	b.remove(cidApp1)
	got, err := sandboxDigestsFor(b, 77)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, slicesSorted([]string{digestOther, digestApp})) {
		t.Fatalf("digests = %v, want the removed container still recorded", got)
	}

	// It is gone for caller resolution, though: a stopped container must not
	// bind a caller.
	writeCgroup(t, procRoot, 78, cidApp1)
	if _, err := sandboxDigestsFor(b, 78); err == nil {
		t.Fatal("a removed container still resolved a caller")
	}

	// Tearing the sandbox down does clear it.
	b.removeSandbox("sandbox-1")
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); known {
		t.Fatal("removed sandbox still known")
	}
}

// sandboxForPeer binds the caller by kernel PID → cgroup → tracked container
// → its sandbox. An untracked caller fails.
func TestInventorySandboxForPeer(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil, nil)
	writeCgroup(t, procRoot, 4242, cidGetCert)

	got, err := b.sandboxForPeer(workloadclaims.PeerForPID(4242))
	if err != nil {
		t.Fatal(err)
	}
	if got != "sandbox-1" {
		t.Fatalf("sandbox = %q, want sandbox-1", got)
	}

	writeCgroup(t, procRoot, 55, cidOther)
	if _, err := b.sandboxForPeer(workloadclaims.PeerForPID(55)); err == nil {
		t.Fatal("untracked caller resolved to a sandbox")
	}
	if _, err := b.sandboxForPeer(workloadclaims.PeerForPID(0)); err == nil {
		t.Fatal("peer pid 0 accepted")
	}
}

func TestInventoryDigestsForSandbox(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())

	if _, _, known, err := b.DigestsForSandbox("nope"); err != nil || known {
		t.Fatalf("unknown sandbox: known=%v err=%v, want known=false", known, err)
	}

	// A known sandbox with no containers answers an empty inventory.
	b.recordSandbox("sandbox-empty")
	got, _, known, err := b.DigestsForSandbox("sandbox-empty")
	if err != nil || !known {
		t.Fatalf("empty sandbox: known=%v err=%v", known, err)
	}
	if len(got) != 0 {
		t.Fatalf("digests = %v, want none", got)
	}

	// The inventory includes injected containers, deduplicates, and sorts.
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)
	b.record(cidApp2, "sandbox-1", "worker", digestApp, nil, nil)
	b.record(cidOther, "sandbox-2", "app", digestApp2, nil, nil)
	got, _, known, err = b.DigestsForSandbox("sandbox-1")
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if want := []string{digestOther, digestApp}; !slices.Equal(got, slicesSorted(want)) {
		t.Fatalf("digests = %v, want %v (sorted, deduped, sidecar included, no sandbox-2)", got, slicesSorted(want))
	}
}

func slicesSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// An unresolved digest fails the whole inventory rather than serve a subset:
// the inventory covers every running container, injected ones included.
func TestInventoryDigestsForSandboxRefusesUnresolved(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	b.record(cidGetCert, "sandbox-1", "c8s-cert", "", nil, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)

	if _, _, _, err := b.DigestsForSandbox("sandbox-1"); err == nil {
		t.Fatal("served a subset of the sandbox inventory")
	}
}

// removeSandbox evicts the sandbox and its containers; recording a container
// alone (no pod event) still makes its sandbox known.
func TestInventorySandboxLifecycle(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())

	b.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); !known {
		t.Fatal("recorded container did not imply its sandbox")
	}

	b.record(cidOther, "sandbox-2", "app", digestApp2, nil, nil)
	b.removeSandbox("sandbox-1")
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); known {
		t.Fatal("removed sandbox still known")
	}
	got, _, known, err := b.DigestsForSandbox("sandbox-2")
	if err != nil || !known || !slices.Equal(got, []string{digestApp2}) {
		t.Fatalf("sandbox-2 after removing sandbox-1: %v %v %v", got, known, err)
	}
	// sandbox-1's containers went with it.
	if len(b.containers) != 1 {
		t.Fatalf("containers = %v, want only sandbox-2's", b.containers)
	}
}

// Two admissions whose argv differ only in how a separator byte falls must both
// survive in the high-water mark. Under a separator argv can carry, the second
// record overwrote the first — and it vanished from the digests view too, so
// CDS's cross-check between the two views still agreed and the sandbox stayed
// eligible to be named for a workload it had not run.
func TestInventoryArgvSeparatorDoesNotEraseAdmissions(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	const sandbox = "sandbox-1"

	b.record(cidApp1, sandbox, "app", digestApp, []string{"/app\x1f--serve"}, nil)
	b.record(cidApp2, sandbox, "app", digestApp, []string{"/app", "--serve"}, nil)

	_, containers, known, err := b.DigestsForSandbox(sandbox)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if len(containers) != 2 {
		t.Fatalf("containers = %+v, want both admissions recorded", containers)
	}
	for _, want := range [][]string{{"/app\x1f--serve"}, {"/app", "--serve"}} {
		if !slices.ContainsFunc(containers, func(c workloadclaims.SandboxContainer) bool {
			return slices.Equal(c.Argv, want)
		}) {
			t.Fatalf("argv %q was erased from the high-water mark: %+v", want, containers)
		}
	}
}

// A container recorded without a digest closes its sandbox's answer; a later
// record that resolves that same container reopens it.
func TestInventory_UnresolvedClearsWhenTheContainerResolves(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.record("ctr-1", "sbx-1", "app", "", nil, nil)
	inv.record("ctr-2", "sbx-1", "side", pushDigestA, nil, nil)

	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("an unresolved container must fail the whole answer")
	}

	inv.record("ctr-3", "sbx-1", "other", "", nil, nil)
	inv.record("ctr-1", "sbx-1", "app", pushDigestB, nil, nil)
	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("a second unresolved container must keep the answer closed")
	}

	inv.record("ctr-3", "sbx-1", "other", pushDigestC, nil, nil)
	digests, _, _, err := inv.DigestsForSandbox("sbx-1")
	if err != nil {
		t.Fatalf("resolving every container must reopen the answer: %v", err)
	}
	for _, want := range []string{pushDigestA, pushDigestB, pushDigestC} {
		if !slices.Contains(digests, want) {
			t.Fatalf("digests %v missing %s", digests, want)
		}
	}
}

// unresolved is keyed on the runtime-assigned container ID: two containers in a
// sandbox can share a name, and one resolving must not clear the other.
func TestInventory_UnresolvedIsKeyedOnContainerID(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.record("ctr-1", "sbx-1", "app", "", nil, nil)
	inv.record("ctr-2", "sbx-1", "app", pushDigestA, nil, nil)

	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("a namesake container cleared another container's unresolved marker")
	}

	inv.record("ctr-1", "sbx-1", "app", pushDigestB, nil, nil)
	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err != nil {
		t.Fatalf("resolving the container itself must reopen the answer: %v", err)
	}
}
