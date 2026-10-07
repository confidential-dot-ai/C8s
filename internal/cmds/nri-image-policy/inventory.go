package nriimagepolicy

import (
	"fmt"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/admissionhistory"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// admissionInventory implements workloadclaims.SandboxResolver for node-CVM:
// which sandbox a calling process belongs to, and which image digests a named
// sandbox is running (docs/armtls.md, "Sandbox identity"). It is fed from the
// same CreateContainer / Synchronize events that drive enforcement — and
// pod-sandbox events for the sandbox set. Caller identity comes from the kernel
// (SO_PEERCRED → cgroup → container), never from the request.
//
// "Admitted" here and in every caller means the plugin let the container run,
// not that it passed the checks: audit mode or an undeliverable kill each
// leave one running, and the inventory reports what runs.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]ctrRec                   // live containerID -> record (caller resolution)
	admitted   map[string]admissionhistory.History // sandboxID -> everything ever admitted there
	denied     map[string]error                    // sandboxID -> why it asserts no identity
	sandboxes  map[string]struct{}                 // live pod sandbox IDs
	procRoot   string
}

type ctrRec struct {
	sandboxID string
	name      string // unread
	digest    string // canonical sha256:<hex>; "" when unresolved
	argv      []string
}

func newAdmissionInventory(procRoot string) *admissionInventory {
	return &admissionInventory{
		containers: map[string]ctrRec{},
		admitted:   map[string]admissionhistory.History{},
		denied:     map[string]error{},
		sandboxes:  map[string]struct{}{},
		procRoot:   procRoot,
	}
}

// record notes an admitted container, injected sidecars included: /digests is
// an inventory of what was admitted in the sandbox, and the injected images are
// admitted under any argv, so CDS drops them from workload matching itself.
// argv is the effective OCI process.args the container runs.
func (b *admissionInventory) record(containerID, sandboxID, name, digest string, argv []string, env *allowlist.EnvObservation, mounts ...allowlist.ObservedMount) {
	b.recordObserved(containerID, sandboxID, name, digest, argv, env, mounts)
}

func (b *admissionInventory) recordObserved(containerID, sandboxID, name, digest string, argv []string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) {
	if containerID == "" || sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.containers[containerID] = ctrRec{sandboxID: sandboxID, name: name, digest: digest, argv: argv}

	rec := b.admitted[sandboxID]
	rec.Record(containerID, digest, argv, env, mounts...)
	b.admitted[sandboxID] = rec

	// A container implies its sandbox, so a record arriving before (or without)
	// the pod event still leaves the sandbox resolvable.
	b.sandboxes[sandboxID] = struct{}{}
}

// remove evicts a stopped container from caller resolution only. The sandbox's
// admission record keeps it: a stopped container must not bind a caller, but it
// still ran here. That includes an unresolved digest, so a container
// that stops before one resolves closes its sandbox's answer for the sandbox's
// life.
func (b *admissionInventory) remove(containerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.containers, containerID)
}

// recordSandbox notes a live pod sandbox (RunPodSandbox / Synchronize).
func (b *admissionInventory) recordSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sandboxes[sandboxID] = struct{}{}
}

// removeSandbox evicts a removed pod sandbox and any containers still recorded
// under it, so a torn-down pod's digests cannot linger in /digests answers.
func (b *admissionInventory) removeSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sandboxes, sandboxID)
	delete(b.admitted, sandboxID)
	delete(b.denied, sandboxID)
	for id, rec := range b.containers {
		if rec.sandboxID == sandboxID {
			delete(b.containers, id)
		}
	}
}

// recordDenial notes a refusal that kept a container of the sandbox from
// running. The first reason stands for the sandbox's life; removeSandbox
// evicts it with the sandbox.
//
// INVARIANT: a sandbox with any denied container asserts no identity.
func (b *admissionInventory) recordDenial(sandboxID string, reason error) {
	if sandboxID == "" || reason == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, onRecord := b.denied[sandboxID]; onRecord {
		return
	}
	b.denied[sandboxID] = reason
}

// denial is why the sandbox asserts no identity, nil when every container of
// it the plugin decided on was let run.
func (b *admissionInventory) denial(sandboxID string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.denied[sandboxID]
}

// callerForPeer resolves the calling process to its tracked container record.
// A zero PID is rejected: on node-CVM the inventory MUST bind the caller via
// kernel credentials. peer.IsAlive() is rechecked after the /proc read so a PID
// recycled between SO_PEERCRED and that read (the peer exited mid-resolution)
// is rejected rather than resolved to whatever now holds the number
// (docs/getcert-workload-binding.md, Corner 1). Callers must hold at least
// b.mu.RLock.
func (b *admissionInventory) callerForPeer(peer workloadclaims.Peer) (ctrRec, error) {
	pid := peer.PID()
	if pid <= 0 {
		return ctrRec{}, fmt.Errorf("no peer credentials on the inventory connection")
	}
	candidates, err := workloadclaims.ContainerIDCandidatesForPID(b.procRoot, pid)
	if err != nil {
		return ctrRec{}, err
	}
	// The cgroup was read by PID; confirm the pinned peer is still the process
	// that was there, so a reused PID cannot bind the caller to a victim's
	// container. Fails closed if liveness can't be confirmed — the peer exited,
	// or no pidfd was available (anomalous on a supported CC kernel).
	if !peer.IsAlive() {
		return ctrRec{}, fmt.Errorf("cannot confirm the caller is still the pinned peer process (exited during resolution, or pidfd unavailable)")
	}
	// Resolve the shallowest candidate that is a tracked container: the
	// caller's own runtime-assigned scope is always an ancestor of any cgroup
	// it could nest, so this defeats a caller that names a child cgroup with a
	// victim's container ID (see ContainerIDCandidatesForPID).
	for _, id := range candidates {
		if rec, ok := b.containers[id]; ok {
			return rec, nil
		}
	}
	return ctrRec{}, fmt.Errorf("caller cgroup names no tracked container")
}

// sandboxForPeer resolves the calling process to the pod sandbox it runs in,
// bound by kernel credentials. The enforcer's own verification of that
// sandbox's protection is the plugin's answer (plugin.SandboxForPeer).
func (b *admissionInventory) sandboxForPeer(peer workloadclaims.Peer) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	caller, err := b.callerForPeer(peer)
	if err != nil {
		return "", err
	}
	return caller.sandboxID, nil
}

// DigestsForSandbox reports every container ever admitted in the sandbox,
// injected containers included: CDS drops the injected ones itself. Digests is
// the sorted, deduplicated digest set (issuance); containers carries the
// per-container (digest, argv) detail, sorted for a stable answer.
//
// An unresolved digest fails the whole answer rather than commit a subset as if
// it were the whole inventory.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.sandboxes[sandboxID]; !ok {
		return nil, nil, false, nil
	}
	digests, containers, err := b.admitted[sandboxID].Snapshot()
	if err != nil {
		return nil, nil, true, fmt.Errorf("sandbox %s %w", sandboxID, err)
	}
	return digests, containers, true, nil
}
