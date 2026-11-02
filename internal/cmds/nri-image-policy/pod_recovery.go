package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/admissionhistory"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// All callers hold podMu. A clean checkpoint never contains an authority
// mutation whose durable commit is still in flight.
func (p *plugin) beginPodTransition() error {
	if p.recovery == nil {
		return nil
	}
	if p.podStartDisconnected.Load() {
		return errors.New("pod runtime connection ended")
	}
	if p.cfg.podWaiting() {
		return nil
	}
	if p.recovery.state == nil {
		return errors.New("pod recovery has not registered a clean boot")
	}
	if err := p.recovery.begin(); err != nil {
		p.endPodIdentity(err)
		return err
	}
	return nil
}

func (p *plugin) finishPodTransition(result *error) {
	if p.recovery == nil || p.cfg.podWaiting() {
		return
	}
	if !p.recovery.active {
		return
	}
	state, err := p.checkpointPod()
	if err == nil {
		err = p.recovery.commit(state)
	}
	if err != nil {
		p.recovery.failed = err
		clear(p.podStarts)
		if p.podBroker != nil {
			p.podBroker.terminal = err
			p.podBroker.cancel()
		}
	}
	*result = errors.Join(*result, err)
}

func (p *plugin) checkpointPod() (*podRecoveryState, error) {
	s, b := p.recovery, p.podBroker
	if s == nil || b == nil || p.measurer == nil || p.inventory == nil {
		return nil, errors.New("pod recovery is missing its authority")
	}
	policy, err := checkpointPodPolicy(p.policy.current())
	if err != nil {
		return nil, err
	}
	state := &podRecoveryState{Version: 1, KernelBootID: s.kernelBootID, ConfigDigest: s.configDigest, BootID: b.bootID, Sandbox: s.sandbox,
		Processes: s.processes, Histories: map[string]json.RawMessage{}, Containers: map[string]podRecoveredContainer{}, Denials: map[string]podRecoveredDenial{},
		Sandboxes: []string{}, Mesh: map[string]podRecoveredMesh{}, Digests: p.measurer.Digests(), Policy: policy}
	if b.terminal != nil {
		state.Terminal = b.terminal.Error()
	}
	inv := p.inventory
	inv.mu.RLock()
	state.Revision = inv.revision
	for id, h := range inv.admitted {
		raw, err := h.Checkpoint()
		if err != nil {
			inv.mu.RUnlock()
			return nil, err
		}
		state.Histories[id] = raw
	}
	for id, c := range inv.containers {
		state.Containers[id] = podRecoveredContainer{SandboxID: c.sandboxID, Name: c.name, Digest: c.digest, Argv: slices.Clone(c.argv)}
	}
	for id, d := range inv.denied {
		saved := podRecoveredDenial{Creations: map[string]string{}}
		if d.permanent != nil {
			saved.Permanent = d.permanent.Error()
		}
		for name, err := range d.creations {
			saved.Creations[name] = err.Error()
		}
		state.Denials[id] = saved
	}
	for id := range inv.sandboxes {
		state.Sandboxes = append(state.Sandboxes, id)
	}
	inv.mu.RUnlock()
	slices.Sort(state.Sandboxes)
	p.mesh.mu.Lock()
	for id, m := range p.mesh.pods {
		saved := podRecoveredMesh{NamespacePath: m.netns.path, Device: m.netns.id.device, Inode: m.netns.id.inode, MeshStarted: m.meshStarted, WorkloadCreated: m.workloadCreated, KubeNamespace: m.kubeNamespace, ExitEntry: m.exitEntry, Exits: slices.Clone(m.exits)}
		if m.refusal != nil {
			saved.Refusal = m.refusal.Error()
		}
		for _, role := range m.roleLaunches {
			saved.Roles = append(saved.Roles, podRecoveredRole{Role: role.role, Digest: role.digest, Argv: slices.Clone(role.argv)})
		}
		state.Mesh[id] = saved
	}
	p.mesh.mu.Unlock()
	if b.root != nil {
		identity, err := podRootIdentity(b.root)
		if err != nil {
			return nil, err
		}
		state.CredentialSource = b.source
		state.CredentialDevice, state.CredentialInode = identity.device, identity.inode
		state.CredentialIssuer, err = getcert.GuestIssuerBinding(b.root)
		if err != nil {
			return nil, err
		}
		if s.state != nil && s.state.CredentialIssuer != "" && state.CredentialIssuer != s.state.CredentialIssuer {
			return nil, errors.New("pod issuer binding changed after publication")
		}
		if err := samePodCredentialRoot(b.root, b.source); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// restorePodRecovery runs at Synchronize before any reconstruction or rules
// installation. It restores only guest-retained authorizations and verifies
// every object still present in the runtime independently.
func (p *plugin) restorePodRecovery(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) (result error) {
	s := p.recovery
	if s == nil || p.cfg.podWaiting() {
		return nil
	}
	if err := s.begin(); err != nil {
		return err
	}
	// Any unsuccessful recovery deliberately leaves its crash fence in place.
	saved := s.state
	if saved == nil {
		return errors.New("missing Pod recovery checkpoint")
	}
	marker, markerErr := readPodRecoveryFile(p.podBroker.runtime, podBrokerMarker)
	if saved.CredentialSource != "" {
		if markerErr != nil || string(marker) != saved.BootID+"\n" {
			return errors.New("pod recovery lost its claimed broker identity")
		}
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return errors.New("pod recovery has an unrecorded credential identity")
	}
	if !slices.Equal(saved.Digests, p.measurer.Digests()) {
		return errors.New("pod recovery journal differs from retained history")
	}
	policy, err := restorePodPolicy(saved.Policy)
	if err != nil {
		return err
	}
	p.policy.snap.Store(policy)
	if saved.Sandbox == nil {
		if len(pods) != 0 || len(ctrs) != 0 || len(saved.Histories) != 0 || len(saved.Processes) != 0 || len(saved.Mesh) != 0 || len(saved.Digests) != 0 {
			return errors.New("unclaimed Pod recovery state has runtime history")
		}
	} else {
		if len(pods) != 1 {
			return errors.New("pod recovery requires the original sandbox")
		}
		pod := pods[0]
		want := saved.Sandbox
		if pod.GetId() != want.ID || pod.GetUid() != want.UID || pod.GetName() != want.Name || pod.GetNamespace() != want.Namespace || pod.GetPid() != want.PID || want.Name != p.cfg.Pod.Name || want.Namespace != p.cfg.Pod.Namespace {
			return errors.New("pod recovery sandbox identity changed")
		}
		birth, err := podProcessBirth(pod.GetPid())
		if err != nil || birth != want.Birth {
			return errors.New("pod recovery sandbox process changed")
		}
	}
	inv := newAdmissionInventory(p.inventory.procRoot)
	inv.needsVariableEvidence = p.inventory.needsVariableEvidence
	inv.revision = saved.Revision
	for id, raw := range saved.Histories {
		if saved.Sandbox == nil || id != saved.Sandbox.ID {
			return errors.New("pod recovery history belongs to another sandbox")
		}
		h, err := admissionhistory.RestoreCheckpoint(raw)
		if err != nil {
			return err
		}
		inv.admitted[id] = h
	}
	for _, id := range saved.Sandboxes {
		if saved.Sandbox == nil || id != saved.Sandbox.ID {
			return errors.New("pod recovery sandbox set changed")
		}
		inv.sandboxes[id] = struct{}{}
	}
	if err := validatePodRecoveredAdmissions(saved, inv); err != nil {
		return err
	}
	for id, d := range saved.Denials {
		if saved.Sandbox == nil || id != saved.Sandbox.ID {
			return errors.New("pod recovery refusal belongs to another sandbox")
		}
		restored := sandboxDenial{creations: map[string]error{}}
		if d.Permanent != "" {
			return errors.New("pod recovery retained a permanent admission refusal")
		}
		for name, reason := range d.Creations {
			restored.creations[name] = errors.New(reason)
		}
		inv.denied[id] = restored
	}
	restoredMesh := map[string]*protectedPod{}
	for id, m := range saved.Mesh {
		if saved.Sandbox == nil || id != saved.Sandbox.ID || m.Refusal != "" {
			return errors.New("pod recovery lost packet protection")
		}
		pod := pods[0]
		netns, err := proveSandboxNamespace(podNetworkNamespace(pod), pod.GetPid())
		if err != nil {
			return err
		}
		if netns.path != m.NamespacePath || netns.id != (fileID{device: m.Device, inode: m.Inode}) || m.KubeNamespace != pod.GetNamespace() {
			return errors.New("pod recovery network namespace changed")
		}
		if err := verifyPodRuleset(netns, p.mesh.policy, m.KubeNamespace, m.Exits); err != nil {
			return fmt.Errorf("pod recovery packet protection: %w", err)
		}
		state := &protectedPod{netns: netns, meshStarted: m.MeshStarted, workloadCreated: m.WorkloadCreated, kubeNamespace: m.KubeNamespace, exitEntry: m.ExitEntry, exits: slices.Clone(m.Exits)}
		for _, role := range m.Roles {
			state.roleLaunches = append(state.roleLaunches, roleLaunch{role: role.Role, digest: role.Digest, argv: slices.Clone(role.Argv)})
		}
		restoredMesh[id] = state
	}
	if saved.Sandbox != nil && len(restoredMesh) != 1 {
		return errors.New("pod recovery has no retained sandbox protection")
	}
	p.mesh.mu.Lock()
	p.mesh.pods = restoredMesh
	p.mesh.mu.Unlock()
	p.inventory = inv
	for _, ctr := range ctrs {
		if _, duplicate := inv.containers[ctr.GetId()]; duplicate {
			return errors.New("pod recovery runtime repeated a container")
		}
		proof, ok := saved.Processes[ctr.GetId()]
		if !ok || proof.Removed || saved.Sandbox == nil || ctr.GetPodSandboxId() != saved.Sandbox.ID || proof.SandboxID != saved.Sandbox.ID || ctr.GetName() != proof.Name {
			return errors.New("pod recovery found an unknown or replaced container")
		}
		pod := pods[0]
		image, err := p.containerImage(pod, ctr)
		if err != nil {
			return err
		}
		if image != proof.Digest {
			return errors.New("pod recovery container image changed")
		}
		if err := p.containerd.VerifyContainerImage(ctx, ctr.GetId(), pod.GetId(), image); err != nil {
			return err
		}
		launch := p.observedLaunch(withResolved(ctx), ctr, image, containerEnv(ctr), p.observedMounts(pod, ctr))
		if podLaunchKey(launch) != proof.LaunchKey || p.roleOf(launch) != proof.Role {
			return errors.New("pod recovery final launch differs from its authorization")
		}
		gated := gatedContainer{role: proof.Role, mountsPinned: p.bindsRoleMounts(launch, proof.Role), digest: launch.Digest, argv: launch.Argv}
		if _, _, err := p.mesh.admissible(pod, ctr, gated); err != nil {
			return err
		}
		source, err := p.podCredentialSource(pod, ctr, proof.Role, launch.Mounts)
		if err != nil {
			return err
		}
		if source != "" && source != saved.CredentialSource {
			return errors.New("pod recovery credential mount changed")
		}
		if ctr.GetState() == api.ContainerState_CONTAINER_RUNNING || ctr.GetState() == api.ContainerState_CONTAINER_CREATED {
			birth, err := podProcessIdentity(ctr.GetPid(), ctr.GetId())
			if err != nil || ctr.GetPid() != proof.PID || birth != proof.Birth {
				return errors.New("pod recovery container process changed")
			}
		} else if ctr.GetState() != api.ContainerState_CONTAINER_STOPPED {
			return errors.New("pod recovery container state is unknown")
		}
		if verdict, reason := p.checkContainer(ctx, p.cfg, pod, ctr, image); verdict == verdictDeny {
			return fmt.Errorf("pod recovery current policy refusal: %s", reason)
		}
		inv.containers[ctr.GetId()] = ctrRec{sandboxID: proof.SandboxID, name: proof.Name, digest: proof.Digest, argv: slices.Clone(ctr.GetArgs())}
		if ctr.GetState() == api.ContainerState_CONTAINER_STOPPED {
			inv.stop(ctr.GetId())
		}
	}
	// Runtime removal cannot erase an admission. It only removes live caller
	// identity, including jobs removed while the plugin was disconnected.
	for id, record := range saved.Containers {
		if _, live := inv.containers[id]; !live {
			history := inv.admitted[record.SandboxID]
			history.Exited(id)
			inv.admitted[record.SandboxID] = history
		}
	}
	if saved.Sandbox != nil && len(saved.Digests) > 0 {
		observations, _, err := inv.podSnapshot(saved.Sandbox.ID)
		if err != nil {
			return err
		}
		claims := workloadclaims.PodClaims{Version: 1, BootID: saved.BootID, AssignedPodUID: p.cfg.Pod.UID, RuntimePodUID: saved.Sandbox.UID, SandboxID: saved.Sandbox.ID, Revision: saved.Revision, RuntimeExtensions: saved.Digests, Containers: observations}
		if _, err := claims.Canonical(); err != nil {
			return err
		}
	}
	if len(saved.Digests) > 0 && saved.CredentialSource == "" {
		return errors.New("pod recovery lost credential custody")
	}
	if saved.CredentialSource != "" {
		root, err := openRetainedPodCredentialRoot(saved.CredentialSource, fileID{device: saved.CredentialDevice, inode: saved.CredentialInode})
		if err != nil {
			return err
		}
		issuer, err := getcert.GuestIssuerBinding(root)
		if err != nil || issuer != saved.CredentialIssuer {
			root.Close()
			return errors.New("pod recovery issuer binding was lost or changed")
		}
		p.podBroker.root = root
		p.podBroker.source = saved.CredentialSource
		p.podBroker.pod = pods[0]
	}
	clear(p.podStarts)
	p.podRecovered = true
	// Revalidate the sandbox after the potentially slow image proofs.
	if saved.Sandbox != nil {
		birth, err := podProcessBirth(saved.Sandbox.PID)
		if err != nil || birth != saved.Sandbox.Birth {
			return errors.New("pod recovery sandbox exited during verification")
		}
	}
	state, err := p.checkpointPod()
	if err != nil {
		return err
	}
	if err := s.commit(state); err != nil {
		return err
	}
	if p.podBroker.root != nil {
		p.runPodCredentialWorker()
	}
	return nil
}

func podLaunchKey(launch allowlist.RunningContainer) string {
	return podObservationKey(workloadclaims.SandboxContainer{Digest: launch.Digest, Argv: launch.Argv, Env: launch.Env, Mounts: launch.Mounts})
}

func (p *plugin) rememberPodSandbox(pod *api.PodSandbox) error {
	if p.recovery == nil {
		return nil
	}
	if existing := p.recovery.sandbox; existing != nil {
		if existing.ID != pod.GetId() || existing.UID != pod.GetUid() {
			return errors.New("pod sandbox replacement ends this boot identity")
		}
		return nil
	}
	if pod.GetUid() == "" || pod.GetId() == "" || pod.GetName() != p.cfg.Pod.Name || pod.GetNamespace() != p.cfg.Pod.Namespace {
		return errors.New("pod sandbox does not match its assignment")
	}
	birth, err := podProcessBirth(pod.GetPid())
	if err != nil {
		return err
	}
	p.recovery.sandbox = &podRecoveredSandbox{ID: pod.GetId(), UID: pod.GetUid(), Name: pod.GetName(), Namespace: pod.GetNamespace(), PID: pod.GetPid(), Birth: birth}
	return nil
}

func (p *plugin) rememberPodProcess(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, image string) error {
	if p.recovery == nil {
		return nil
	}
	birth, err := podProcessIdentity(ctr.GetPid(), ctr.GetId())
	if err != nil {
		return err
	}
	launch := p.observedLaunch(ctx, ctr, image, containerEnv(ctr), p.observedMounts(pod, ctr))
	p.recovery.processes[ctr.GetId()] = podRecoveredProcess{SandboxID: pod.GetId(), Name: ctr.GetName(), Digest: launch.Digest, Role: p.roleOf(launch), LaunchKey: podLaunchKey(launch), PID: ctr.GetPid(), Birth: birth}
	return nil
}

// Policy replacement, revocation and its checkpoint share admission's lock.
func (p *plugin) applyPodPolicy(ctx context.Context, pulled *allowlist.Allowlist, version uint64) (result error) {
	p.podMu.Lock()
	defer p.podMu.Unlock()
	if p.recovery == nil || p.recovery.state == nil || !p.podRegistered.Load() {
		return errors.New("pod policy is waiting for verified runtime registration")
	}
	current := p.policy.current()
	if err := validatePodPolicyUpdate(current, pulled, version); err != nil {
		return err
	}
	if current.pulled != nil && current.version == version {
		return nil
	}
	if err := p.beginPodTransition(); err != nil {
		return err
	}
	defer p.finishPodTransition(&result)
	p.policy.apply(pulled, version)
	// Responses obtained under the previous capabilities cannot publish under
	// the new policy, even if all current containers remain admitted.
	p.inventory.mu.Lock()
	p.inventory.revision++
	p.inventory.mu.Unlock()
	p.podChanged()
	p.KillRevoked(ctx)
	return nil
}

// Reuse the history's canonical admission identity, including mount ordering
// and the distinction between unknown and empty evidence.
func podObservationKey(observation workloadclaims.SandboxContainer) string {
	var history admissionhistory.History
	history.Record("proof", observation.Digest, observation.Role, observation.Argv, observation.Env, observation.Mounts...)
	_, records, err := history.Snapshot(nil)
	if err != nil || len(records) != 1 {
		return ""
	}
	return records[0].Key()
}

func validatePodRecoveredAdmissions(saved *podRecoveryState, inv *admissionInventory) error {
	observations := map[string]workloadclaims.SandboxContainer{}
	for _, history := range inv.admitted {
		_, records, err := history.Snapshot(nil)
		if err != nil {
			return err
		}
		for _, record := range records {
			observations[podObservationKey(record)] = record
		}
	}
	proven := map[string]bool{}
	for id, proof := range saved.Processes {
		observation, exists := observations[proof.LaunchKey]
		if id == "" || proof.PID == 0 || proof.Birth == 0 || proof.Digest == "" || proof.LaunchKey == "" || !exists || observation.Role != proof.Role || observation.Digest != proof.Digest || saved.Sandbox == nil || proof.SandboxID != saved.Sandbox.ID {
			return errors.New("pod recovery lost a complete retained admission")
		}
		proven[proof.LaunchKey] = true
	}
	if len(proven) != len(observations) {
		return errors.New("pod recovery admission has no retained runtime authorization")
	}
	for id, record := range saved.Containers {
		proof, exists := saved.Processes[id]
		if !exists || proof.Removed || record.SandboxID != proof.SandboxID || record.Name != proof.Name || record.Digest != proof.Digest {
			return errors.New("pod recovery live inventory differs from its retained authorization")
		}
	}
	return nil
}
