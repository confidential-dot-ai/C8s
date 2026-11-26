package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// ValidateContainerAdjustment runs after all create-time plugins. Unlike a
// StartContainer notification, a failed/disconnected validator rejects creation.
// Together with containerd's required_plugins configuration this prevents a
// plugin disconnect between creation and start from bypassing launch admission.
//
// The container has no root to measure yet, so an fsVerityFile rule is judged
// on its source and read-only mode alone; the start check decides the digest.
func (p *plugin) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
	defer p.cvm().lockAdmission()()
	if err := p.cvm().refuseLapsedRuntime(); err != nil {
		return err
	}
	if req.GetContainer() == nil || req.GetPod() == nil {
		return fmt.Errorf("missing container or sandbox in NRI validation")
	}
	if err := refuseSourceEdit(req.GetAdjust()); err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), req.GetContainer().GetName(), err)
	}
	ctr, env := adjustedLaunchContainer(req)
	imageRef, err := p.cvm().imageOf(req.GetPod(), ctr)
	if err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), err)
	}
	mounts := p.adjustedMounts(ctx, req, ctr)
	observed := observedContainer{
		pod:         req.GetPod(),
		ctr:         ctr,
		imageRef:    imageRef,
		env:         env,
		mounts:      mounts,
		deferVerity: bindDestinations(mounts),
		// The gate and the static-pod check run ahead of admission; all three
		// share one lookup, so they judge one digest.
		lookup: p.digestLookup(ctx, imageRef),
	}
	// The gate runs ahead of the admission check and independently of
	// policy.mode: a protected pod's container runs only once it is verified.
	if err := p.gateMesh(ctx, req, observed); err != nil {
		// A pre-existing pod recovery has not yet reached is off the gate's
		// record: refuse the create, but transiently, so the retry after
		// recovery is not met by a denial recorded for the pod's life. A
		// sandbox still off the record once recovery has run is unknown, and
		// its refusal stands.
		if errors.Is(err, errSandboxOffRecord) && !p.mesh.recoveryDone() {
			return err
		}
		return p.denyContainer(req.GetPod().GetId(), err)
	}
	if err := p.unpinnedStaticPod(ctx, p.cfg, observed); err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), err)
	}
	snap := p.policy.current()
	verdict, reason := p.checkContainerObserved(ctx, p.cfg, snap, observed, launchFinal)
	if verdict == verdictDeny && p.cfg.Policy.Mode != ModeAudit {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), fmt.Errorf("%s", reason))
	}
	if err := p.noteNodeService(ctx, snap, observed); err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), err)
	}
	p.noteCapabilityGrant(ctx, p.cfg, snap, observed)
	// No inventory record here: later validators can still reject creation, and
	// CDI transformations under an any policy have not happened yet.
	return nil
}

// noteCapabilityGrant records what the allowlists declare for this launch, for
// the runtime wrapper to hold the container's create to (capabilitygrants.go).
// The record belongs to this hook: a validator that does not answer fails the
// create, and the wrapper reads the record before the start check runs. It
// reads the digest and snapshot admission judged; with no allowlist nothing
// declares a capability, so it looks up no digest.
func (p *plugin) noteCapabilityGrant(ctx context.Context, cfg *config, snap *policySnapshot, observed observedContainer) {
	var declared [][]string
	if cfg.AllowlistEnabled() {
		declared = p.policy.declaredCapabilities(snap, p.observedLaunch(ctx, observed))
	}
	id := observed.ctr.GetId()
	if err := p.capGrants.note(id, declared); err != nil {
		p.logger.Error("cannot record the container's capability grant; the runtime wrapper refuses it every capability beyond the node's default set", "container", id, "error", err)
	}
}

// refuseSourceEdit refuses an NRI edit setting or removing the kubelet's
// static pod mark, which c8s-runc's floor reads from the bundle.
func refuseSourceEdit(adjust *api.ContainerAdjustment) error {
	for key := range adjust.GetAnnotations() {
		if name, _ := api.IsMarkedForRemoval(key); name == configSourceAnnotation {
			return fmt.Errorf("an NRI plugin edits the %s annotation", configSourceAnnotation)
		}
	}
	return nil
}

// unpinnedStaticPod refuses, on a worker, a static pod's container whose launch
// no base entry pins: c8s-runc's floor leaves a static pod to its template.
func (p *plugin) unpinnedStaticPod(ctx context.Context, cfg *config, observed observedContainer) error {
	if !cfg.Worker || !staticPod(observed.pod) {
		return nil
	}
	if p.policy.baseAdmitsPinned(p.observedLaunch(ctx, observed)) {
		return nil
	}
	return errors.New("a worker runs a static pod only on a launch a base entry pins")
}

// gateMesh applies the mesh startup gate at the one hook whose error always
// rejects a creation: a create notification can time out and a closed plugin
// lets the create proceed, while a validator's refusal is the answer.
func (p *plugin) gateMesh(ctx context.Context, req *api.ValidateContainerAdjustmentRequest, observed observedContainer) error {
	pod := observed.pod
	ctr := observed.ctr
	if !p.mesh.hosts(pod) {
		return nil
	}
	launch := p.observedLaunch(ctx, observed)
	adjusted := req.GetAdjust().GetLinux()
	// The role, and the mount set a declaration pins, are read from the mounts
	// the pod itself asks for: a credential client of any pod also carries the
	// binds this enforcer adds (credentialMounts), which no declaration names.
	declared := launch
	declared.Mounts = p.observedMounts(ctx, pod, req.GetContainer())
	role, err := p.cvm().adjustmentRole(pod, ctr, launch, declared, observed.mounts)
	if err != nil {
		return err
	}
	return p.mesh.admit(pod, ctr, gatedContainer{
		role:         role,
		mountsPinned: p.bindsRoleMounts(declared, role),
		digest:       launch.Digest,
		argv:         launch.Argv,
		namespaces:   adjusted.GetNamespaces(),
		netDevices:   adjusted.GetNetDevices(),
	})
}

func bindDestinations(mounts []allowlist.ObservedMount) []string {
	destinations := make([]string, len(mounts))
	for i, m := range mounts {
		destinations[i] = m.Destination
	}
	return destinations
}

// adjustedLaunchContainer applies the env/argv part of cumulative NRI edits.
// For valid unique input names this is equivalent to NRI's AdjustEnv: the last
// edit per name wins; marked names are removed. Order is irrelevant to policy.
// Invalid input or deferred CDI injection yields unknown env evidence, so only
// unrestricted env policies can admit it at this stage. Never guess an empty env.
func adjustedLaunchContainer(req *api.ValidateContainerAdjustmentRequest) (*api.Container, *allowlist.EnvObservation) {
	ctr := proto.Clone(req.GetContainer()).(*api.Container)
	adjust := req.GetAdjust()
	if len(adjust.GetArgs()) > 0 {
		ctr.Args = slices.Clone(adjust.GetArgs())
	}
	if len(adjust.GetCDIDevices()) > 0 {
		return ctr, nil
	}
	if len(adjust.GetEnv()) == 0 {
		return ctr, containerEnv(ctr)
	}
	if _, err := observeEnv(ctr); err != nil {
		return ctr, nil
	}
	values := map[string]string{}
	for _, entry := range ctr.Env {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	for _, edit := range adjust.GetEnv() {
		if edit == nil {
			return ctr, nil
		}
		name, remove := edit.IsMarkedForRemoval()
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return ctr, nil
		}
		if remove {
			delete(values, name)
		} else {
			values[name] = edit.Value
		}
	}
	ctr.Env = nil
	for name, value := range values {
		ctr.Env = append(ctr.Env, name+"="+value)
	}
	return ctr, containerEnv(ctr)
}

// adjustedMounts observes cumulative edits; deferred CDI leaves evidence unavailable.
func (p *plugin) adjustedMounts(ctx context.Context, req *api.ValidateContainerAdjustmentRequest, ctr *api.Container) []allowlist.ObservedMount {
	if len(req.GetAdjust().GetCDIDevices()) > 0 {
		return nil
	}
	for _, edit := range req.GetAdjust().GetMounts() {
		if edit == nil {
			return nil
		}
		destination, remove := edit.IsMarkedForRemoval()
		ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
			return m.GetDestination() == destination
		})
		if !remove {
			ctr.Mounts = append(ctr.Mounts, proto.Clone(edit).(*api.Mount))
		}
	}
	return p.observedMounts(ctx, req.GetPod(), ctr)
}
