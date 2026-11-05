package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ValidateContainerAdjustment runs after all create-time plugins. Unlike a
// StartContainer notification, a failed/disconnected validator rejects creation.
// Together with containerd's required_plugins configuration this prevents a
// plugin disconnect between creation and start from bypassing launch admission.
func (p *plugin) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
	if req.GetContainer() == nil || req.GetPod() == nil {
		return fmt.Errorf("missing container or sandbox in NRI validation")
	}
	if err := refuseSourceEdit(req.GetAdjust()); err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), req.GetContainer().GetName(), err)
	}
	ctr, env := adjustedLaunchContainer(req)
	mounts := p.adjustedMounts(req, ctr)
	// The gate and the static-pod check run ahead of admission; all three
	// share one lookup, so they judge one digest.
	imageRef := ctr.GetAnnotations()[annotationImageName]
	lookup := p.digestLookup(ctx, imageRef)
	// The gate runs ahead of the admission check and independently of
	// policy.mode: a protected pod's container runs only once it is verified.
	if err := p.gateMesh(req, ctr, lookup, env, mounts); err != nil {
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
	if err := p.unpinnedStaticPod(p.cfg, req.GetPod(), ctr, lookup, env, mounts); err != nil {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), err)
	}
	verdict, reason, _ := p.checkContainerObserved(ctx, p.cfg, p.policy.current(), req.GetPod(), ctr, imageRef, lookup, launchFinal, env, mounts)
	if verdict == verdictDeny && p.cfg.Policy.Mode != ModeAudit {
		return p.denyContainerCreation(req.GetPod().GetId(), ctr.GetName(), fmt.Errorf("%s", reason))
	}
	// No inventory record here: later validators can still reject creation, and
	// CDI transformations under an any policy have not happened yet.
	return nil
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
func (p *plugin) unpinnedStaticPod(cfg *config, pod *api.PodSandbox, ctr *api.Container, lookup func() (string, error), env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) error {
	if !cfg.Worker || !staticPod(pod) {
		return nil
	}
	if p.policy.baseAdmitsPinned(lookedUpLaunch(lookup, ctr, env, mounts)) {
		return nil
	}
	return errors.New("a worker runs a static pod only on a launch a base entry pins")
}

// gateMesh applies the mesh startup gate at the one hook whose error always
// rejects a creation: a create notification can time out and a closed plugin
// lets the create proceed, while a validator's refusal is the answer.
func (p *plugin) gateMesh(req *api.ValidateContainerAdjustmentRequest, ctr *api.Container, lookup func() (string, error), env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) error {
	pod := req.GetPod()
	if !p.mesh.hosts(pod) {
		return nil
	}
	launch := lookedUpLaunch(lookup, ctr, env, mounts)
	adjusted := req.GetAdjust().GetLinux()
	// The role, and the mount set a declaration pins, are read from the mounts
	// the pod itself asks for: a credential client of any pod also carries the
	// binds this enforcer adds (credentialMounts), which no declaration names.
	declared := launch
	declared.Mounts = p.observedMounts(pod, req.GetContainer())
	role := p.roleOf(declared)
	return p.mesh.admit(pod, ctr, gatedContainer{
		role:         role,
		mountsPinned: p.bindsRoleMounts(declared, role),
		digest:       launch.Digest,
		argv:         launch.Argv,
		namespaces:   adjusted.GetNamespaces(),
		netDevices:   adjusted.GetNetDevices(),
	})
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
func (p *plugin) adjustedMounts(req *api.ValidateContainerAdjustmentRequest, ctr *api.Container) []allowlist.ObservedMount {
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
	return p.observedMounts(req.GetPod(), ctr)
}
