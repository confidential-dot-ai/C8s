package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// cvmRole is the half of admission a node CVM and a pod CVM answer differently:
// the pod CVM admits only its signed assignment, and every refusal ends it.
type cvmRole interface {
	// lockAdmission orders an admission mutation against credential publication.
	lockAdmission() func()
	refuseLapsedRuntime() error

	// imageOf is the image identity admission judges this container by.
	imageOf(pod *api.PodSandbox, ctr *api.Container) (string, error)
	// enforcerMounts are the binds this enforcer adds, which no declaration names.
	enforcerMounts() enforcerMounts
	containerMounts(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error)

	// gateStart returns the credential source the start it cleared publishes under.
	gateStart(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) (string, error)
	// finishStart issues the start permission the runtime redeems.
	finishStart(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, source string) error
	// adjustmentRole is the mesh role the validation hook judges, after the boundary checks that role clears.
	adjustmentRole(pod *api.PodSandbox, ctr *api.Container, launch, declared allowlist.RunningContainer, mounts []allowlist.ObservedMount) (string, error)

	admitSandbox(pod *api.PodSandbox) error
	// admitUnprotected decides a sandbox whose packet protection failed to install.
	admitUnprotected(pod *api.PodSandbox, cause error) error
	// endIdentity ends the identity a recorded denial costs; a node holds none.
	endIdentity(refusal error)
	// endIdentityForRefusal records a refusal a node leaves retryable.
	endIdentityForRefusal(pod *api.PodSandbox, refusal error)
	// denyCreation records a refused creation, which an admission of the same name lifts.
	denyCreation(pod *api.PodSandbox, ctr *api.Container, refusal error)
	stopAfterRestart(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container)
}

// INVARIANT: the signed pod section alone decides the role.
func (p *plugin) cvm() cvmRole {
	if p.cfg.podRole() {
		return podCVM{p: p}
	}
	return nodeCVM{p: p}
}

// nodeCVM admits the pods the control plane schedules on this node.
type nodeCVM struct {
	p *plugin
}

func (nodeCVM) lockAdmission() func() {
	return func() {}
}

func (nodeCVM) refuseLapsedRuntime() error {
	return nil
}

func (nodeCVM) imageOf(_ *api.PodSandbox, ctr *api.Container) (string, error) {
	return ctr.GetAnnotations()[annotationImageName], nil
}

func (c nodeCVM) enforcerMounts() enforcerMounts {
	return enforcerMounts{
		socketDir:  c.p.cfg.WorkloadClaims.SocketDir,
		cdsPins:    c.p.cdsPins,
		cdsAddress: c.p.cdsAddress,
	}
}

func (nodeCVM) gateStart(context.Context, *api.PodSandbox, *api.Container, string) (string, error) {
	return "", nil
}

func (nodeCVM) finishStart(context.Context, *api.PodSandbox, *api.Container, string) error {
	return nil
}

func (c nodeCVM) adjustmentRole(_ *api.PodSandbox, _ *api.Container, _, declared allowlist.RunningContainer, _ []allowlist.ObservedMount) (string, error) {
	return c.p.roleOf(declared), nil
}

func (nodeCVM) admitSandbox(*api.PodSandbox) error {
	return nil
}

func (nodeCVM) admitUnprotected(*api.PodSandbox, error) error {
	return nil
}

func (nodeCVM) endIdentity(error) {}

func (nodeCVM) endIdentityForRefusal(*api.PodSandbox, error) {}

func (nodeCVM) denyCreation(*api.PodSandbox, *api.Container, error) {}

func (nodeCVM) stopAfterRestart(context.Context, []*api.PodSandbox, []*api.Container) {}

// podCVM admits only the containers of its signed assignment.
type podCVM struct {
	p *plugin
}

func (c podCVM) lockAdmission() func() {
	c.p.podMu.Lock()
	return c.p.podMu.Unlock
}

// Callers hold podMu: a callback queued from the dropped NRI session grants nothing.
func (c podCVM) refuseLapsedRuntime() error {
	if c.p.podStartDisconnected.Load() {
		return errors.New("pod runtime connection ended")
	}
	return nil
}

// The CRI image-name annotation may name a mutable alias even for a pinned request.
func (c podCVM) imageOf(pod *api.PodSandbox, ctr *api.Container) (string, error) {
	assigned := c.p.cfg.Pod
	if pod.GetId() == "" || ctr.GetId() == "" || ctr.GetPodSandboxId() != pod.GetId() ||
		pod.GetNamespace() != assigned.Namespace || pod.GetName() != assigned.Name {
		return "", fmt.Errorf("container does not belong to the assigned Pod")
	}
	digest, exists := assigned.Images[ctr.GetName()]
	if !exists || !types.IsCanonicalDigest(digest) {
		return "", fmt.Errorf("container %q has no staged image pin", ctr.GetName())
	}
	return digest, nil
}

// A measured Pod workload gets no node-service exception.
func (c podCVM) enforcerMounts() enforcerMounts {
	return enforcerMounts{clientDocument: c.p.clientDocument}
}

// A start refused here records no admission history.
func (c podCVM) gateStart(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) (string, error) {
	p := c.p
	if p.measurer == nil {
		return "", errors.New("pod start requires the runtime measurement journal")
	}
	if err := p.containerd.VerifyContainerImage(ctx, ctr.GetId(), pod.GetId(), imageRef); err != nil {
		return "", fmt.Errorf("verify selected Pod image: %w", err)
	}
	mounts := p.observedMounts(pod, ctr)
	launch := p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), mounts)
	role := p.roleOf(launch)
	source, err := p.podCredentialSource(pod, ctr, role, mounts)
	if err != nil {
		return "", err
	}
	if err := p.podSecretReader(pod, ctr, role, mounts); err != nil {
		return "", err
	}
	if err := p.mesh.admit(pod, ctr, gatedContainer{
		role:         role,
		mountsPinned: p.bindsRoleMounts(launch, role),
		digest:       launch.Digest,
		argv:         launch.Argv,
	}); err != nil {
		return "", err
	}
	return source, nil
}

// The Pod endpoint's final mounts must still carry the exact private RAM volume.
func (c podCVM) adjustmentRole(pod *api.PodSandbox, ctr *api.Container, launch, _ allowlist.RunningContainer, mounts []allowlist.ObservedMount) (string, error) {
	role := c.p.roleOf(launch)
	if _, err := c.p.podCredentialSource(pod, ctr, role, mounts); err != nil {
		return "", err
	}
	if err := c.p.podSecretReader(pod, ctr, role, mounts); err != nil {
		return "", err
	}
	return role, nil
}

func (c podCVM) admitSandbox(pod *api.PodSandbox) error {
	assigned := c.p.cfg.Pod
	if pod.GetUid() == "" || pod.GetId() == "" || pod.GetName() != assigned.Name || pod.GetNamespace() != assigned.Namespace {
		return errors.New("pod sandbox does not match its assignment")
	}
	return nil
}

func (c podCVM) admitUnprotected(pod *api.PodSandbox, cause error) error {
	return c.p.denyContainer(pod.GetId(), cause)
}

func (c podCVM) endIdentity(refusal error) {
	c.p.endPodIdentity(refusal)
}

func (c podCVM) endIdentityForRefusal(pod *api.PodSandbox, refusal error) {
	_ = c.p.denyContainer(pod.GetId(), refusal)
}

func (c podCVM) denyCreation(pod *api.PodSandbox, ctr *api.Container, refusal error) {
	_ = c.p.denyContainerCreation(pod.GetId(), ctr.GetName(), refusal)
}
