package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/nri/pkg/api"
)

// admitWhileInitializing decides a container seen after NRI registration but
// before the first allowlist fetch: audit mode passes, everything else takes
// the ordinary check. The base allowlist admits ahead of the empty startup
// snapshot, so bootstrap images are admitted and nothing else is.
func (p *plugin) admitWhileInitializing(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	log := p.logger.With(
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
	)

	if cfg.Policy.Mode == ModeAudit {
		log.Warn("plugin initializing: would deny container creation (audit mode)")
		return nil
	}
	verdict, reason := p.checkContainer(ctx, cfg, pod, ctr, imageRef)
	if verdict == verdictDeny {
		log.Warn("plugin initializing: denying container creation", "denial", reason)
		return fmt.Errorf("image policy plugin initializing: %s", reason)
	}
	return nil
}

// CreateContainer supplies the socket mount and checks digest/argv early.
// Final admission is at StartContainer, where containerd reports the persisted
// OCI spec after all NRI/CDI edits.
// Nothing is added to the admission history until that final check.
func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	defer p.lockPodAdmission()()
	if err := p.refuseDisconnectedPod(); err != nil {
		return nil, nil, err
	}
	imageRef, err := p.containerImage(pod, ctr)
	if err != nil {
		return nil, nil, p.denyContainerCreation(pod.GetId(), ctr.GetName(), err)
	}
	verdict, reason := p.checkContainerPhase(ctx, p.cfg, pod, ctr, imageRef, launchPreliminary)
	if verdict == verdictDeny && p.cfg.Policy.Mode != ModeAudit {
		if !p.Ready() {
			refusal := fmt.Errorf("image policy plugin initializing: %s", reason)
			if p.cfg.podRole() {
				return nil, nil, p.denyContainerCreation(pod.GetId(), ctr.GetName(), refusal)
			}
			return nil, nil, refusal
		}
		return nil, nil, p.denyContainerCreation(pod.GetId(), ctr.GetName(), fmt.Errorf("%s", reason))
	}
	adjustment, err := p.credentialMounts(ctx, pod, ctr)
	if err != nil && p.cfg.Policy.Mode != ModeAudit {
		return nil, nil, p.denyContainerCreation(pod.GetId(), ctr.GetName(), err)
	}
	return adjustment, nil, nil
}

// StartContainer tracks the container as running ahead of its admission, so a
// KillRevoked that follows an allowlist newer than the one admitStart read
// still sees it. A refused start never runs and leaves the running set.
func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.running.add(pod, ctr)
	if err := p.admitStart(ctx, pod, ctr); err != nil {
		p.running.remove(ctr.GetId())
		return err
	}
	return nil
}

// admitStart runs before task.Start/execve. Its environment is the final
// persisted OCI spec, unlike CreateContainer (or adjustment validation), which
// precedes other plugins and runtime CDI injection. Start updates cannot edit
// argv/env. Failed checks leave no admitted-container evidence.
func (p *plugin) admitStart(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	defer p.lockPodAdmission()()
	if err := p.refuseDisconnectedPod(); err != nil {
		return err
	}
	delete(p.podStarts, ctr.GetId())
	ctx = withResolved(ctx)
	cfg := p.cfg
	imageRef, err := p.containerImage(pod, ctr)
	if err != nil {
		return p.denyContainer(pod.GetId(), err)
	}
	var credentialSource string
	if cfg.podRole() {
		if p.measurer == nil {
			return p.denyContainer(pod.GetId(), errors.New("pod start requires the runtime measurement journal"))
		}
		if err := p.containerd.VerifyContainerImage(ctx, ctr.GetId(), pod.GetId(), imageRef); err != nil {
			return p.denyContainer(pod.GetId(), fmt.Errorf("verify selected Pod image: %w", err))
		}
		mounts := p.observedMounts(pod, ctr)
		launch := p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), mounts)
		role := p.roleOf(launch)
		var err error
		credentialSource, err = p.podCredentialSource(pod, ctr, role, mounts)
		if err == nil {
			err = p.podSecretReader(pod, ctr, role, mounts)
		}
		if err == nil {
			err = p.mesh.admit(pod, ctr, gatedContainer{role: role, mountsPinned: p.bindsRoleMounts(launch, role), digest: launch.Digest, argv: launch.Argv})
		}
		if err != nil {
			return p.denyContainer(pod.GetId(), err)
		}
	}
	if err := p.admitContainer(ctx, cfg, pod, ctr, imageRef); err != nil {
		return err
	}
	if err := p.measureStarted(ctx, imageRef); err != nil {
		return p.transientRefusal(pod, err)
	}
	unlock := p.mesh.lockStarts(pod)
	defer unlock()
	if err := p.bindExits(ctx, pod, ctr, imageRef); err != nil {
		return p.denyContainer(pod.GetId(), fmt.Errorf("mesh gate: container %s of pod %s/%s: %w", ctr.GetName(), pod.GetNamespace(), pod.GetName(), err))
	}
	// INVARIANT: recorded whether or not the first pull has settled; an
	// unresolved digest closes the sandbox's inventory answer for its life.
	p.noteMeshStarted(ctx, pod, ctr, imageRef)
	p.recordForInventory(ctx, pod, ctr, imageRef)
	return p.finishPodStart(ctx, pod, ctr, credentialSource)
}

// admitContainer refuses a start the image policy denies.
func (p *plugin) admitContainer(
	ctx context.Context,
	cfg *config,
	pod *api.PodSandbox,
	ctr *api.Container,
	imageRef string,
) error {
	if !p.Ready() {
		if err := p.admitWhileInitializing(ctx, cfg, pod, ctr, imageRef); err != nil {
			return p.transientRefusal(pod, err)
		}
		return nil
	}
	verdict, reason := p.checkContainer(ctx, cfg, pod, ctr, imageRef)
	if verdict == verdictDeny && cfg.Policy.Mode != ModeAudit {
		return p.denyContainer(pod.GetId(), fmt.Errorf("%s", reason))
	}
	return nil
}

// transientRefusal returns a start refusal a node does not record, so a
// container retried once the plugin is ready or the journal settles is not
// held against its sandbox; a pod CVM records it, since every refusal there
// ends the pod's identity (denyContainer).
func (p *plugin) transientRefusal(pod *api.PodSandbox, refusal error) error {
	if p.cfg.podRole() {
		return p.denyContainer(pod.GetId(), refusal)
	}
	return refusal
}

// noteMeshStarted tells the gate a pod's mesh endpoint is running, the start
// the rest of the pod waits on.
func (p *plugin) noteMeshStarted(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) {
	if !p.mesh.hosts(pod) {
		return
	}
	launch := p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), p.observedMounts(pod, ctr))
	if p.roleOf(launch) == meshRole {
		p.mesh.noteMeshStarted(pod.GetId())
	}
}
