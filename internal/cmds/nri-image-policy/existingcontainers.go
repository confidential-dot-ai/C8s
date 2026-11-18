package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// shouldCheckExisting reports whether the startup check has work — enforcement,
// inventory recovery, or both. See docs/getcert-workload-binding.md, Corner 4.
func (p *plugin) shouldCheckExisting() bool {
	return p.cfg.Policy.EnforceExisting || p.inventory != nil
}

// Synchronize is called when the plugin connects to containerd. It records every
// existing container, checks what it can, and kills violations when
// enforce_existing is set.
func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	defer p.cvm().lockAdmission()()
	clear(p.podStarts)
	cfg := p.cfg
	if err := p.cvm().refuseLapsedRuntime(); err != nil {
		return nil, err
	}
	// Seed the inventory's sandbox set now, even when the container check is
	// deferred: sandbox existence needs no allowlist.
	if p.inventory != nil {
		for _, pod := range pods {
			p.inventory.recordSandbox(pod.GetId())
		}
		p.inventory.awaitRecovery()
	}

	// Ahead of every other decision: on a node image a container that already
	// exists means admission was not in place when it started The
	// call does not return when that is what happened. A Pod guest keeps no
	// admission history across a plugin restart, so a restart within one boot
	// ends the Pod identity and stops the Pod's containers. Its runtime starts
	// only once the pod is assigned, so the first registration is the assigned
	// one and no restart is expected before the pod runs.
	if p.boot.check(ctx, p, pods, ctrs) {
		p.bootRestart.Store(true)
		p.endPodIdentity(errors.New("pod inventory was reconstructed after a plugin restart"))
		p.cvm().stopAfterRestart(ctx, pods, ctrs)
	}

	freshRegistration := !p.bootRestart.Load()
	if err := p.cvm().admitRegistration(pods, ctrs, freshRegistration); err != nil {
		return nil, err
	}
	p.trackRunning(pods, ctrs)
	p.cvm().noteRegistration(freshRegistration)

	// If not ready yet, defer recovery and the startup check until CDS init
	// completes: recovery needs the served allowlist to decide exits. Ready is
	// read under deferredMu so RunDeferredCheck cannot run between it and the
	// store and leave the batch unhandled.
	p.deferredMu.Lock()
	if !p.Ready() {
		p.deferredPods = pods
		p.deferredCtrs = ctrs
		p.deferredMu.Unlock()
		p.logger.Info("plugin not ready, deferring recovery and the startup check",
			"pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}
	p.deferredMu.Unlock()

	p.recoverExisting(ctx, pods, ctrs)
	// Recovery has run: a container create from here finds its pod on record or
	// is refused for its sandbox's life, no longer transiently.
	p.mesh.noteRecovered()

	if !p.shouldCheckExisting() {
		p.logger.Info("startup check disabled", "pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}

	p.checkExisting(ctx, cfg, pods, ctrs)
	return nil, nil
}

// podsByID indexes the sandboxes the runtime reported by their sandbox ID, so
// a container can be matched to its pod by GetPodSandboxId.
func podsByID(pods []*api.PodSandbox) map[string]*api.PodSandbox {
	byID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		byID[pod.GetId()] = pod
	}
	return byID
}

// trackRunning adds every running container whose pod sandbox the runtime
// reported at registration to the running set: the containers the startup check
// can judge.
func (p *plugin) trackRunning(pods []*api.PodSandbox, ctrs []*api.Container) {
	podByID := podsByID(pods)
	for _, ctr := range ctrs {
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil || ctr.GetState() != api.ContainerState_CONTAINER_RUNNING {
			continue
		}
		p.running.add(pod, ctr)
	}
}

// recoverExisting rebuilds the node-service count and takes every sandbox
// running when this enforcer connected back under the mesh gate, or refuses it
// for its life.
func (p *plugin) recoverExisting(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) {
	p.recountNodeServices(ctx, pods, ctrs)
	podByID := podsByID(pods)
	bySandbox := map[string][]recoveredContainer{}
	workloads := map[string][]workloadclaims.SandboxContainer{}
	for _, ctr := range ctrs {
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil || !p.mesh.hosts(pod) {
			continue
		}
		launch := p.observedLaunch(ctx, p.observeContainer(pod, ctr, ctr.GetAnnotations()[annotationImageName]))
		role := p.roleOf(launch)
		// Liveness is the running set, not the registration snapshot: a container
		// that started in the deferral window is not CONTAINER_RUNNING in the
		// snapshot but is on the running set, and its mesh endpoint opened the
		// gate, so recovery must see it as started.
		running := p.running.contains(ctr.GetId())
		bySandbox[pod.GetId()] = append(bySandbox[pod.GetId()], recoveredContainer{
			ctr: ctr,
			launch: gatedContainer{
				role:         role,
				mountsPinned: p.bindsRoleMounts(launch, role),
				digest:       launch.Digest,
				argv:         launch.Argv,
			},
			running: running,
		})
		// A container that never ran was never counted by admission. One that ran
		// counts whether it is still running or has since stopped, so the snapshot
		// state and the running set together decide it.
		if ctr.GetState() != api.ContainerState_CONTAINER_CREATED || running {
			workloads[pod.GetId()] = append(workloads[pod.GetId()], p.sandboxContainer(launch))
			p.rejoinComponentSet(pod.GetId(), launch, role)
		}
	}
	for _, pod := range pods {
		if !p.mesh.hosts(pod) {
			continue
		}
		exits := p.recoveredExits(workloads[pod.GetId()])
		switch err := p.mesh.recoverPod(pod, bySandbox[pod.GetId()], exits); {
		case err == nil, errors.Is(err, errSandboxAlreadyOnRecord):
			// Already on record means protect() took the pod first; it is
			// protected, so this is not a failure to recover.
		default:
			p.removePodWithoutIdentity(pod, err)
		}
	}
}

// reportUnprotected names a pod whose sandbox the gate refused: a pod whose
// recovery this process refused gets no identity until it is deleted, any
// other failure refuses this sandbox's containers.
func (p *plugin) reportUnprotected(pod *api.PodSandbox, refusal error) {
	if errors.Is(refusal, errRecoveryRefusedPod) {
		p.removePodWithoutIdentity(pod, refusal)
		return
	}
	p.logger.Error("cannot protect a pod; every container of it will be refused",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"error", refusal)
}

// The delete runs off this NRI callback, which containerd allows two seconds.
func (p *plugin) removePodWithoutIdentity(pod *api.PodSandbox, refusal error) {
	if !p.holdsNodeIdentity() {
		p.logPodWithoutIdentity(pod, refusal)
		return
	}
	p.logger.Warn("a pod running before this enforcer connected gets no identity; deleting it so a replacement can get one",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"pod_uid", pod.GetUid(),
		"error", refusal)
	go func() {
		if err := p.deletePod(context.Background(), pod); !refusedPodGone(err) {
			p.logUndeletedPod(pod, err)
		}
	}()
}

// Only a node enforcer is given this node's delete (newPlugin).
func (p *plugin) holdsNodeIdentity() bool {
	return p.deletePod != nil
}

// logPodWithoutIdentity names the pod an operator deletes to let it get an
// identity.
func (p *plugin) logPodWithoutIdentity(pod *api.PodSandbox, refusal error) {
	p.logger.Warn("a pod running before this enforcer connected gets no identity; delete the pod to give it one",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"pod_uid", pod.GetUid(),
		"error", refusal)
}

func (p *plugin) logUndeletedPod(pod *api.PodSandbox, failure error) {
	p.logger.Error("cannot delete a pod this enforcer refused; delete it to let a replacement get an identity",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"pod_uid", pod.GetUid(),
		"error", failure)
}

// recoveredExits reads back the exit grant a running sandbox holds. An
// undecided or refused match grants none and carries the cause.
func (p *plugin) recoveredExits(containers []workloadclaims.SandboxContainer) recoveredExits {
	decision := p.recoveredExitDecision(containers)
	if decision.undecided != nil {
		return recoveredExits{cause: decision.undecided}
	}
	if decision.refusal != nil {
		return recoveredExits{cause: decision.refusal}
	}
	return recoveredExits{entry: decision.entry, exits: decision.exits}
}

// checkExisting records every container it is handed, checks the ones whose pod
// sandbox it was also handed, and kills violations when enforce_existing is set.
func (p *plugin) checkExisting(ctx context.Context, cfg *config, pods []*api.PodSandbox, ctrs []*api.Container) {
	p.logger.Info("checking existing containers",
		"pods", len(pods), "containers", len(ctrs), "enforcing", cfg.Policy.EnforceExisting)

	podByID := podsByID(pods)

	if p.inventory != nil {
		defer p.inventory.recovered()
	}
	var killed, failed int
	for _, ctr := range ctrs {
		imageRef := ctr.GetAnnotations()[annotationImageName]
		pod := podByID[ctr.GetPodSandboxId()]
		p.cvm().recordExisting(ctx, pod, ctr, imageRef)
		if pod == nil {
			continue
		}
		verdict, denial := p.cvm().admitExisting(ctx, pod, ctr, imageRef)
		if verdict != verdictDeny {
			continue
		}
		// Never killed: stopping a platform container (kube-proxy, CoreDNS) can
		// cut the node. An unnamed repository is denied at the next create.
		if cfg.isExemptNamespace(pod.GetNamespace()) {
			p.logger.Warn("exempt namespace: leaving a running container whose image repository the namespace's exempt set does not name",
				"namespace", pod.GetNamespace(), "container", ctr.GetName())
			continue
		}
		// enforce_existing off: the check only feeds the inventory. A node
		// following a replica set's chain that has applied no CDS allowlist
		// yet holds only its base allowlist, which lacks what the CDS admitted
		// after an upgrade to a build its launch pins do not name: the first
		// applied allowlist rechecks the running containers (KillRevoked).
		if !cfg.allowlistRevokesRunning() || (cfg.Allowlist.Pull.CDSChain != "" && p.AppliedAllowlistVersion() == 0) {
			continue
		}
		// A restart of the gated plugin found a running container the current
		// allowlist does not admit. It has already run, so stopping it proves
		// nothing about what it did. Does not return.
		if p.escalateOnRestart() {
			p.boot.fatalExisting(pod, ctr)
		}
		if p.killRunning(ctx, pod, ctr, denial) {
			killed++
		} else {
			failed++
		}
	}

	p.logger.Info("existing-container check complete",
		"killed", killed, "failed", failed, "checked", len(ctrs), "enforcing", cfg.Policy.EnforceExisting)
}

// KillRevoked rechecks every running container against the allowlist just
// applied, and kills the ones it no longer admits under the same rules as the
// startup check, short of the boot gate's escalation.
func (p *plugin) KillRevoked(ctx context.Context) {
	cfg := p.cfg
	if !cfg.allowlistRevokesRunning() {
		return
	}
	running := p.running.list()
	var killed, failed int
	for _, c := range running {
		if cfg.isExemptNamespace(c.pod.GetNamespace()) {
			continue
		}
		denial, denied := p.deniedNow(ctx, c)
		if !denied {
			continue
		}
		p.cvm().endIdentityForRefusal(c.pod, errors.New(denial))
		if p.killRunning(ctx, c.pod, c.ctr, denial) {
			killed++
		} else {
			failed++
		}
	}
	p.logger.Info("rechecked running containers against the applied allowlist",
		"version", p.AppliedAllowlistVersion(), "killed", killed, "failed", failed, "checked", len(running))
}

// deniedNow is the denial the policy in force gives a running container, and
// whether it denies it at all. The same image admission matched: on a Pod
// guest the staged pin, not an alias the CRI annotation may have moved since.
func (p *plugin) deniedNow(ctx context.Context, c runningContainer) (string, bool) {
	imageRef, err := p.cvm().imageOf(c.pod, c.ctr)
	if err != nil {
		return err.Error(), true
	}
	verdict, denial := p.checkContainer(ctx, p.cfg, c.pod, c.ctr, imageRef)
	return denial, verdict == verdictDeny
}

// recheckRunning applies the policy just put in force to what already runs:
// the whole of every pod whose component sets have ended, the whole of every
// pod the served allowlist admitted once this node has fallen back to its
// base, then every single container the policy no longer admits.
func (p *plugin) recheckRunning(ctx context.Context) {
	p.endPodsOnEndedSets(ctx)
	p.endPodsOffTheBase(ctx)
	p.KillRevoked(ctx)
}

// endPodsOffTheBase ends, while this node runs on its base allowlist alone,
// every pod with a container the base does not admit: the pods the served
// allowlist admitted. They go whole, as a pod off its component sets does.
func (p *plugin) endPodsOffTheBase(ctx context.Context) {
	if !p.cfg.allowlistRevokesRunning() || !p.policy.freshness.fellBackToBase() {
		return
	}
	cause := errors.New("this node runs on its base allowlist alone: it has had no allowlist of the CDS's within one certificate lifetime")
	for _, ended := range p.podsDeniedNow(ctx, cause) {
		p.endPod(ctx, ended)
	}
}

// podsDeniedNow are the pods running here with a container the policy in
// force no longer admits, outside the exempt namespaces.
func (p *plugin) podsDeniedNow(ctx context.Context, cause error) []endedPod {
	var ended []endedPod
	for _, running := range p.runningPods() {
		if p.cfg.isExemptNamespace(running[0].pod.GetNamespace()) {
			continue
		}
		pod := endedPod{pod: running[0].pod, cause: cause}
		denied := false
		for _, c := range running {
			pod.ctrs = append(pod.ctrs, c.ctr)
			if _, refused := p.deniedNow(ctx, c); refused {
				denied = true
			}
		}
		if denied {
			ended = append(ended, pod)
		}
	}
	return ended
}

// endPodsOnEndedSets stops every container of each pod whose component sets
// have all ended and has the Pod deleted, so its controller replaces it on a
// set in force. KillRevoked stops a single container the policy no longer
// admits; a pod off its sets goes whole, because a main container left without
// its sidecars is cut off from the mesh and still holds its secrets.
func (p *plugin) endPodsOnEndedSets(ctx context.Context) {
	if !p.cfg.allowlistRevokesRunning() {
		return
	}
	for _, ended := range p.podsOffTheirSets() {
		p.endPod(ctx, ended)
	}
}

// endedPod is a pod this node ends whole, with the containers of it that
// still run and the cause its Pod is deleted for.
type endedPod struct {
	pod   *api.PodSandbox
	ctrs  []*api.Container
	cause error
}

// podsOffTheirSets are the pods running here whose membership holds no
// component set the applied document still has in force.
func (p *plugin) podsOffTheirSets() []endedPod {
	inForce := p.policy.setsInForce()
	var ended []endedPod
	for sandboxID, running := range p.runningPods() {
		sets, off := p.componentSets.offSetsInForce(sandboxID, inForce)
		if !off {
			continue
		}
		pod := endedPod{
			pod:   running[0].pod,
			cause: fmt.Errorf("this pod runs on no component set in force; it is on %s", setVersions(sets)),
		}
		for _, c := range running {
			pod.ctrs = append(pod.ctrs, c.ctr)
		}
		ended = append(ended, pod)
	}
	return ended
}

// runningPods groups what runs on this node by the sandbox it runs in.
func (p *plugin) runningPods() map[string][]runningContainer {
	byPod := map[string][]runningContainer{}
	for _, c := range p.running.list() {
		byPod[c.pod.GetId()] = append(byPod[c.pod.GetId()], c)
	}
	return byPod
}

// endPod stops the pod's containers and has the Pod deleted. A container
// leaves the running set once its kill is delivered; one whose kill failed
// stays on it, for the next recheck.
func (p *plugin) endPod(ctx context.Context, ended endedPod) {
	p.logger.Warn("ending a whole pod",
		"namespace", ended.pod.GetNamespace(),
		"pod", ended.pod.GetName(),
		"containers", len(ended.ctrs),
		"cause", ended.cause)
	p.cvm().endIdentityForRefusal(ended.pod, ended.cause)
	for _, ctr := range ended.ctrs {
		if p.killRunning(ctx, ended.pod, ctr, ended.cause.Error()) {
			p.running.remove(ctr.GetId())
		}
	}
	p.deleteEndedPod(ended.pod, ended.cause)
}

// The delete runs off the pull loop, which keeps polling while the API server
// answers.
func (p *plugin) deleteEndedPod(pod *api.PodSandbox, cause error) {
	if !p.holdsNodeIdentity() {
		p.logger.Warn("a pod this node ended keeps its Pod object; delete the pod to let a replacement run",
			"namespace", pod.GetNamespace(),
			"pod", pod.GetName(),
			"pod_uid", pod.GetUid(),
			"error", cause)
		return
	}
	go func() {
		if err := p.deletePod(context.Background(), pod); !refusedPodGone(err) {
			p.logger.Error("cannot delete a pod this node ended; delete the pod to let a replacement run",
				"namespace", pod.GetNamespace(),
				"pod", pod.GetName(),
				"pod_uid", pod.GetUid(),
				"error", err)
		}
	}()
}

// killRunning kills the task of a running container the checks denied for
// denial, and reports whether the kill was delivered.
func (p *plugin) killRunning(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, denial string) bool {
	log := p.logger.With("namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "denial", denial)
	if err := p.containerd.StopContainer(ctx, ctr.GetId()); err != nil {
		log.Error("failed to kill a denied running container", "error", err)
		return false
	}
	log.Warn("killed a denied running container")
	return true
}

// stopAfterRestart stops every running container a plugin restart found on a
// Pod guest. The identity has ended, so no start of the Pod is admitted again;
// stopping what already runs lets the kubelet report the Pod's containers
// terminated instead of leaving a Pod that runs but can never renew its
// credentials. Failures are logged: a container that stays up is still refused
// every later start and issuance.
func (c podCVM) stopAfterRestart(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) {
	p := c.p
	podByID := podsByID(pods)
	for _, ctr := range ctrs {
		if ctr.GetState() != api.ContainerState_CONTAINER_RUNNING {
			continue
		}
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil {
			pod = &api.PodSandbox{Id: ctr.GetPodSandboxId()}
		}
		p.killRunning(ctx, pod, ctr, "pod identity ended by a plugin restart within this boot")
	}
}

// RunDeferredCheck recovers and checks the pods/containers that were seen
// during Synchronize before the plugin was ready. Should be called after
// SetReady and CDS init.
func (p *plugin) RunDeferredCheck(ctx context.Context) {
	defer p.cvm().lockAdmission()()
	cfg := p.cfg

	p.deferredMu.Lock()
	pods := p.deferredPods
	ctrs := p.deferredCtrs
	p.deferredPods = nil
	p.deferredCtrs = nil
	p.deferredMu.Unlock()

	// Recovery runs even with the check off: a pod off the gate's record is
	// refused for its life.
	p.recoverExisting(ctx, pods, ctrs)
	// Recovery has run: a container create from here finds its pod on record or
	// is refused for its sandbox's life, no longer transiently.
	p.mesh.noteRecovered()

	if !p.shouldCheckExisting() {
		if p.inventory != nil {
			p.inventory.recovered()
		}
		return
	}

	if len(ctrs) == 0 {
		p.logger.Info("no deferred containers to check")
		if p.inventory != nil {
			p.inventory.recovered()
		}
		return
	}

	p.logger.Info("running deferred startup check", "pods", len(pods), "containers", len(ctrs))
	p.checkExisting(ctx, cfg, pods, ctrs)
}
