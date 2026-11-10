package nriimagepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// imageVerdict is the result of checking an image against the allowlist.
type imageVerdict int

const (
	verdictAllow imageVerdict = iota
	verdictDeny
	verdictSkip // no admission check applied (missing image annotation)
)

// evaluateRule checks whether a pod satisfies a compiled Kubernetes selector.
// Returns true if the pod satisfies the rule (i.e. should be allowed).
func evaluateRule(rule labelRule, podLabels map[string]string) bool {
	if rule.selector == nil {
		return false
	}
	return rule.selector.Matches(labels.Set(podLabels))
}

// checkLabels evaluates all label rules against a pod's labels.
// Returns verdictDeny if any rule is violated, or verdictAllow if all rules pass.
func (p *plugin) checkLabels(cfg *config, namespace, podName, containerName string, podLabels map[string]string) (imageVerdict, string) {
	for _, rule := range cfg.Policy.LabelRules {
		if !evaluateRule(rule, podLabels) {
			reason := fmt.Sprintf("label rule %q denied workload", rule.Name)
			p.logger.Warn("label rule violated",
				"rule", rule.Name,
				"namespace", namespace,
				"pod", podName,
				"container", containerName,
			)
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "label_rule",
				Rule:      rule.Name,
				Namespace: namespace,
				Pod:       podName,
				Container: containerName,
			})
			return verdictDeny, reason
		}
	}
	return verdictAllow, ""
}

// imageCheck contains the container identity and observed launch specification.
// Argv is the effective OCI process.args; nil Mounts means unobserved mounts.
type imageCheck struct {
	Namespace string
	PodName   string
	Container string
	ImageRef  string
	Argv      []string
	Env       *allowlist.EnvObservation
	// EnvErr says why Env is unavailable, when the OCI environment itself is
	// the cause. It names at most a variable, never a value.
	EnvErr error
	Mounts []allowlist.ObservedMount
}

type launchPhase uint8

const (
	launchPreliminary launchPhase = iota
	launchFinal
)

// keepsTag reports whether a container may run an image by tag: the base's,
// as the node's manifests name carried images by tag, or a mesh-exempt
// namespace's, whose pods get no workload traffic. A worker keeps none.
func (p *plugin) keepsTag(cfg *config, baseAdmitted bool, namespace string) bool {
	if cfg.Worker {
		return false
	}
	return baseAdmitted || p.mesh.policy.exempts(namespace)
}

// checkImagePhase checks the image and observed launch specification against
// the base and served allowlists for the requested admission phase.
func (p *plugin) checkImagePhase(ctx context.Context, cfg *config, check imageCheck, phase launchPhase) (imageVerdict, string) {
	log := p.logger.With(
		"namespace", check.Namespace,
		"pod", check.PodName,
		"container", check.Container,
		"image", check.ImageRef,
	)
	decide := imageDecision{audit: p.audit, check: check}

	// A missing annotation means the kubelet was bypassed.
	if check.ImageRef == "" {
		if cfg.Policy.DenyMissingAnnotation {
			log.Warn("no image reference found in annotations, denying")
			return decide.deny("no_image_annotation", "container has no image annotation")
		}
		log.Warn("no image reference found in annotations, allowing (deny_missing_annotation disabled)")
		return decide.skip("no_image_annotation")
	}

	digest := extractDigest(check.ImageRef)
	pinned := digest != ""
	if !pinned {
		resolved, err := p.resolve(ctx, check.ImageRef)
		if err != nil {
			log.Warn("cannot resolve image digest via containerd", "error", err)
			return decide.denyUnresolvedDigest(err)
		}
		digest = resolved
		log.Debug("resolved tag to digest via containerd", "digest", digest)
	}

	snap := p.policy.current()
	if snap == nil || snap.index == nil {
		log.Error("no allowlist loaded; denying")
		unavailable := fmt.Sprintf("no allowlist available for %s", check.ImageRef)
		return decide.deny("no_allowlist_available", unavailable)
	}

	// The base allowlist admits what its entries admit. Served entries are
	// matched against the final OCI argv, environment, and classified mounts.
	rc := allowlist.RunningContainer{Digest: digest, Argv: check.Argv, Env: check.Env, Mounts: check.Mounts}
	baseAdmitted := p.policy.baseAdmits(rc, phase)

	// A tag is resolved here, at hook time, while the runtime builds the
	// rootfs from the image kubelet resolved earlier; a tag moved in between
	// would let this check judge one image and the container run another.
	if !pinned && !p.keepsTag(cfg, baseAdmitted, check.Namespace) {
		log.Warn("image not referenced by digest", "digest", digest)
		unpinned := fmt.Sprintf("image must be referenced by digest (name@sha256:...): %s", check.ImageRef)
		return decide.deny("not_digest_pinned", unpinned)
	}

	servedAdmitted := snap.admits(rc, phase)
	if !baseAdmitted && !servedAdmitted {
		reason, denial := launchDenial(snap.index, check, rc, phase)
		log.Warn("image not admitted by allowlist", p.denialAttrs(check, rc, reason)...)
		return decide.deny(reason, denial)
	}

	log.Info("image allowed")
	return decide.allow("verified")
}

// Pairs each verdict with the audit event that records it.
type imageDecision struct {
	audit *audit.Logger
	check imageCheck
}

func (d imageDecision) deny(reason, message string) (imageVerdict, string) {
	d.audit.Log(d.event("deny", reason))
	return verdictDeny, message
}

func (d imageDecision) denyUnresolvedDigest(err error) (imageVerdict, string) {
	event := d.event("deny", "resolve_failed")
	event.Error = err.Error()
	d.audit.Log(event)
	return verdictDeny, fmt.Sprintf("cannot resolve digest for %s: %v", d.check.ImageRef, err)
}

// A skipped check is audited as an allow: no rule admitted the container, none denied it.
func (d imageDecision) skip(reason string) (imageVerdict, string) {
	d.audit.Log(d.event("allow", reason))
	return verdictSkip, ""
}

func (d imageDecision) allow(reason string) (imageVerdict, string) {
	d.audit.Log(d.event("allow", reason))
	return verdictAllow, ""
}

func (d imageDecision) event(action, reason string) audit.Event {
	return audit.Event{
		Action:    action,
		Reason:    reason,
		Namespace: d.check.Namespace,
		Pod:       d.check.PodName,
		Container: d.check.Container,
		Image:     d.check.ImageRef,
	}
}

// launchDenial separates an image no entry lists from one whose launch
// specification satisfies no entry listing it.
//
// INVARIANT: the denial reaches a namespace-readable kubelet event, so it names
// the image, policy fields and at most a variable name — argv and env values
// can carry credentials and stay out of it.
func launchDenial(
	index *allowlist.Index,
	check imageCheck,
	rc allowlist.RunningContainer,
	phase launchPhase,
) (reason, denial string) {
	if !index.AdmitsDigest(rc.Digest) {
		return "not_in_allowlist", fmt.Sprintf("image not in allowlist: %s", check.ImageRef)
	}
	denial = fmt.Sprintf("image %s is allowlisted, but its launch specification satisfies no workload entry's command, args, env or mounts policy", check.ImageRef)
	if fields := index.Mismatch(rc, phase == launchFinal); len(fields) > 0 {
		denial += "; the closest entry differs in " + strings.Join(fields, ", ")
		if check.EnvErr != nil && slices.Contains(fields, "env") {
			denial += " (" + check.EnvErr.Error() + ")"
		}
	}
	return "launch_not_admitted", denial
}

// The node-root fault is added only for an entry that declares a node-root
// mount, where it explains the refusal.
func (p *plugin) denialAttrs(check imageCheck, rc allowlist.RunningContainer, reason string) []any {
	attrs := []any{"digest", rc.Digest, "image", check.ImageRef, "argv_sha256", argvDigest(rc.Argv), "reason", reason}
	if missing := nodeRootMissing(rc.Mounts); missing != "" && p.policy.declaresNodeRoot(rc.Digest) {
		attrs = append(attrs, "node_root_unavailable", missing)
	}
	return attrs
}

// argvDigest identifies an argv in the node's journal without its values,
// which can carry credentials.
func argvDigest(argv []string) string {
	sum := sha256.Sum256([]byte(strings.Join(argv, "\x00")))
	return hex.EncodeToString(sum[:])
}

// checkContainer runs the label rules and the image allowlist over a
// container. Only the image digest (answered by the containerd content
// store) admits; label rules can only deny.
//
// A denial in an exempt namespace is downgraded to skip only when that
// namespace's exempt set names the container's image repository.
func (p *plugin) checkContainer(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string) (imageVerdict, string) {
	return p.checkContainerPhase(ctx, cfg, pod, ctr, imageRef, launchFinal)
}

// checkContainerPhase adds the sandbox policy to the final phase. That policy
// reads the whole container spec — mounts, devices, hooks — so it only makes
// sense on the spec containerd persisted: CreateContainer precedes the other
// plugins' adjustments, and the adjustment validator sees those edits applied
// to a clone's env, argv and mounts alone (env.go, adjustedLaunchContainer).
//
// A sandbox denial is never downgraded by exemptNamespace: host privilege is a
// property of the pod spec. Only the measured node TCB excuses it, and it
// excuses neither a host port nor a capability (hostports.go,
// capabilities.go).
func (p *plugin) checkContainerPhase(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, phase launchPhase) (imageVerdict, string) {
	var mounts []allowlist.ObservedMount
	if phase == launchFinal {
		mounts = p.observedMounts(pod, ctr)
	}
	env := containerEnv(ctr)
	verdict, reason := p.checkContainerObserved(ctx, cfg, pod, ctr, imageRef, phase, env, mounts)
	if verdict == verdictDeny || !sandboxPolicyApplies(cfg, phase) {
		return verdict, reason
	}
	if v, r := p.checkSandbox(ctx, cfg, pod, ctr, imageRef, env, mounts); v == verdictDeny {
		return v, r
	}
	if refusal := p.hostPortRefusal(ctx, cfg, pod, ctr, imageRef, env, mounts); refusal != "" {
		return verdictDeny, refusal
	}
	if refusal := p.capabilityRefusal(ctx, cfg, pod, ctr, imageRef, env, mounts); refusal != "" {
		return verdictDeny, refusal
	}
	return verdict, reason
}

// sandboxPolicyApplies reports whether the host-privilege rules run: they read
// the persisted container spec, which only the final phase has.
func sandboxPolicyApplies(cfg *config, phase launchPhase) bool {
	return phase == launchFinal && cfg.sandboxObserved()
}

func (p *plugin) checkContainerObserved(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, phase launchPhase, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) (imageVerdict, string) {
	namespace, podName, ctrName := pod.GetNamespace(), pod.GetName(), ctr.GetName()

	verdict, reason := p.checkLabels(cfg, namespace, podName, ctrName, pod.GetLabels())
	if verdict != verdictDeny && cfg.AllowlistEnabled() {
		verdict, reason = p.checkImagePhase(ctx, cfg, imageCheck{
			Namespace: namespace,
			PodName:   podName,
			Container: ctrName,
			ImageRef:  imageRef,
			Argv:      ctr.GetArgs(),
			Env:       env,
			EnvErr:    envError(ctr, env),
			Mounts:    mounts,
		}, phase)
	}
	return p.exemptNamespace(cfg, pod, ctr, imageRef, verdict, reason)
}

// Runs last and only downgrades, keyed on the image's repository.
func (p *plugin) exemptNamespace(cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, verdict imageVerdict, reason string) (imageVerdict, string) {
	namespace, podName, ctrName := pod.GetNamespace(), pod.GetName(), ctr.GetName()
	if verdict != verdictDeny || !slices.Contains(cfg.Policy.ExemptNamespaces, namespace) {
		return verdict, reason
	}

	if cfg.Policy.ExemptRepositories.Admits(namespace, imageRef) {
		p.logger.Info("exempt namespace: admitting a container whose image repository the namespace's exempt set names",
			"namespace", namespace, "pod", podName, "container", ctrName, "image", imageRef, "denial", reason)
		p.audit.Log(audit.Event{
			Action:    "allow",
			Reason:    "namespace_exempt",
			Overrides: reason,
			Namespace: namespace,
			Pod:       podName,
			Container: ctrName,
			Image:     imageRef,
		})
		return verdictSkip, ""
	}
	// Outside the set: denied, never killed (checkExisting), audited as drift.
	p.audit.Log(audit.Event{
		Action:    "deny",
		Reason:    "exempt_repository_miss",
		Namespace: namespace,
		Pod:       podName,
		Container: ctrName,
		Image:     imageRef,
	})
	return verdict, reason
}

// checkSandbox applies the fixed host-privilege policy: a container may not
// hold a host namespace, a host bind mount, a device, a CDI injection, an OCI
// hook or the marks of a privileged container. The allowlist bounds which bytes
// run; this bounds what those bytes are handed.
//
// Two exemptions apply. The first is the node TCB: only the MEASURED base
// allowlist, and only when the node config claims it as the node TCB
// (allowlist.node_tcb). A CDS-served entry never is, because the cluster admin
// this policy defends against authors that document. The control plane picks
// the image a pod runs, so a base digest alone proves nothing about the launch;
// nodeTCBExempt says how much a base entry excuses. See
// docs/allowlist-and-capabilities.md.
//
// The second sets aside a single bind, not the container: one an entry of the
// base or the served allowlist grants this launch (allowlist.Index.GrantsHostBind).
//
// The digest is resolved only when an exemption could apply, so an ordinary
// container costs no containerd round-trip.
func (p *plugin) checkSandbox(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) (imageVerdict, string) {
	cdi, err := expandCDI(ctr, p.cdiSpecDirs)
	if err != nil {
		p.logger.Warn("cannot expand the container's CDI devices; their edits count as host privilege",
			"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "error", err)
	}
	own := p.nodeMounts()
	obs := observeSandbox(pod, ctr, own, mounts, noBindGrant{}, cdi)
	violations := obs.violations(cfg.podRole())
	if len(violations) == 0 {
		return verdictAllow, ""
	}
	digest := ""
	if cfg.AllowlistEnabled() && len(obs.HostBinds) > 0 {
		digest = p.resolveDigest(ctx, imageRef)
		rc := allowlist.RunningContainer{Digest: digest, Argv: ctr.GetArgs(), Env: env, Mounts: mounts}
		obs.HostBinds = hostBinds(pod, ctr, own, mounts, declaredBindGrant{policy: p.policy, launch: rc}, cdi)
		if violations = obs.violations(cfg.podRole()); len(violations) == 0 {
			return verdictAllow, ""
		}
	}
	if cfg.Allowlist.NodeTCB {
		if digest == "" {
			digest = p.resolveDigest(ctx, imageRef)
		}
		rc := allowlist.RunningContainer{Digest: digest, Argv: ctr.GetArgs(), Env: env, Mounts: mounts}
		if p.nodeTCBExempt(pod, rc) {
			return verdictAllow, ""
		}
	}

	namespace, podName, ctrName := pod.GetNamespace(), pod.GetName(), ctr.GetName()
	// INVARIANT: the log carries the whole observation so a reviewer can write
	// the missing node-TCB rule from it; the returned reason reaches a
	// namespace-readable kubelet event and names only the violated rules, which
	// are the pod's own spec.
	p.logger.Warn("container holds host privilege outside the node TCB",
		append([]any{
			"namespace", namespace, "pod", podName, "container", ctrName,
			"image", imageRef, "digest", digest,
			"violations", violations, "sandbox", cfg.sandboxMode(),
		}, obs.logAttrs()...)...)
	if cfg.sandboxMode() == SandboxAudit {
		p.audit.Log(audit.Event{
			Action:    "allow",
			Reason:    "sandbox_audit",
			Overrides: strings.Join(violations, ", "),
			Namespace: namespace,
			Pod:       podName,
			Container: ctrName,
			Image:     imageRef,
		})
		return verdictAllow, ""
	}
	p.audit.Log(audit.Event{
		Action:    "deny",
		Reason:    "sandbox_violation",
		Rule:      strings.Join(violations, ", "),
		Namespace: namespace,
		Pod:       podName,
		Container: ctrName,
		Image:     imageRef,
	})
	return verdictDeny, fmt.Sprintf("container is not part of the node TCB and requests host privilege: %s", strings.Join(violations, ", "))
}
