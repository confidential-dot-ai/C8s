package nriimagepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	pluginName = "image-policy"
	pluginIdx  = "00"

	// Kubernetes CRI annotations for image info
	annotationImageName = "io.kubernetes.cri.image-name"
)

// imageVerdict is the result of checking an image against the allowlist.
type imageVerdict int

const (
	verdictAllow imageVerdict = iota
	verdictDeny
	verdictSkip // no admission check applied (missing image annotation)
)

// policySnapshot is an immutable admission view: an Index built from the
// last-applied CDS pull, tagged with that pull's version (the ETag counter).
// Swapped as a unit; policyStore checks the base allowlist ahead of it.
type policySnapshot struct {
	index   *allowlist.Index
	version uint64
}

// policyStore holds the current admission snapshot. A single writer (the pull
// loop) swaps it via apply; CreateContainer reads it concurrently via current.
// The base allowlist is checked ahead of every snapshot, so a failed or
// withheld pull never drops it.
type policyStore struct {
	base *allowlist.Index // the boot-time base allowlist document
	snap atomic.Pointer[policySnapshot]
}

// newPolicyStore seeds the store with an empty snapshot (version 0) so admission
// enforces the base allowlist alone before the first pull lands and after any
// pull failure. A nil base admits nothing.
func newPolicyStore(base *allowlist.Allowlist) *policyStore {
	if base == nil {
		base = &allowlist.Allowlist{}
	}
	s := &policyStore{base: base.BuildIndex()}
	s.snap.Store(&policySnapshot{index: (&allowlist.Allowlist{}).BuildIndex()})
	return s
}

func (s *policyStore) current() *policySnapshot {
	if s == nil {
		return nil
	}
	return s.snap.Load()
}

// baseAdmits applies the same launch phases as the served allowlist: argv at
// preliminary admission, then all constraints once runtime evidence is available.
func (s *policyStore) baseAdmits(r allowlist.RunningContainer, phase launchPhase) bool {
	if s == nil {
		return false
	}
	if phase == launchPreliminary {
		return s.base.AdmitsProcess(r)
	}
	return s.base.AdmitsContainer(r)
}

// apply installs the pulled document at version, unless version is below the
// applied one — an epoch rollback a withheld/rolled-back CDS must not use to
// loosen a tightened policy. Reports whether it applied. Single-writer: only the
// pull loop calls it, so the read-compare-store needs no lock against other
// writers.
//
// The applied version is process-local (newPolicyStore starts at 0), so
// rollback is only rejected within a process lifetime: after a restart the first
// pull is trusted, whatever its version, and state re-syncs from CDS. Surviving a
// restart would need a monotonic counter the host cannot reset — out of scope; on
// the untrusted host a persisted file is itself host-controlled. See
// docs/allowlist-and-capabilities.md.
func (s *policyStore) apply(pulled *allowlist.Allowlist, version uint64) bool {
	if cur := s.snap.Load(); cur != nil && version < cur.version {
		return false
	}
	s.snap.Store(&policySnapshot{index: pulled.BuildIndex(), version: version})
	return true
}

// containerdOps is the containerd surface admission drives; internal/containerd's
// *Resolver satisfies it.
type containerdOps interface {
	Resolve(ctx context.Context, imageRef string) (string, error)
	StopContainer(ctx context.Context, containerID string) error
}

// plugin implements the NRI plugin interface for image policy enforcement.
type plugin struct {
	stub       stub.Stub
	cfg        *config
	policy     *policyStore
	audit      *audit.Logger
	logger     *slog.Logger
	ready      atomic.Bool
	containerd containerdOps

	// exempt admits an exempt namespace's containers by the digest set captured
	// running in it, not by the namespace name. nil ⇔ not opted in
	// (policy.exempt_namespaces empty) or not yet captured. See exempt.go.
	exempt atomic.Pointer[exemptSnapshot]

	// inventory serves the sandbox-identity flow (docs/ratls.md). nil ⇔ the flow
	// is disabled (no workload_claims.socket_dir) — configuration, not a
	// fault: Configure then leaves the inventory-feeding events unsubscribed,
	// and the nil-guarded hooks/seeding no-op rather than fail a container
	// lifecycle callback over bookkeeping.
	inventory *admissionInventory

	// boot is the boot gate: nil unless policy.fatal_existing. See
	// bootgate.go. bootRestart records that this registration is a plugin
	// restart, which makes the startup check's denials fatal.
	boot        *bootGate
	bootRestart atomic.Bool

	// Deferred check: pods/containers observed during Synchronize before
	// the plugin is ready, replayed once the cache has a allowlist.
	deferredMu   sync.Mutex
	deferredPods []*api.PodSandbox
	deferredCtrs []*api.Container
}

func newPlugin(
	cfg *config,
	ctrd containerdOps,
	store *policyStore,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) (*plugin, error) {
	p := &plugin{
		cfg:        cfg,
		policy:     store,
		audit:      auditLogger,
		logger:     logger,
		containerd: ctrd,
	}
	p.boot = newBootGate(cfg, logger)
	if cfg.WorkloadClaims.SocketDir != "" {
		procRoot := cfg.WorkloadClaims.ProcRoot
		if procRoot == "" {
			procRoot = "/proc"
		}
		p.inventory = newAdmissionInventory(procRoot)
	}

	// Check if running as pre-installed plugin (containerd sets these env vars)
	isPreInstalled := os.Getenv("NRI_PLUGIN_NAME") != ""

	var opts []stub.Option
	if !isPreInstalled {
		// Only set name/idx for external plugins - pre-installed plugins
		// get these from environment variables set by containerd
		opts = append(opts,
			stub.WithPluginName(pluginName),
			stub.WithPluginIdx(pluginIdx),
		)
	} else {
		logger.Info("running as pre-installed plugin",
			"NRI_PLUGIN_NAME", os.Getenv("NRI_PLUGIN_NAME"),
			"NRI_PLUGIN_IDX", os.Getenv("NRI_PLUGIN_IDX"),
			"NRI_PLUGIN_SOCKET", os.Getenv(api.PluginSocketEnvVar),
		)
	}

	s, err := stub.New(p, opts...)
	if err != nil {
		return nil, fmt.Errorf("create NRI stub: %w", err)
	}
	p.stub = s

	return p, nil
}

// Ready returns true when the plugin has a allowlist loaded and is serving.
func (p *plugin) Ready() bool {
	return p.ready.Load()
}

// SetReady marks the plugin as ready to serve.
func (p *plugin) SetReady() {
	p.ready.Store(true)
}

// Run starts the plugin and blocks until context is cancelled.
func (p *plugin) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		p.stub.Stop()
	}()

	return p.stub.Run(ctx)
}

// Configure is called when the plugin is registered with the runtime.
func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (api.EventMask, error) {
	p.logger.Info("plugin configured",
		"runtime", runtime,
		"version", version,
	)

	var mask api.EventMask
	mask.Set(api.Event_CREATE_CONTAINER)
	mask.Set(api.Event_START_CONTAINER)
	mask.Set(api.Event_VALIDATE_CONTAINER_ADJUSTMENT)
	if p.inventory != nil {
		// The inventory needs eviction on stop to stay correct across pod churn,
		// and the pod-sandbox lifecycle to keep its sandbox set (the /sandbox
		// and /digests routes) live.
		mask.Set(api.Event_REMOVE_CONTAINER)
		mask.Set(api.Event_RUN_POD_SANDBOX)
		mask.Set(api.Event_REMOVE_POD_SANDBOX)
	}
	return mask, nil
}

// RemoveContainer evicts a stopped container from caller resolution; the
// sandbox's record keeps it (inventory.remove). Only subscribed when the
// inventory is enabled (see Configure).
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if p.inventory != nil {
		p.inventory.remove(ctr.GetId())
	}
	return nil
}

// RunPodSandbox records a started pod sandbox for the inventory's sandbox set.
// Only subscribed when the inventory is enabled (see Configure).
func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if p.inventory != nil {
		p.inventory.recordSandbox(pod.GetId())
	}
	return nil
}

// RemovePodSandbox evicts a removed pod sandbox (and its containers) from the
// inventory. Only subscribed when the inventory is enabled (see Configure).
func (p *plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if p.inventory != nil {
		p.inventory.removeSandbox(pod.GetId())
	}
	return nil
}

// recordForInventory resolves a container's image digest and records it for the
// admission inventory. A resolve failure records an empty digest, which makes
// the inventory refuse the pod's whole answer rather than commit a subset —
// fail-closed, and logged at error because it costs the pod its claim.
//
// INVARIANT: callers record what runs, not what passed the checks.
func (p *plugin) recordForInventory(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) {
	if p.inventory == nil {
		return
	}
	digest := extractDigest(imageRef)
	if digest == "" && imageRef != "" {
		if resolved, err := p.containerd.Resolve(ctx, imageRef); err == nil {
			digest = extractDigest(resolved)
		} else {
			p.logger.Error("cannot resolve the image digest of a running container; the sandbox inventory will refuse to answer for this pod", "image", imageRef, "error", err)
		}
	}
	p.recordDigest(ctr, digest, observedMounts(pod, ctr))
}

// recordUncheckedForInventory records the digest inlined in the reference
// without resolving; the pre-Ready hook must answer inside NRI's
// plugin_request_timeout, so recording adds no containerd round-trip.
func (p *plugin) recordUncheckedForInventory(pod *api.PodSandbox, ctr *api.Container, imageRef string) {
	p.recordDigest(ctr, extractDigest(imageRef), observedMounts(pod, ctr))
}

// recordDigest is the only inventory.record call site. ctr.Args is the
// effective OCI process.args, the same value the checks read.
func (p *plugin) recordDigest(ctr *api.Container, digest string, mounts []allowlist.ObservedMount) {
	if p.inventory == nil {
		return
	}
	env := containerEnv(ctr)
	p.inventory.recordObserved(ctr.GetId(), ctr.GetPodSandboxId(), ctr.GetName(), digest, ctr.GetArgs(), env, mounts)
}

func observedMounts(pod *api.PodSandbox, ctr *api.Container) []allowlist.ObservedMount {
	if pod == nil {
		return nil
	}
	return newMountObserver(nil).Observe(pod, ctr)
}

// resolveDigest returns the canonical store digest for imageRef using the same
// path checkImagePhase admits on: the inline digest if present, else the containerd
// content store. Empty on an unresolvable or absent reference. Quiet — the
// callers that need an audit trail (checkImagePhase) do their own logging.
func (p *plugin) resolveDigest(ctx context.Context, imageRef string) string {
	if d := extractDigest(imageRef); d != "" {
		return d
	}
	if imageRef == "" {
		return ""
	}
	resolved, err := p.containerd.Resolve(ctx, imageRef)
	if err != nil {
		return ""
	}
	return resolved
}

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
	Mounts    []allowlist.ObservedMount
}

type launchPhase uint8

const (
	launchPreliminary launchPhase = iota
	launchFinal
)

// checkImagePhase checks the image and observed launch specification against
// the base and served allowlists for the requested admission phase.
func (p *plugin) checkImagePhase(ctx context.Context, cfg *config, check imageCheck, phase launchPhase) (imageVerdict, string) {
	log := p.logger.With(
		"namespace", check.Namespace,
		"pod", check.PodName,
		"container", check.Container,
		"image", check.ImageRef,
	)

	// If no image ref found, deny by default (missing annotation means kubelet was bypassed)
	if check.ImageRef == "" {
		if cfg.Policy.DenyMissingAnnotation {
			log.Warn("no image reference found in annotations, denying")
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "no_image_annotation",
				Namespace: check.Namespace,
				Pod:       check.PodName,
				Container: check.Container,
			})
			return verdictDeny, "container has no image annotation"
		}
		log.Warn("no image reference found in annotations, allowing (deny_missing_annotation disabled)")
		p.audit.Log(audit.Event{
			Action:    "allow",
			Reason:    "no_image_annotation",
			Namespace: check.Namespace,
			Pod:       check.PodName,
			Container: check.Container,
		})
		return verdictSkip, ""
	}

	// Extract digest from image reference (e.g. repo@sha256:abc)
	digest := extractDigest(check.ImageRef)
	if digest == "" {
		// No digest in reference — resolve tag via containerd image store
		resolved, err := p.containerd.Resolve(ctx, check.ImageRef)
		if err != nil {
			log.Warn("cannot resolve image digest via containerd", "error", err)
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "resolve_failed",
				Namespace: check.Namespace,
				Pod:       check.PodName,
				Container: check.Container,
				Image:     check.ImageRef,
				Error:     err.Error(),
			})
			return verdictDeny, fmt.Sprintf("cannot resolve digest for %s: %v", check.ImageRef, err)
		}
		digest = resolved
		log.Debug("resolved tag to digest via containerd", "digest", digest)
	}

	snap := p.policy.current()
	if snap == nil || snap.index == nil {
		log.Error("no allowlist loaded; denying")
		p.audit.Log(audit.Event{
			Action:    "deny",
			Reason:    "no_allowlist_available",
			Namespace: check.Namespace,
			Pod:       check.PodName,
			Container: check.Container,
			Image:     check.ImageRef,
		})
		return verdictDeny, fmt.Sprintf("no allowlist available for %s", check.ImageRef)
	}

	// The base allowlist admits what its entries admit. Served entries are
	// matched against the final OCI argv, environment, and classified mounts.
	rc := allowlist.RunningContainer{Digest: digest, Argv: check.Argv, Env: check.Env, Mounts: check.Mounts}
	admitted := snap.index.AdmitsProcess(rc)
	if phase == launchFinal {
		admitted = snap.index.AdmitsContainer(rc)
	}
	if !p.policy.baseAdmits(rc, phase) && !admitted {
		// INVARIANT: the returned reason reaches a namespace-readable kubelet
		// event, so it names only the image — argv can carry credentials and
		// stays in the node-local log.
		reason, denial := "not_in_allowlist", fmt.Sprintf("image not in allowlist: %s", check.ImageRef)
		if listed := snap.index.AdmitsDigest(digest); listed {
			reason = "launch_not_admitted"
			denial = fmt.Sprintf("image %s is allowlisted, but its launch specification satisfies no workload entry's command, args, env or mounts policy", check.ImageRef)
		}
		log.Warn("image not admitted by allowlist", "digest", digest, "argv", check.Argv, "reason", reason)
		p.audit.Log(audit.Event{
			Action:    "deny",
			Reason:    reason,
			Namespace: check.Namespace,
			Pod:       check.PodName,
			Container: check.Container,
			Image:     check.ImageRef,
		})
		return verdictDeny, denial
	}

	// All checks passed
	log.Info("image allowed")
	p.audit.Log(audit.Event{
		Action:    "allow",
		Reason:    "verified",
		Namespace: check.Namespace,
		Pod:       check.PodName,
		Container: check.Container,
		Image:     check.ImageRef,
	})
	return verdictAllow, ""
}

// checkContainer runs the label rules and the image allowlist over a
// container. Only the image digest (answered by the containerd content
// store) admits; label rules can only deny.
//
// A denial in an exempt namespace is downgraded to skip when the container's
// digest was captured running in that namespace (the frozen snapshot), and only
// then. The exemption runs last, only downgrades, and is keyed on the resolved
// digest — a local fact — not the namespace name the control plane chooses.
func (p *plugin) checkContainer(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string) (imageVerdict, string) {
	return p.checkContainerPhase(ctx, cfg, pod, ctr, imageRef, launchFinal)
}

// checkContainerPhase adds the sandbox policy to the final phase. That policy
// reads the whole container spec — mounts, devices, hooks — so it only makes
// sense on the spec containerd persisted: CreateContainer precedes the other
// plugins' adjustments, and the adjustment validator sees those edits applied
// to a clone's env, argv and mounts alone (env.go, adjustedLaunchContainer).
//
// A sandbox denial is never downgraded by exemptNamespace: the snapshot says
// which digests ran in the namespace, and host privilege is a property of the
// pod spec, not of the image. Only the measured node TCB excuses it.
func (p *plugin) checkContainerPhase(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, phase launchPhase) (imageVerdict, string) {
	var mounts []allowlist.ObservedMount
	if phase == launchFinal {
		mounts = newMountObserver(nil).Observe(pod, ctr)
	}
	verdict, reason := p.checkContainerObserved(ctx, cfg, pod, ctr, imageRef, phase, containerEnv(ctr), mounts)
	if verdict == verdictDeny || phase != launchFinal || !cfg.sandboxObserved() {
		return verdict, reason
	}
	if v, r := p.checkSandbox(ctx, cfg, pod, ctr, imageRef, containerEnv(ctr), mounts); v == verdictDeny {
		return v, r
	}
	return verdict, reason
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
			Mounts:    mounts,
		}, phase)
	}
	return p.exemptNamespace(ctx, cfg, pod, ctr, imageRef, verdict, reason)
}

// exemptNamespace downgrades a denial to skip when the container's digest was
// captured running in that exempt namespace (the frozen snapshot), and only
// then. It runs last, only downgrades, and is keyed on the resolved digest — a
// local fact — not the namespace name the control plane chooses.
func (p *plugin) exemptNamespace(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, verdict imageVerdict, reason string) (imageVerdict, string) {
	namespace, podName, ctrName := pod.GetNamespace(), pod.GetName(), ctr.GetName()
	if verdict != verdictDeny || !slices.Contains(cfg.Policy.ExemptNamespaces, namespace) {
		return verdict, reason
	}

	digest := p.resolveDigest(ctx, imageRef)
	if p.exempt.Load().admits(namespace, digest) {
		p.logger.Info("exempt namespace: admitting a container whose digest was captured running here",
			"namespace", namespace, "pod", podName, "container", ctrName, "digest", digest, "denial", reason)
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
	// Exempt namespace, digest not in the frozen snapshot: a drifted or
	// newly-introduced image. Denied (and never killed — see checkExisting),
	// audited under a distinct reason so drift is alertable from the log.
	p.audit.Log(audit.Event{
		Action:    "deny",
		Reason:    "exempt_snapshot_miss",
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
// Only the MEASURED base allowlist is exempt, and only when the node config
// claims it as the node TCB (allowlist.node_tcb). A CDS-served entry never is: the
// document is authored by the cluster admin this policy defends against.
//
// The exemption is the whole base entry — digest, argv, env and mounts — not
// the digest alone: the control plane picks the image a pod runs, so a TCB
// image restaged with another entrypoint is a tenant container, and an entry
// with a pinned argv refuses it. An entry left at `any` exempts every launch of
// its digest; see docs/allowlist-and-capabilities.md.
//
// The digest is resolved only when there is something to excuse, so an ordinary
// container costs no containerd round-trip.
func (p *plugin) checkSandbox(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) (imageVerdict, string) {
	obs := observeSandbox(pod, ctr, cfg.WorkloadClaims.SocketDir)
	violations := obs.violations()
	if len(violations) == 0 {
		return verdictAllow, ""
	}
	digest := ""
	if cfg.Allowlist.NodeTCB {
		digest = p.resolveDigest(ctx, imageRef)
		rc := allowlist.RunningContainer{Digest: digest, Argv: ctr.GetArgs(), Env: env, Mounts: mounts}
		if p.policy.baseAdmits(rc, launchFinal) {
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

// shouldCheckExisting reports whether the startup check has work — enforcement,
// inventory recovery, or both. See docs/getcert-workload-binding.md, Corner 4.
func (p *plugin) shouldCheckExisting() bool {
	return p.cfg.Policy.EnforceExisting || p.inventory != nil
}

// initExempt loads or captures the exempt-namespace digest snapshot from the
// Synchronize state. A persisted file is authoritative and frozen: the
// installer removes it on a boot config rewrite, so its presence means "already
// captured". Absent, this is the first admission under this config, so it
// captures what is running in the exempt namespaces now — the platform pods
// that came up before containerd's required_plugins gate — and freezes that.
// See exempt.go for why load must win on a reboot.
func (p *plugin) initExempt(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) {
	cfg := p.cfg
	if len(cfg.Policy.ExemptNamespaces) == 0 {
		return
	}

	loaded, err := loadExemptSnapshot(cfg.Policy.ExemptSnapshotPath)
	if err != nil {
		p.logger.Error("cannot read the exempt-namespace snapshot; exempt namespaces admit nothing until it is regenerated",
			"path", cfg.Policy.ExemptSnapshotPath, "error", err)
		return
	}
	if loaded != nil {
		p.exempt.Store(loaded)
		p.logger.Info("loaded exempt-namespace snapshot",
			"path", cfg.Policy.ExemptSnapshotPath, "namespaces", loaded.Namespaces, "digests", loaded.count())
		return
	}

	captured := p.captureExempt(ctx, pods, ctrs)
	if captured.empty() {
		// Freezing an empty capture would deny every platform pod. Leave the
		// file absent so a later start — once containerd hands over the running
		// set — captures instead. On a cold boot the file is present and loaded
		// above, so this only guards a config-rewrite restart that momentarily
		// saw nothing.
		p.logger.Warn("no containers running in the exempt namespaces at first admission; snapshot not written",
			"namespaces", cfg.Policy.ExemptNamespaces)
		return
	}
	p.exempt.Store(captured)
	if err := captured.persist(cfg.Policy.ExemptSnapshotPath); err != nil {
		p.logger.Error("cannot persist the exempt-namespace snapshot; it will be recaptured on the next restart",
			"path", cfg.Policy.ExemptSnapshotPath, "error", err)
	}
	p.logger.Info("captured exempt-namespace snapshot",
		"path", cfg.Policy.ExemptSnapshotPath, "namespaces", captured.Namespaces, "digests", captured.count())
}

// captureExempt builds a snapshot of the image digests running in the exempt
// namespaces, keyed by namespace. A container whose digest will not resolve is
// skipped, not frozen: an unresolved image cannot be an admission key, and
// admitting it later would need a resolvable digest anyway.
func (p *plugin) captureExempt(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) *exemptSnapshot {
	snap := newExemptSnapshot(p.cfg.Policy.ExemptNamespaces)

	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}
	for _, ctr := range ctrs {
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil {
			continue
		}
		namespace := pod.GetNamespace()
		if !slices.Contains(p.cfg.Policy.ExemptNamespaces, namespace) {
			continue
		}
		imageRef := ctr.GetAnnotations()[annotationImageName]
		digest := p.resolveDigest(ctx, imageRef)
		if digest == "" {
			p.logger.Warn("exempt namespace: skipping a running container whose image digest will not resolve",
				"namespace", namespace, "container", ctr.GetName(), "image", imageRef)
			continue
		}
		snap.add(namespace, digest)
	}
	return snap
}

// Synchronize is called when the plugin connects to containerd. It records every
// existing container, checks what it can, and kills violations when
// enforce_existing is set.
func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	cfg := p.cfg

	// Seed the inventory's sandbox set now, even when the container check is
	// deferred: sandbox existence needs no allowlist.
	if p.inventory != nil {
		for _, pod := range pods {
			p.inventory.recordSandbox(pod.GetId())
		}
	}

	// Ahead of every other decision: on a node image a container that already
	// exists means admission was not in place when it started The
	// call does not return when that is what happened.
	if p.boot.check(ctx, p, pods, ctrs) {
		p.bootRestart.Store(true)
	}

	// Load or capture the exempt-namespace snapshot from this connect-time set,
	// before any container check reads it and regardless of readiness.
	p.initExempt(ctx, pods, ctrs)

	if !p.shouldCheckExisting() {
		p.logger.Info("startup check disabled", "pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}

	// If not ready yet, defer the check until after CDS init completes.
	if !p.Ready() {
		p.logger.Info("plugin not ready, deferring startup check",
			"pods", len(pods), "containers", len(ctrs))
		p.deferredMu.Lock()
		p.deferredPods = pods
		p.deferredCtrs = ctrs
		p.deferredMu.Unlock()
		return nil, nil
	}

	p.checkExisting(ctx, cfg, pods, ctrs)
	return nil, nil
}

// checkExisting records every container it is handed, checks the ones whose pod
// sandbox it was also handed, and kills violations when enforce_existing is set.
func (p *plugin) checkExisting(ctx context.Context, cfg *config, pods []*api.PodSandbox, ctrs []*api.Container) {
	p.logger.Info("checking existing containers",
		"pods", len(pods), "containers", len(ctrs), "enforcing", cfg.Policy.EnforceExisting)

	// Build pod lookup by sandbox ID
	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}

	var killed, failed int
	for _, ctr := range ctrs {
		// Recorded ahead of the lookup that can skip it; the record needs no pod.
		imageRef := ctr.GetAnnotations()[annotationImageName]
		pod := podByID[ctr.GetPodSandboxId()]
		p.recordForInventory(ctx, pod, ctr, imageRef)
		if pod == nil {
			continue
		}
		if verdict, _ := p.checkContainer(ctx, cfg, pod, ctr, imageRef); verdict != verdictDeny {
			continue
		}
		// A running container in an exempt namespace is never killed: stopping a
		// platform container (kube-proxy, CoreDNS) can cut the node. A snapshot
		// miss is denied at the next create and audited; it is not enforced
		// retroactively against something already running.
		if slices.Contains(cfg.Policy.ExemptNamespaces, pod.GetNamespace()) {
			p.logger.Warn("exempt namespace: leaving a running container whose digest is not in the snapshot",
				"namespace", pod.GetNamespace(), "container", ctr.GetName())
			continue
		}
		// enforce_existing off: the check only feeds the inventory.
		if cfg.Policy.Mode == ModeAudit || !cfg.Policy.EnforceExisting {
			continue
		}
		// A restart of the gated plugin found a running container the current
		// allowlist does not admit. It has already run, so stopping it proves
		// nothing about what it did. Does not return.
		if p.escalateOnRestart() {
			p.boot.fatalExisting(pod, ctr)
		}

		if err := p.containerd.StopContainer(ctx, ctr.GetId()); err != nil {
			p.logger.Error("sync: failed to kill container", "container", ctr.GetName(), "error", err)
			failed++
		} else {
			killed++
		}
	}

	p.logger.Info("existing-container check complete",
		"killed", killed, "failed", failed, "checked", len(ctrs), "enforcing", cfg.Policy.EnforceExisting)
}

// RunDeferredCheck checks the pods/containers that were seen during Synchronize
// before the plugin was ready. Should be called after SetReady and CDS init.
func (p *plugin) RunDeferredCheck(ctx context.Context) {
	cfg := p.cfg

	if !p.shouldCheckExisting() {
		return
	}

	p.deferredMu.Lock()
	pods := p.deferredPods
	ctrs := p.deferredCtrs
	p.deferredPods = nil
	p.deferredCtrs = nil
	p.deferredMu.Unlock()

	if len(ctrs) == 0 {
		p.logger.Info("no deferred containers to check")
		return
	}

	p.logger.Info("running deferred startup check", "pods", len(pods), "containers", len(ctrs))
	p.checkExisting(ctx, cfg, pods, ctrs)
}

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
	verdict, reason := p.checkContainerPhase(ctx, p.cfg, pod, ctr, ctr.GetAnnotations()[annotationImageName], launchPreliminary)
	if verdict == verdictDeny && p.cfg.Policy.Mode != ModeAudit {
		if !p.Ready() {
			return nil, nil, fmt.Errorf("image policy plugin initializing: %s", reason)
		}
		return nil, nil, fmt.Errorf("%s", reason)
	}
	return p.socketDirAdjustment(pod, ctr), nil, nil
}

// StartContainer runs before task.Start/execve. Its environment is the final
// persisted OCI spec, unlike CreateContainer (or adjustment validation), which
// precedes other plugins and runtime CDI injection. Start updates cannot edit
// argv/env. Failed checks leave no admitted-container evidence.
func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	cfg := p.cfg
	imageRef := ctr.GetAnnotations()[annotationImageName]
	if !p.Ready() {
		if err := p.admitWhileInitializing(ctx, cfg, pod, ctr, imageRef); err != nil {
			return err
		}
		p.recordUncheckedForInventory(pod, ctr, imageRef)
		return nil
	}
	verdict, reason := p.checkContainer(ctx, cfg, pod, ctr, imageRef)
	if verdict == verdictDeny && cfg.Policy.Mode != ModeAudit {
		return fmt.Errorf("%s", reason)
	}
	p.recordForInventory(ctx, pod, ctr, imageRef)
	return nil
}

// socketDirAdjustment bind-mounts the inventory's socket directory, read-only,
// at workloadclaims.SidecarSocketDir into the webhook-injected sidecars of an
// injected pod — the OCI-level replacement for a pod-spec hostPath volume,
// which PodSecurity baseline and restricted would reject. nil for every other
// container, and whenever the inventory is disabled.
//
// The annotation+name gate scopes the mount; it is NOT a security boundary.
// Both are tenant-forgeable, so every socket in the directory must stay safe
// against any on-node caller (peer-credential binding, RO mount).
func (p *plugin) socketDirAdjustment(pod *api.PodSandbox, ctr *api.Container) *api.ContainerAdjustment {
	if p.inventory == nil {
		return nil
	}
	if pod.GetAnnotations()[workloadclaims.AnnotationInjected] != "true" {
		return nil
	}
	if !workloadclaims.IsSidecarContainer(ctr.GetName()) {
		return nil
	}
	adjust := &api.ContainerAdjustment{}
	adjust.AddMount(&api.Mount{
		Destination: workloadclaims.SidecarSocketDir,
		Type:        "bind",
		Source:      p.cfg.WorkloadClaims.SocketDir,
		Options:     []string{"rbind", "ro", "rprivate", "nosuid", "nodev", "noexec"},
	})
	return adjust
}

// extractDigest returns the canonical "sha256:<64hex>" digest from an image
// reference pulled by digest (registry/repo@sha256:... in any accepted form).
// Returns empty string when the reference carries no valid digest; the caller
// treats that as "no digest" and resolves via containerd or denies.
func extractDigest(imageRef string) string {
	d, err := types.NormalizeDigest(imageRef)
	if err != nil {
		return ""
	}
	return d.String()
}

// observeEnv uses runc's last-value rule for duplicate names on CDI containers.
func observeEnv(ctr *api.Container) (*allowlist.EnvObservation, error) {
	obs, err := allowlist.ObserveEnv(ctr.GetEnv())
	if err == nil || !cdiInjected(ctr) {
		return obs, err
	}
	return allowlist.ObserveLaunchEnv(ctr.GetEnv())
}

// cdiInjected reports whether the runtime injected CDI devices into this
// container. The CRI CDIDevices field carries them when the device plugin uses
// the cdi-cri strategy; the cdi.k8s.io annotations carry them under the
// cdi-annotations strategy, which is what the c8s node image's NVIDIA device
// plugin uses.
func cdiInjected(ctr *api.Container) bool {
	if len(ctr.GetCDIDevices()) > 0 {
		return true
	}
	for key := range ctr.GetAnnotations() {
		if strings.HasPrefix(key, cdiAnnotationPrefix) {
			return true
		}
	}
	return false
}

// cdiAnnotationPrefix is the CRI annotation namespace kubelet uses to pass CDI
// device references to the runtime.
const cdiAnnotationPrefix = "cdi.k8s.io/"

// containerEnv refuses an incomplete OCI process. containerd can report an
// empty spec after a failed spec read; that must not look like observed-empty.
// A runnable OCI process has at least one argument, even when its env is empty.
func containerEnv(ctr *api.Container) *allowlist.EnvObservation {
	if len(ctr.GetArgs()) == 0 {
		return nil
	}
	env, _ := observeEnv(ctr)
	return env
}
