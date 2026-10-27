package nriimagepolicy

import (
	"context"
	"errors"
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

// admitsNodeRoot reports whether the base or applied allowlist admits r with
// an exact nodeRootFile rule for m (allowlist.Index.AdmitsNodeRoot).
func (s *policyStore) admitsNodeRoot(r allowlist.RunningContainer, m allowlist.ObservedMount) bool {
	if s == nil {
		return false
	}
	if s.base.AdmitsNodeRoot(r, m) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.AdmitsNodeRoot(r, m)
}

// declaresNodeRoot reports whether the base or applied allowlist has a
// nodeRootFile rule for digest.
func (s *policyStore) declaresNodeRoot(digest string) bool {
	if s == nil {
		return false
	}
	if s.base.DeclaresNodeRoot(digest) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.DeclaresNodeRoot(digest)
}

// needsVariableEvidence reports whether the base or applied allowlist has a
// match env policy for digest.
func (s *policyStore) needsVariableEvidence(digest string) bool {
	if s == nil {
		return false
	}
	if s.base.NeedsVariableEvidence(digest) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.NeedsVariableEvidence(digest)
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
	if s.rolledBack(version) {
		return false
	}
	s.snap.Store(&policySnapshot{index: pulled.BuildIndex(), version: version})
	return true
}

// rolledBack reports whether version is below the applied one.
func (s *policyStore) rolledBack(version uint64) bool {
	cur := s.snap.Load()
	return cur != nil && version < cur.version
}

// containerdOps is the containerd surface admission drives; internal/containerd's
// *Resolver satisfies it.
type containerdOps interface {
	Resolve(ctx context.Context, imageRef string) (string, error)
	VerifyContainerImage(ctx context.Context, containerID, sandboxID, digest string) error
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

	mountStorage mountStorageInspector

	// exempt admits an exempt namespace's containers by the digest set captured
	// running in it, not by the namespace name. nil ⇔ not opted in
	// (policy.exempt_namespaces empty) or not yet captured. See exempt.go.
	exempt atomic.Pointer[exemptSnapshot]

	// inventory serves the sandbox-identity flow (docs/armtls.md). nil ⇔ the flow
	// is disabled (no workload_claims.socket_dir) — configuration, not a
	// fault: Configure then leaves the inventory-feeding events unsubscribed,
	// and the nil-guarded hooks/seeding no-op rather than fail a container
	// lifecycle callback over bookkeeping.
	inventory *admissionInventory

	// mesh is the mesh gate (meshgate.go), under the mesh policy the measured
	// config carries.
	mesh *meshGate
	// measurer extends each started workload into RTMR[3]; nil unless
	// measure.rtmr3. Pause sandboxes never reach StartContainer.
	measurer workloadMeasurer
	// Pod admission and credential publication share one ordering boundary.
	podMu                sync.Mutex
	podBroker            *podCredentialBroker
	podStarts            map[string]podStartGrant
	podStartDisconnected atomic.Bool

	// cdsPins is the node-side path of the CDS attestation policy handed to
	// the injected credential clients, or "" when the node pins nothing.
	// prepareCDSPins sets it before any container can be created (cdspins.go).
	cdsPins string

	// cdsAddress is the node-side path of the CDS endpoint handed to those
	// same clients, or "" when no pod of this node is injected.
	// prepareCDSAddress sets it before any container can be created
	// (cdsaddress.go).
	cdsAddress string

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
	p.mesh = newMeshGate(*cfg.Mesh, logger)
	logger.Info("mesh gate enabled",
		"trusted_enforcement", cfg.requiresTrustedMeshEnforcement(),
		"exempt_namespaces", cfg.Mesh.ExemptNamespaces)
	measurer, err := openMeasurer(cfg, logger)
	if err != nil {
		return nil, err
	}
	p.measurer = measurer
	if cfg.WorkloadClaims.SocketDir != "" {
		procRoot := cfg.WorkloadClaims.ProcRoot
		if procRoot == "" {
			procRoot = "/proc"
		}
		p.inventory = newAdmissionInventory(procRoot)
		p.inventory.needsVariableEvidence = store.needsVariableEvidence
	}

	// Check if running as pre-installed plugin (containerd sets these env vars)
	isPreInstalled := os.Getenv("NRI_PLUGIN_NAME") != ""

	var opts []stub.Option
	if cfg.podRole() {
		opts = append(opts, stub.WithOnClose(p.disconnectPodStarts))
	}
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

// AppliedAllowlistVersion is the CDS version of the allowlist admission decides
// with: the last pull apply accepted, so a pull the anti-rollback check ignored
// does not move it. It is 0 until a pull applied.
func (p *plugin) AppliedAllowlistVersion() uint64 {
	return p.policy.current().version
}

// Run starts the plugin and blocks until context is cancelled.
func (p *plugin) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer p.disconnectPodStarts()
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
	// The mesh gate holds a sandbox's protection over its life, and the
	// inventory keeps its sandbox set (the /sandbox and /digests routes) live.
	mask.Set(api.Event_RUN_POD_SANDBOX)
	mask.Set(api.Event_REMOVE_POD_SANDBOX)
	mask.Set(api.Event_UPDATE_CONTAINER)
	if p.inventory != nil {
		// The inventory needs stop and removal to stay correct across pod churn.
		mask.Set(api.Event_STOP_CONTAINER)
		mask.Set(api.Event_REMOVE_CONTAINER)
	}
	return mask, nil
}

// StopContainer marks a stopped container exited in its sandbox's record
// (inventory.stop). Only subscribed when the inventory is enabled (see
// Configure).
func (p *plugin) StopContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	defer p.lockPodAdmission()()
	delete(p.podStarts, ctr.GetId())
	if p.inventory != nil {
		p.inventory.stop(ctr.GetId())
	}
	return nil, nil
}

// RemoveContainer evicts a removed container from caller resolution; the
// sandbox's record keeps it (inventory.remove). Only subscribed when the
// inventory is enabled (see Configure).
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	defer p.lockPodAdmission()()
	delete(p.podStarts, ctr.GetId())
	if p.inventory != nil {
		p.inventory.remove(ctr.GetId())
	}
	return nil
}

// RunPodSandbox records a started pod sandbox for the inventory's sandbox set
// and installs the pod's packet protection, before any container of that pod
// is created. A failed install refuses the sandbox, so the gate is what
// refuses its containers (docs/armtls.md).
func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	defer p.lockPodAdmission()()
	if p.inventory != nil {
		p.inventory.recordSandbox(pod.GetId())
	}
	if err := p.mesh.protect(pod); err != nil {
		p.logger.Error("cannot protect a pod; every container of it will be refused", "error", err)
	}
	return nil
}

// RemovePodSandbox evicts a removed pod sandbox (and its containers) from the
// inventory and the mesh gate.
func (p *plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	defer p.lockPodAdmission()()
	p.endPodIdentity(errors.New("pod sandbox removed; its boot history cannot be reused for a new identity"))
	if p.inventory != nil {
		p.inventory.removeSandbox(pod.GetId())
	}
	p.mesh.forget(pod.GetId())
	return nil
}

// UpdateContainer refuses every change to a container of a pod the enforcer
// protects. An error here fails the update, so the container keeps the
// resources it was admitted with.
func (p *plugin) UpdateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container, _ *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	if !p.mesh.hosts(pod) {
		return nil, nil
	}
	return nil, fmt.Errorf("container %s of pod %s/%s cannot be changed while the pod is protected", ctr.GetName(), pod.GetNamespace(), pod.GetName())
}

// SandboxForPeer and DigestsForSandbox make the plugin the
// workloadclaims.SandboxResolver: the inventory resolves the caller by kernel
// credentials, holds the refusals that kept the sandbox's containers from
// running, and the gate verifies the pod it runs in. Lock order: the
// inventory's, then the gate's.
func (p *plugin) SandboxForPeer(peer workloadclaims.Peer) (workloadclaims.CallerSandbox, error) {
	sandboxID, err := p.inventory.sandboxForPeer(peer)
	if err != nil {
		return workloadclaims.CallerSandbox{}, err
	}
	refusal := p.inventory.denial(sandboxID)
	if refusal == nil {
		refusal = p.mesh.verifyMember(sandboxID)
	}
	return workloadclaims.CallerSandbox{
		SandboxID: sandboxID,
		Refusal:   refusal,
	}, nil
}

func (p *plugin) DigestsForSandbox(sandboxID string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return p.inventory.DigestsForSandbox(sandboxID)
}

// denyContainer records the refusal that keeps a container of sandboxID from
// running and returns it for the hook to fail with.
//
// INVARIANT: every refusal a hook returns in enforcing mode passes through
// here, so the sandbox it belongs to asserts no identity.
func (p *plugin) denyContainer(sandboxID string, refusal error) error {
	if p.cfg.podRole() {
		p.endPodIdentity(refusal)
	}
	if p.inventory != nil {
		p.inventory.recordDenial(sandboxID, refusal)
	}
	p.podChanged()
	return refusal
}

// denyContainerCreation is denyContainer for a refusal returned at a creation
// hook, whose container therefore never ran. Admitting a container of the same
// name in the sandbox lifts the refusal, so a pod created in the window
// between an allowlist apply and this node pulling the entry gets its identity
// once the retried container passes the admission check.
func (p *plugin) denyContainerCreation(sandboxID, containerName string, refusal error) error {
	if p.inventory != nil {
		p.inventory.recordCreationDenial(sandboxID, containerName, refusal)
	}
	p.podChanged()
	return refusal
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
	digest, err := p.imageDigest(ctx, imageRef)
	if err != nil {
		p.logger.Error("cannot resolve the image digest of a running container; the sandbox inventory will refuse to answer for this pod", "image", imageRef, "error", err)
	}
	p.recordDigest(ctr, digest, p.observedMounts(pod, ctr))
}

// recordDigest is the only inventory.record call site. ctr.Args is the
// effective OCI process.args, the same value the checks read, and the role is
// the one the measured base binds to that whole launch.
func (p *plugin) recordDigest(ctr *api.Container, digest string, mounts []allowlist.ObservedMount) {
	if p.inventory == nil {
		return
	}
	env := containerEnv(ctr)
	launch := allowlist.RunningContainer{
		Digest: digest,
		Argv:   ctr.GetArgs(),
		Env:    env,
		Mounts: mounts,
	}
	role := p.roleOf(launch)
	p.inventory.recordObserved(ctr.GetId(), ctr.GetPodSandboxId(), ctr.GetName(), digest, role, ctr.GetArgs(), env, mounts)
}

// nodeMounts grants no node-service exception to a measured Pod workload.
func (p *plugin) nodeMounts() nodeMounts {
	if p.cfg.podRole() {
		return nodeMounts{}
	}
	return nodeMounts{
		socketDir:  p.cfg.WorkloadClaims.SocketDir,
		cdsPins:    p.cdsPins,
		cdsAddress: p.cdsAddress,
	}
}

func (p *plugin) observedMounts(pod *api.PodSandbox, ctr *api.Container) []allowlist.ObservedMount {
	if pod == nil {
		return nil
	}
	return newMountObserver(p.mountStorage, p.nodeMounts()).Observe(pod, ctr)
}

// resolveDigest returns the canonical store digest for imageRef using the same
// path checkImagePhase admits on: the inline digest if present, else the containerd
// content store. Empty on an unresolvable or absent reference. Quiet — the
// callers that need an audit trail (checkImagePhase) do their own logging.
// imageDigest returns imageRef's digest, resolving a tag through containerd.
// It returns "" without error when imageRef is empty or resolves to no digest.
func (p *plugin) imageDigest(ctx context.Context, imageRef string) (string, error) {
	if d := extractDigest(imageRef); d != "" || imageRef == "" {
		return d, nil
	}
	resolved, err := p.resolve(ctx, imageRef)
	if err != nil {
		return "", err
	}
	return extractDigest(resolved), nil
}

func (p *plugin) resolveDigest(ctx context.Context, imageRef string) string {
	if d := extractDigest(imageRef); d != "" {
		return d
	}
	if imageRef == "" {
		return ""
	}
	resolved, err := p.resolve(ctx, imageRef)
	if err != nil {
		return ""
	}
	return resolved
}

type resolvedKey struct{}

// withResolved scopes one hook call: within it each tag resolves once, so
// admission, the RTMR[3] measurement and the inventory see one digest even if
// the tag moves, and the hook pays one containerd round-trip per tag.
func withResolved(ctx context.Context) context.Context {
	return context.WithValue(ctx, resolvedKey{}, &sync.Map{})
}

func (p *plugin) resolve(ctx context.Context, imageRef string) (string, error) {
	memo, _ := ctx.Value(resolvedKey{}).(*sync.Map)
	if memo != nil {
		if d, ok := memo.Load(imageRef); ok {
			return d.(string), nil
		}
	}
	d, err := p.containerd.Resolve(ctx, imageRef)
	if err == nil && memo != nil {
		memo.Store(imageRef, d)
	}
	return d, err
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
		resolved, err := p.resolve(ctx, check.ImageRef)
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
		attrs := []any{"digest", digest, "argv", check.Argv, "reason", reason}
		if missing := nodeRootMissing(check.Mounts); missing != "" && p.policy.declaresNodeRoot(digest) {
			attrs = append(attrs, "node_root_unavailable", missing)
		}
		log.Warn("image not admitted by allowlist", attrs...)
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
		mounts = p.observedMounts(pod, ctr)
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
// Two exemptions apply. The first is a node-TCB entry: only the MEASURED base
// allowlist, and only when the node config claims it as the node TCB
// (allowlist.node_tcb). A CDS-served entry never is, because the cluster admin
// this policy defends against authors that document. The exemption is the
// whole base entry — digest, argv, env and mounts — not the digest alone: the
// control plane picks the image a pod runs, so a TCB image restaged with
// another entrypoint is a tenant container, and an entry with a pinned argv
// refuses it. An entry left at `any` exempts every launch of its digest; see
// docs/allowlist-and-capabilities.md.
//
// The second exempts a single bind, not the container: one whose mount
// evidence carries node-root provenance and that an exact `nodeRootFile` rule of
// the base or the served allowlist admits at that destination and source. A
// served rule is safe here because it can only name read-only bytes of the
// measured node image, and strict clients verify the served policy byte for
// byte.
//
// The digest is resolved only when an exemption could apply, so an ordinary
// container costs no containerd round-trip.
func (p *plugin) checkSandbox(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) (imageVerdict, string) {
	obs := observeSandbox(pod, ctr, p.nodeMounts(), mounts, nil)
	violations := obs.violations()
	if len(violations) == 0 {
		return verdictAllow, ""
	}
	digest := ""
	if cfg.AllowlistEnabled() && len(obs.HostBinds) > 0 && slices.ContainsFunc(mounts, func(m allowlist.ObservedMount) bool { return m.Provenance != "" }) {
		digest = p.resolveDigest(ctx, imageRef)
		rc := allowlist.RunningContainer{Digest: digest, Argv: ctr.GetArgs(), Env: env, Mounts: mounts}
		obs = observeSandbox(pod, ctr, p.nodeMounts(), mounts, func(m allowlist.ObservedMount) bool {
			return p.policy.admitsNodeRoot(rc, m)
		})
		if violations = obs.violations(); len(violations) == 0 {
			return verdictAllow, ""
		}
	}
	if cfg.Allowlist.NodeTCB {
		if digest == "" {
			digest = p.resolveDigest(ctx, imageRef)
		}
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
	defer p.lockPodAdmission()()
	clear(p.podStarts)
	cfg := p.cfg

	// Seed the inventory's sandbox set now, even when the container check is
	// deferred: sandbox existence needs no allowlist.
	if p.inventory != nil {
		for _, pod := range pods {
			p.inventory.recordSandbox(pod.GetId())
		}
		p.inventory.awaitRecovery()
	}
	p.mesh.refuseExisting(pods)

	// Ahead of every other decision: on a node image a container that already
	// exists means admission was not in place when it started The
	// call does not return when that is what happened.
	if p.boot.check(ctx, p, pods, ctrs) {
		p.bootRestart.Store(true)
		p.endPodIdentity(errors.New("pod inventory was reconstructed after a plugin restart"))
	}

	// Load or capture the exempt-namespace snapshot from this connect-time set,
	// before any container check reads it and regardless of readiness.
	p.initExempt(ctx, pods, ctrs)

	if !p.shouldCheckExisting() {
		p.logger.Info("startup check disabled", "pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}

	// If not ready yet, defer the check until after CDS init completes. Ready
	// is read under deferredMu so RunDeferredCheck cannot run between it and
	// the store and leave the batch unchecked.
	p.deferredMu.Lock()
	if !p.Ready() {
		p.deferredPods = pods
		p.deferredCtrs = ctrs
		p.deferredMu.Unlock()
		p.logger.Info("plugin not ready, deferring startup check",
			"pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}
	p.deferredMu.Unlock()

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

	if p.inventory != nil {
		defer p.inventory.recovered()
	}
	var killed, failed int
	for _, ctr := range ctrs {
		imageRef := ctr.GetAnnotations()[annotationImageName]
		pod := podByID[ctr.GetPodSandboxId()]
		unreconstructable := cfg.podRole()
		if unreconstructable {
			// Current runtime metadata cannot reconstruct the complete history
			// required by a Pod identity after a plugin restart.
			_ = p.denyContainer(ctr.GetPodSandboxId(), errors.New("cannot reconstruct Pod admission history from existing containers"))
		} else {
			// Node inventory records even containers without a known sandbox.
			if p.inventory != nil && ctr.GetState() == api.ContainerState_CONTAINER_STOPPED {
				p.inventory.stop(ctr.GetId())
			}
			p.recordForInventory(ctx, pod, ctr, imageRef)
		}
		if pod == nil {
			continue
		}
		if !unreconstructable {
			if verdict, _ := p.checkContainer(ctx, cfg, pod, ctr, imageRef); verdict != verdictDeny {
				continue
			}
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
	defer p.lockPodAdmission()()
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
		if p.inventory != nil {
			p.inventory.recovered()
		}
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
	defer p.lockPodAdmission()()
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

// StartContainer runs before task.Start/execve. Its environment is the final
// persisted OCI spec, unlike CreateContainer (or adjustment validation), which
// precedes other plugins and runtime CDI injection. Start updates cannot edit
// argv/env. Failed checks leave no admitted-container evidence.
func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	defer p.lockPodAdmission()()
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
			err = p.mesh.admit(pod, ctr, gatedContainer{role: role, mountsPinned: p.bindsRoleMounts(launch, role), digest: launch.Digest, argv: launch.Argv})
		}
		if err != nil {
			return p.denyContainer(pod.GetId(), err)
		}
	}
	if !p.Ready() {
		if err := p.admitWhileInitializing(ctx, cfg, pod, ctr, imageRef); err != nil {
			return p.transientRefusal(pod, err)
		}
		if err := p.measureStarted(ctx, imageRef); err != nil {
			return p.transientRefusal(pod, err)
		}
		// INVARIANT: the gate holds a member pod whether or not the first
		// pull has settled, so the start that opens it is recorded on both
		// paths. A role comes from the base alone, which is loaded at boot.
		// The record resolves the digest here too: an unresolved one closes
		// the sandbox's inventory answer for its life (internal/admissionhistory),
		// and the pod that starts in this window is the one a fresh install
		// brings up with CDS.
		p.noteMeshStarted(ctx, pod, ctr, imageRef)
		p.recordForInventory(ctx, pod, ctr, imageRef)
		return p.finishPodStart(ctx, pod, ctr, credentialSource)
	}
	verdict, reason := p.checkContainer(ctx, cfg, pod, ctr, imageRef)
	if verdict == verdictDeny && cfg.Policy.Mode != ModeAudit {
		return p.denyContainer(pod.GetId(), fmt.Errorf("%s", reason))
	}
	if err := p.measureStarted(ctx, imageRef); err != nil {
		return p.transientRefusal(pod, err)
	}
	p.noteMeshStarted(ctx, pod, ctr, imageRef)
	p.recordForInventory(ctx, pod, ctr, imageRef)
	return p.finishPodStart(ctx, pod, ctr, credentialSource)
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

// roleOf is the only role lookup: the role the measured base allowlist binds
// to this finalized launch. The field never travels on the wire, so a role
// comes from the node's own boot config.
func (p *plugin) roleOf(launch allowlist.RunningContainer) string {
	if p.policy == nil {
		return ""
	}
	return p.policy.base.RoleOf(launch)
}

// bindsRoleMounts reports whether the declaration granting this launch its
// role pins the mount set too. Like the role, it comes from the measured base
// alone.
func (p *plugin) bindsRoleMounts(launch allowlist.RunningContainer, role string) bool {
	if p.policy == nil {
		return false
	}
	return p.policy.base.BindsRoleMounts(launch, role)
}

// observedLaunch is the container as a role lookup reads it.
func (p *plugin) observedLaunch(ctx context.Context, ctr *api.Container, imageRef string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) allowlist.RunningContainer {
	return allowlist.RunningContainer{
		Digest: p.resolveDigest(ctx, imageRef),
		Argv:   ctr.GetArgs(),
		Env:    env,
		Mounts: mounts,
	}
}

// credentialMounts bind-mounts what the node hands a credential client,
// read-only: the inventory's socket directory at
// workloadclaims.SidecarSocketDir into the socket consumers
// (workloadclaims.IsSocketConsumer) of an injected pod, the node's CDS
// attestation policy at workloadclaims.CDSPinsPath, and the CDS endpoint it
// dials at workloadclaims.CDSAddressPath. All are OCI-level replacements for a
// pod-spec hostPath volume, which PodSecurity baseline and restricted would
// reject. nil for every other container, and whenever the inventory is
// disabled.
//
// The two policy mounts are what make the CDS a client reaches trusted: it
// reads compiled paths, so a pod cannot name another source and the control
// plane cannot pass one as an argument. A container running as the credentials
// identity that this node's measured base grants no such role is refused.
func (p *plugin) credentialMounts(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error) {
	if p.cfg.podRole() {
		return nil, nil
	}
	if fetchesRouteManifest(pod, ctr) {
		return p.routerCDSMount(), nil
	}
	injected := injectedCredentialSidecar(pod, ctr)
	if !holdsCredentialsIdentity(ctr) && !injected {
		return nil, nil
	}
	if holdsCredentialsIdentity(ctr) && p.measuredRole(ctx, pod, ctr) != CredentialRole {
		return nil, fmt.Errorf("container %q runs as the credentials identity (uid %d) but this node's measured base grants it no %s role, so it would reach CDS unpinned",
			ctr.GetName(), workloadclaims.CredentialsUID, CredentialRole)
	}
	var mounts []*api.Mount
	if servesInventory := p.inventory != nil; servesInventory {
		mounts = append(mounts, readOnlyBind(p.cfg.WorkloadClaims.SocketDir, workloadclaims.SidecarSocketDir))
	}
	if pinsCDS := p.cdsPins != ""; pinsCDS {
		mounts = append(mounts, readOnlyBind(p.cdsPins, workloadclaims.CDSPinsPath))
	}
	if p.cdsAddress != "" {
		mounts = append(mounts, readOnlyBind(p.cdsAddress, workloadclaims.CDSAddressPath))
	}
	if len(mounts) == 0 {
		return nil, nil
	}
	return &api.ContainerAdjustment{Mounts: mounts}, nil
}

// holdsCredentialsIdentity reports whether this container runs as the identity
// the pod ruleset admits the node's CDS for. The grant itself is the measured
// role.
func holdsCredentialsIdentity(ctr *api.Container) bool {
	return ctr.GetUser().GetUid() == workloadclaims.CredentialsUID
}

// fetchesRouteManifest reports whether this container is the one the router's
// route manifest comes through: its attest sidecar, on the upstream identity
// that pod's ruleset admits the node's CDS for (meshgate_linux.go). The pod is
// the chart's own in a namespace the enforcer compiles in, and the measured
// base binds every container of it to a role, so the name holds no privilege
// of its own.
func fetchesRouteManifest(pod *api.PodSandbox, ctr *api.Container) bool {
	return pod.GetNamespace() == routerNamespace &&
		ctr.GetName() == workloadclaims.AttestContainerName &&
		ctr.GetUser().GetUid() == workloadclaims.UpstreamUID
}

// routerCDSMount is the CDS endpoint alone: the router polls the signed route
// manifest from the one CDS its node admits, and takes its pins from the
// measured base the chart renders rather than from a node document.
func (p *plugin) routerCDSMount() *api.ContainerAdjustment {
	if p.cdsAddress == "" {
		return nil
	}
	return &api.ContainerAdjustment{
		Mounts: []*api.Mount{readOnlyBind(p.cdsAddress, workloadclaims.CDSAddressPath)},
	}
}

// injectedCredentialSidecar reports the webhook's own shape: a reserved
// sidecar name on a pod the injector annotated. Both are tenant-forgeable, so
// every socket in the directory stays safe against any on-node caller through
// peer-credential binding and a read-only mount.
func injectedCredentialSidecar(pod *api.PodSandbox, ctr *api.Container) bool {
	return pod.GetAnnotations()[workloadclaims.AnnotationInjected] == "true" &&
		workloadclaims.IsSocketConsumer(ctr.GetName())
}

// measuredRole is the role the node's measured base grants this launch, from
// the evidence the runtime reports at CreateContainer: digest, argv,
// environment and the mounts requested so far, classified as the final check
// classifies them, so a declaration that pins a mount set is matched here too.
// StartContainer re-reads the same fields from the final spec.
func (p *plugin) measuredRole(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) string {
	imageRef, err := p.containerImage(pod, ctr)
	if err != nil {
		return ""
	}
	return p.roleOf(p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), p.observedMounts(pod, ctr)))
}

func readOnlyBind(source, destination string) *api.Mount {
	return &api.Mount{
		Destination: destination,
		Type:        "bind",
		Source:      source,
		Options:     []string{"rbind", "ro", "rprivate", "nosuid", "nodev", "noexec"},
	}
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
// cdi-annotations strategy, which is what the C8s node image's NVIDIA device
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
