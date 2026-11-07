package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
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

// containerdOps is the containerd surface admission drives; internal/containerd's
// *Resolver satisfies it.
type containerdOps interface {
	Resolve(ctx context.Context, imageRef string) (string, error)
	VerifyContainerImage(ctx context.Context, containerID, sandboxID, digest string) error
	ContainerSpec(ctx context.Context, containerID string) (*specs.Spec, error)
	StopContainer(ctx context.Context, containerID string) error
	SandboxNetwork(ctx context.Context, sandboxID string, pod ctrdresolver.SandboxPod) (ctrdresolver.SandboxNetwork, error)
}

// plugin implements the NRI plugin interface for image policy enforcement.
type plugin struct {
	stub          stub.Stub
	cfg           *config
	policy        *policyStore
	audit         *audit.Logger
	logger        *slog.Logger
	ready         atomic.Bool
	podRegistered atomic.Bool
	containerd    containerdOps

	mountStorage mountStorageInspector

	// inventory serves the sandbox-identity flow (docs/armtls.md). nil ⇔ the flow
	// is disabled (no workload_claims.socket_dir) — configuration, not a
	// fault: Configure then leaves the inventory-feeding events unsubscribed,
	// and the nil-guarded hooks/seeding no-op rather than fail a container
	// lifecycle callback over bookkeeping.
	inventory *admissionInventory
	// execGrants records the started containers the measured base grants execs,
	// for the runtime wrapper (execgrants.go). nil where the base grants none.
	execGrants *grantRecords
	// capGrants records the capabilities the allowlists declare for each
	// container admission clears, for the runtime wrapper
	// (capabilitygrants.go).
	capGrants *grantRecords

	// mesh is the mesh gate (meshgate.go), under the mesh policy the measured
	// config carries.
	mesh *meshGate
	// deletePod removes a refused pod as this node (refusedpods.go).
	deletePod func(ctx context.Context, pod *api.PodSandbox) error
	// measurer extends each started workload into RTMR[3]; nil unless
	// measure.rtmr3. Pause sandboxes never reach StartContainer.
	measurer workloadMeasurer
	// Pod admission and credential publication share one ordering boundary.
	podMu                sync.Mutex
	podBroker            *podCredentialBroker
	podStarts            map[string]podStartGrant
	podStartDisconnected atomic.Bool
	// podEnded is set once endPodIdentity ran, in this process or an earlier
	// one of this boot (podEndedMarker): the health socket reports it, so the
	// status service can project the pod as failed while a kubelet under
	// restartPolicy Always keeps recreating refused containers.
	podEnded atomic.Bool

	// cdsPins is the node-side path of the CDS attestation policy handed to
	// the injected credential clients, or "" when no pod of this node is
	// injected. prepareCDSPins sets it before any container can be created (cdspins.go).
	cdsPins string

	// cdsAddress is the node-side path of the CDS endpoint handed to those
	// same clients, or "" when no pod of this node is injected.
	// prepareCDSAddress sets it before any container can be created
	// (cdsaddress.go).
	cdsAddress string

	// clientDocument is the guest-side path of a Pod CVM's client document,
	// bound read-only into every container of the Pod, or "" when the
	// assignment carried none. prepareClientDocument sets it before any
	// container can be created.
	clientDocument string

	// cdiSpecDirs are the CDI spec directories the sandbox policy expands a
	// container's trusted CDI devices from (cdi.go).
	cdiSpecDirs []string

	// boot is the boot gate: nil unless policy.fatal_existing. See
	// bootgate.go. bootRestart records that this registration is a plugin
	// restart, which makes the startup check's denials fatal.
	boot        *bootGate
	bootRestart atomic.Bool

	// running is what KillRevoked rechecks after each applied allowlist.
	running runningContainers

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

		cdiSpecDirs: cdiSpecDirs,
	}
	p.boot = newBootGate(cfg, logger)
	p.restorePodEnded()
	// Every sandbox namespace is proven against the enforcer's own, read here
	// before any thread of it can attach to a pod's (meshgate.go).
	if _, err := enforcerNetworkNamespace(); err != nil {
		return nil, fmt.Errorf("read the enforcer's own network namespace: %w", err)
	}
	p.mesh = newMeshGate(*cfg.Mesh, logger)
	p.mesh.nodeAddress = func() (netip.Addr, error) { return nodeOwnAddress(cfg) }
	if !cfg.podRole() {
		p.deletePod = p.deleteNodePod
	}
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
	if grantsExecs(cfg.Allowlist.Base) {
		p.execGrants = newExecGrantRecords(ExecGrantDir)
	}
	// A served allowlist can declare capabilities the base does not, so the
	// records are kept whatever the base declares.
	p.capGrants = newCapabilityGrantRecords(CapabilityGrantDir)

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
	// The running set and the inventory need stop and removal to stay
	// correct across pod churn.
	mask.Set(api.Event_STOP_CONTAINER)
	mask.Set(api.Event_REMOVE_CONTAINER)
	return mask, nil
}

// StopContainer drops a started container from the running set and marks it
// exited in its sandbox's record (inventory.stop). A stop of a created
// container ends nothing: a start already past StartContainer still runs it.
func (p *plugin) StopContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	defer p.cvm().lockAdmission()()
	delete(p.podStarts, ctr.GetId())
	if wasStarted(ctr) {
		p.running.remove(ctr.GetId())
	}
	if p.inventory != nil {
		p.inventory.stop(ctr.GetId())
	}
	return nil, nil
}

func wasStarted(ctr *api.Container) bool {
	return ctr.GetState() != api.ContainerState_CONTAINER_CREATED
}

// RemoveContainer drops a removed container from the running set and from
// caller resolution; the sandbox's record keeps it (inventory.remove).
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	defer p.cvm().lockAdmission()()
	delete(p.podStarts, ctr.GetId())
	p.running.remove(ctr.GetId())
	p.execGrants.remove(ctr.GetId())
	p.capGrants.remove(ctr.GetId())
	if p.inventory != nil {
		p.inventory.remove(ctr.GetId())
	}
	return nil
}

// RunPodSandbox refuses a sandbox holding host ports no allowlist entry
// declares (hostports.go), records a started pod sandbox for the inventory's
// sandbox set and installs the pod's packet protection, before any container
// of that pod is created. A failed install refuses the sandbox, so the gate is
// what refuses its containers (docs/armtls.md).
func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if err := p.admitSandboxHostPorts(ctx, p.cfg, pod); err != nil {
		return err
	}
	defer p.cvm().lockAdmission()()
	if err := p.cvm().admitSandbox(pod); err != nil {
		return p.denyContainer(pod.GetId(), err)
	}
	if p.inventory != nil {
		p.inventory.recordSandbox(pod.GetId())
	}
	if err := p.mesh.protect(pod); err != nil {
		p.reportUnprotected(pod, err)
		return p.cvm().admitUnprotected(pod, err)
	}
	return nil
}

// RemovePodSandbox evicts a removed pod sandbox (and its containers) from the
// inventory and the mesh gate.
func (p *plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	defer p.cvm().lockAdmission()()
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
	p.cvm().endIdentity(refusal)
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
// admission inventory and the runtime wrapper's exec grants. A resolve
// failure records an empty digest, which makes the inventory refuse the pod's
// whole answer rather than commit a subset — fail-closed, and logged at error
// because it costs the pod its claim.
//
// INVARIANT: callers record what runs, not what passed the checks.
func (p *plugin) recordForInventory(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) {
	if p.inventory == nil && p.execGrants == nil {
		return
	}
	digest, err := p.imageDigest(ctx, imageRef)
	if err != nil {
		p.logger.Error("cannot resolve the image digest of a running container; any sandbox inventory refuses to answer for its pod, and it is granted no execs", "image", imageRef, "error", err)
	}
	p.recordDigest(pod, ctr, digest, p.observedMounts(pod, ctr))
}

// recordDigest is the only inventory.record and exec-grant record call site.
// ctr.Args is the effective OCI process.args, the same value the checks read,
// and the role and execs are the ones the measured base binds to that whole
// launch.
func (p *plugin) recordDigest(pod *api.PodSandbox, ctr *api.Container, digest string, mounts []allowlist.ObservedMount) {
	env := containerEnv(ctr)
	launch := allowlist.RunningContainer{
		Digest: digest,
		Argv:   ctr.GetArgs(),
		Env:    env,
		Mounts: mounts,
	}
	if p.execGrants != nil {
		if err := p.execGrants.note(ctr.GetId(), p.execsOf(pod, launch)); err != nil {
			p.logger.Error("cannot record the container's exec grant; the runtime wrapper denies its execs", "container", ctr.GetId(), "error", err)
		}
	}
	if p.inventory == nil {
		return
	}
	role := p.roleOf(launch)
	p.inventory.recordObserved(ctr.GetId(), ctr.GetPodSandboxId(), ctr.GetName(), digest, role, ctr.GetArgs(), env, mounts)
}

func (p *plugin) observedMounts(pod *api.PodSandbox, ctr *api.Container) []allowlist.ObservedMount {
	if pod == nil {
		return nil
	}
	return newMountObserver(p.mountStorage, p.cvm().enforcerMounts()).Observe(pod, ctr)
}

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

// roleOf is the only role lookup: the role the measured base allowlist binds
// to this finalized launch. The field never travels on the wire, so a role
// comes from the node's own boot config.
func (p *plugin) roleOf(launch allowlist.RunningContainer) string {
	if p.policy == nil {
		return ""
	}
	return p.policy.base.RoleOf(launch)
}

// execsOf is the commands the measured base lets the runtime wrapper start in
// this finalized launch. Like a role, they come from the base alone, and a pod
// the mesh gates cover holds none: no new process starts in a member.
func (p *plugin) execsOf(pod *api.PodSandbox, launch allowlist.RunningContainer) [][]string {
	if p.policy == nil || pod == nil || (p.mesh != nil && p.mesh.hosts(pod)) {
		return nil
	}
	return p.policy.base.ExecsOf(launch)
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
func (p *plugin) observedLaunch(ctx context.Context, observed observedContainer) allowlist.RunningContainer {
	return observed.launch(p.resolveDigest(ctx, observed.imageRef))
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

// envError is why the OCI environment left env unavailable, if it did.
func envError(ctr *api.Container, env *allowlist.EnvObservation) error {
	if env != nil {
		return nil
	}
	_, err := observeEnv(ctr)
	return err
}

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
