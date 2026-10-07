package nriimagepolicy

// The mesh gate is the runtime half of mesh membership: the enforcer installs
// a pod's packet protection into its own network namespace before any of its
// containers is created, verifies it before each one runs, and again before an
// identity assertion. Fails closed; see docs/armtls.md.

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
)

// meshGate holds this node's protection state. A disabled gate hosts no
// member pods, which is what a config with no mesh policy says.
type meshGate struct {
	enabled bool
	policy  meshPolicy
	logger  *slog.Logger
	mu      sync.Mutex
	pods    map[string]*protectedPod
}

// protectedPod is one protected sandbox: a refusal holds for its life,
// serverRole makes it role-only, launched is admitted names and images.
type protectedPod struct {
	netns           podNamespace
	refusal         error
	meshStarted     bool
	workloadCreated bool
	serverRole      string
	launched        map[string]string
	frozen          bool
}

// podNamespace is a pod's own network namespace: the runtime chose the path,
// the file the kernel holds is the namespace itself.
type podNamespace struct {
	path string
	id   fileID
}

type fileID struct {
	device uint64
	inode  uint64
}

// gatedContainer is the container the validator decides on: its verified
// role, its image, and the adjustments that could move its packets.
type gatedContainer struct {
	role       string
	digest     string
	namespaces []*api.LinuxNamespace
	netDevices map[string]*api.LinuxNetDevice
}

func newMeshGate(policy *meshPolicy, logger *slog.Logger) *meshGate {
	gate := &meshGate{logger: logger, pods: map[string]*protectedPod{}}
	if policy != nil {
		gate.enabled, gate.policy = true, *policy
	}
	return gate
}

// hosts reports a sandbox the enforcer protects: its own network namespace,
// in a namespace trusted policy does not exempt (MM3).
func (g *meshGate) hosts(pod *api.PodSandbox) bool {
	return g.enabled &&
		!slices.Contains(g.policy.ExemptNamespaces, pod.GetNamespace()) &&
		podNetworkNamespace(pod) != ""
}

// protect installs the pod ruleset once in a sandbox's life, before any of
// its containers is created. A sandbox it cannot protect is refused for life.
func (g *meshGate) protect(pod *api.PodSandbox) error {
	if !g.hosts(pod) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, onRecord := g.pods[pod.GetId()]; onRecord {
		return fmt.Errorf("sandbox %s is on record already, so its protection stands as installed", pod.GetId())
	}
	netns, err := proveSandboxNamespace(podNetworkNamespace(pod), pod.GetPid())
	if err == nil {
		err = installPodRuleset(netns, g.policy)
	}
	g.pods[pod.GetId()] = &protectedPod{netns: netns, refusal: err}
	if err != nil {
		return fmt.Errorf("protect pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
	}
	g.logger.Info("installed the pod mesh ruleset",
		"namespace", pod.GetNamespace(), "pod", pod.GetName(), "netns", netns.path)
	return nil
}

// refuseExisting refuses every sandbox already running when this enforcer
// connected: its containers ran unchecked, and rules that are correct now
// establish no eligibility (MM2).
func (g *meshGate) refuseExisting(pods []*api.PodSandbox) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, pod := range pods {
		if g.hosts(pod) {
			g.pods[pod.GetId()] = &protectedPod{refusal: errors.New("the sandbox was running before this enforcer connected")}
		}
	}
}

func (g *meshGate) forget(sandboxID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.pods, sandboxID)
}

// noteMeshStarted records the start that opens the gate for the rest of a pod.
func (g *meshGate) noteMeshStarted(sandboxID string) {
	g.update(sandboxID, func(state *protectedPod) { state.meshStarted = true })
}

// freeze fixes the container set of a pod that holds an identity assertion.
func (g *meshGate) freeze(sandboxID string) {
	g.update(sandboxID, func(state *protectedPod) { state.frozen = true })
}

// noteLaunched records an admitted container for the order and freeze rules.
func (g *meshGate) noteLaunched(sandboxID, name string, launch gatedContainer) {
	g.update(sandboxID, func(state *protectedPod) {
		if state.launched == nil {
			state.launched = map[string]string{}
		}
		state.launched[name] = launch.digest
		if launch.role == "" {
			state.workloadCreated = true
		}
		if servesOwnPorts(launch.role) {
			state.serverRole = launch.role
		}
	})
}

func (g *meshGate) update(sandboxID string, change func(*protectedPod)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if state := g.pods[sandboxID]; state != nil {
		change(state)
	}
}

// admit is the startup gate: a container of a protected pod is created only
// after the live ruleset in that pod's namespace is the one trusted policy
// defines, independently of admission mode, ordering and probes.
func (g *meshGate) admit(pod *api.PodSandbox, ctr *api.Container, launch gatedContainer) error {
	if !g.hosts(pod) {
		return nil
	}
	netns, err := g.admissible(pod, ctr, launch)
	if err == nil {
		err = verifyPodRuleset(netns, g.policy)
	}
	if err != nil {
		return fmt.Errorf("mesh gate: container %s of pod %s/%s: %w", ctr.GetName(), pod.GetNamespace(), pod.GetName(), err)
	}
	g.noteLaunched(pod.GetId(), ctr.GetName(), launch)
	return nil
}

// admissible answers from the enforcer's record, and returns the namespace
// whose live ruleset is still to verify.
func (g *meshGate) admissible(pod *api.PodSandbox, ctr *api.Container, launch gatedContainer) (podNamespace, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.state(pod.GetId())
	if err != nil {
		return podNamespace{}, err
	}
	// Protection a pod never had cannot be established by a later check, so a
	// namespace that moved refuses the sandbox for its life.
	if reported := podNetworkNamespace(pod); reported != state.netns.path {
		state.refusal = fmt.Errorf("the reported network namespace moved from %s to %s", state.netns.path, reported)
		return podNamespace{}, state.refusal
	}
	for _, check := range []func() error{
		func() error { return state.requireRoleOrder(launch.role) },
		func() error { return state.requireRoleOnlyPod(launch.role) },
		func() error { return state.requireInFrozenSet(ctr.GetName(), launch.digest) },
		func() error { return g.policy.requireRoleIdentity(ctr, launch.role) },
		func() error { return launch.requireNoNetworkChange() },
	} {
		if err := check(); err != nil {
			return podNamespace{}, err
		}
	}
	return state.netns, nil
}

// verifyMember is the verification an identity assertion requires (MP3): a
// current member pod whose live ruleset is the one trusted policy defines. A
// node with no mesh policy has no protection to verify and withholds none.
func (g *meshGate) verifyMember(sandboxID string) error {
	if !g.enabled {
		return nil
	}
	netns, err := g.memberNamespace(sandboxID)
	if err == nil {
		err = verifyPodRuleset(netns, g.policy)
	}
	if err != nil {
		g.logger.Warn("refusing to verify a sandbox as a protected mesh member", "sandbox", sandboxID, "error", err)
	}
	return err
}

// memberNamespace is the namespace of a protected sandbox whose verified mesh
// endpoint is running.
func (g *meshGate) memberNamespace(sandboxID string) (podNamespace, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.state(sandboxID)
	if err != nil {
		return podNamespace{}, err
	}
	if !state.meshStarted {
		return podNamespace{}, fmt.Errorf("sandbox %s runs no verified mesh endpoint", sandboxID)
	}
	return state.netns, nil
}

// state is the record of a sandbox that is not refused. Callers hold g.mu.
func (g *meshGate) state(sandboxID string) (*protectedPod, error) {
	state := g.pods[sandboxID]
	switch {
	case state == nil:
		return nil, fmt.Errorf("this enforcer installed no packet protection for sandbox %s", sandboxID)
	case state.refusal != nil:
		return nil, fmt.Errorf("sandbox %s is refused for its life: %w", sandboxID, state.refusal)
	}
	return state, nil
}

// requireRoleOrder requires the mesh endpoint to run before any other
// container, and every role to precede every container outside a role.
func (s *protectedPod) requireRoleOrder(role string) error {
	switch {
	case role != "" && s.workloadCreated:
		return fmt.Errorf("the %s role cannot start after a container outside every platform role", role)
	case role == meshRole:
		return nil
	case !s.meshStarted:
		return errors.New("the pod's mesh endpoint is not running, so no other container may start")
	default:
		return nil
	}
}

// requireRoleOnlyPod requires a pod serving a role's own ports to hold role
// containers only: an inbound accept cannot be tied to a socket UID.
func (s *protectedPod) requireRoleOnlyPod(role string) error {
	if role == "" && s.serverRole != "" {
		return fmt.Errorf("this pod serves the %s role's own ports, so only its platform roles may run here", s.serverRole)
	}
	return nil
}

// requireInFrozenSet requires a frozen pod's container to be one it already
// ran under the same image, which its assertion covers.
func (s *protectedPod) requireInFrozenSet(name, digest string) error {
	if admitted, ran := s.launched[name]; s.frozen && (!ran || admitted != digest) {
		return fmt.Errorf("the container set is frozen by an issued identity and %s is not in it", name)
	}
	return nil
}

// requireNoNetworkChange refuses an adjustment that leaves the verified
// ruleset behind: another namespace carries other rules, and a host network
// device reaches past every rule in this one.
func (c gatedContainer) requireNoNetworkChange() error {
	if len(c.namespaces) > 0 || len(c.netDevices) > 0 {
		return errors.New("an adjustment re-points the container's namespaces or moves a host network device in")
	}
	return nil
}

// servesOwnPorts names the roles listening on ports of their own: the router
// serves the cluster's external traffic.
func servesOwnPorts(role string) bool { return role == routerRole }

// proveSandboxNamespace proves that path is the network namespace the
// sandbox's own process lives in, and not the node's: without it the ruleset
// could protect a namespace carrying none of the pod's traffic.
func proveSandboxNamespace(path string, sandboxPID uint32) (podNamespace, error) {
	if sandboxPID == 0 {
		return podNamespace{}, errors.New("the runtime reports no sandbox process to prove the network namespace against")
	}
	described, err := namespaceFile(path)
	if err != nil {
		return podNamespace{}, err
	}
	// The enforcer is a node process, so its own namespace is the node's.
	node, err := namespaceFile("/proc/self/ns/net")
	if err != nil {
		return podNamespace{}, err
	}
	if described.id == node.id {
		return podNamespace{}, fmt.Errorf("%s is the node's own network namespace", path)
	}
	sandbox, err := namespaceFile(fmt.Sprintf("/proc/%d/ns/net", sandboxPID))
	if err != nil {
		return podNamespace{}, err
	}
	// The kernel's own handle on that process's namespace is the namespace:
	// any other file, of any kind, is another thing.
	if described.id != sandbox.id {
		return podNamespace{}, fmt.Errorf("%s is not the network namespace of sandbox process %d", path, sandboxPID)
	}
	return described, nil
}

// namespaceFile describes the file a path names.
func namespaceFile(path string) (podNamespace, error) {
	var described unix.Stat_t
	if err := unix.Stat(path, &described); err != nil {
		return podNamespace{}, fmt.Errorf("describe network namespace %s: %w", path, err)
	}
	return podNamespace{path: path, id: fileID{device: uint64(described.Dev), inode: described.Ino}}, nil
}

// podNetworkNamespace is the path the runtime reports for the pod's own
// network namespace, empty when the pod shares the node's: containerd drops
// the entry rather than naming the host's (sandbox.go).
func podNetworkNamespace(pod *api.PodSandbox) string {
	for _, ns := range pod.GetLinux().GetNamespaces() {
		if ns.GetType() == "network" {
			return ns.GetPath()
		}
	}
	return ""
}
