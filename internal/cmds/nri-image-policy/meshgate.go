package nriimagepolicy

// The mesh gate is the runtime half of mesh membership: the enforcer installs
// a pod's packet protection into its own network namespace before any of its
// containers is created, verifies it before each one runs, and again before an
// identity assertion. Fails closed; see docs/armtls.md.

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
)

// meshGate holds this node's protection state, under the mesh policy its
// measured configuration carries.
type meshGate struct {
	policy meshPolicy
	logger *slog.Logger
	mu     sync.Mutex
	pods   map[string]*protectedPod
	// nodeAddress is this node's own address, which no exit may reach.
	nodeAddress func() (netip.Addr, error)
	// extend adds granted exits to a pod's live ruleset.
	extend func(podNamespace, meshPolicy, string, []exit) error
}

// protectedPod is one protected sandbox: a refusal holds for its life, and
// kubeNamespace is what trusted policy built its ruleset from.
type protectedPod struct {
	netns           podNamespace
	refusal         error
	meshStarted     bool
	workloadCreated bool
	kubeNamespace   string
	roleLaunches    []roleLaunch
	// exitEntry is the allowlist entry whose exits the pod was granted, and
	// exits those exits: fixed for the pod's life once granted.
	exitEntry string
	exits     []exit
	// starts serializes a workload container's exit decision with its record
	// in the inventory, so two starts cannot both decide on a set that lacks
	// the other.
	starts sync.Mutex
}

// exit is one range and TCP port a pod reaches uncaptured.
type exit struct {
	Range netip.Prefix
	Port  uint16
}

// roleLaunch is a platform-role container this gate admitted in a sandbox: a
// later container of the same role running the same bytes under the same
// arguments is a replacement of it.
type roleLaunch struct {
	role   string
	digest string
	argv   []string
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
// role, the bytes and arguments that role was read from, and the adjustments
// that could move its packets.
type gatedContainer struct {
	role string
	// mountsPinned reports that the declaration granting the role pins the
	// mount set too, which the router's namespace requires of every
	// container (requireRoleOnlyPod).
	mountsPinned bool
	digest       string
	argv         []string
	namespaces   []*api.LinuxNamespace
	netDevices   map[string]*api.LinuxNetDevice
}

func newMeshGate(policy meshPolicy, logger *slog.Logger) *meshGate {
	return &meshGate{
		policy: policy,
		logger: logger,
		pods:   map[string]*protectedPod{},
		nodeAddress: func() (netip.Addr, error) {
			return netip.Addr{}, errors.New("this node's own address is unknown")
		},
		extend: extendPodRuleset,
	}
}

// hosts reports a sandbox the enforcer protects: its own network namespace,
// in a namespace trusted policy does not exempt.
func (g *meshGate) hosts(pod *api.PodSandbox) bool {
	return !slices.Contains(g.policy.ExemptNamespaces, pod.GetNamespace()) &&
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
	netns, err := installProtection(pod, g.policy)
	g.pods[pod.GetId()] = &protectedPod{
		netns:         netns,
		refusal:       err,
		kubeNamespace: pod.GetNamespace(),
	}
	if err != nil {
		return fmt.Errorf("protect pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
	}
	g.logger.Info("installed the pod mesh ruleset",
		"namespace", pod.GetNamespace(), "pod", pod.GetName(), "netns", netns.path)
	return nil
}

// installProtection proves the pod's own network namespace and installs the
// ruleset in it. A proven namespace is on record even when the install fails,
// so a later report of another path still reads as a move.
func installProtection(pod *api.PodSandbox, policy meshPolicy) (podNamespace, error) {
	netns, err := proveSandboxNamespace(podNetworkNamespace(pod), pod.GetPid())
	if err != nil {
		return netns, err
	}
	if err := installPodRuleset(netns, policy, pod.GetNamespace()); err != nil {
		return netns, err
	}
	return netns, nil
}

// recoveredContainer is a container of a sandbox that was running when this
// enforcer connected, as the gate reads it from the runtime's list.
type recoveredContainer struct {
	ctr     *api.Container
	launch  gatedContainer
	running bool
}

// recoverPod takes a sandbox that was running before this enforcer connected
// back under the gate, or refuses it for its life. What an earlier enforcer
// protected is read back from the sandbox itself, from evidence still live in
// it rather than any claim the pod makes: the namespace the runtime reports is
// proven the sandbox's own, the ruleset live in it is the one trusted policy
// defines (its real anchor, re-verified here, which is installed once in a
// namespace's life), and each container passes the checks that read a container
// alone. A measured node image separately aborts if any container exists at
// first boot (policy.fatal_existing, checked in Synchronize). The order of the
// list says nothing about what started first, so the order rules are not
// re-read.
func (g *meshGate) recoverPod(pod *api.PodSandbox, ctrs []recoveredContainer, exits recoveredExits) error {
	if !g.hosts(pod) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, onRecord := g.pods[pod.GetId()]; onRecord {
		return fmt.Errorf("sandbox %s is on record already", pod.GetId())
	}
	state, err := g.recovered(pod, ctrs, exits)
	if err != nil {
		g.pods[pod.GetId()] = &protectedPod{
			refusal:       fmt.Errorf("the sandbox was running before this enforcer connected, and %w", err),
			kubeNamespace: pod.GetNamespace(),
		}
		return fmt.Errorf("recover pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
	}
	g.pods[pod.GetId()] = state
	g.logger.Info("recovered the protection of a running pod",
		"namespace", pod.GetNamespace(), "pod", pod.GetName(), "netns", state.netns.path,
		"containers", len(ctrs), "mesh_running", state.meshStarted, "exit_entry", state.exitEntry)
	return nil
}

// recoveredExits is the exit grant the gate reads back for a running sandbox:
// the entry whose exits it holds and those exits, as the admit path would have
// granted them. A sandbox holds exits only while it matches that entry, so the
// ruleset the gate verifies is the base mesh ruleset plus these exits.
//
// cause is why no grant was read — the pod's workload match could not be
// decided (no served allowlist yet) or the match refused it. A pod whose live
// ruleset is exactly the base mesh ruleset still recovers with no exits and no
// cause; only one whose ruleset holds exits the empty grant cannot account for
// fails verification, and then cause explains why the grant was empty so an
// operator does not read the base-ruleset mismatch as tampering.
type recoveredExits struct {
	entry string
	exits []exit
	cause error
}

// recovered is the record of a running sandbox whose protection reads back.
func (g *meshGate) recovered(pod *api.PodSandbox, ctrs []recoveredContainer, exits recoveredExits) (*protectedPod, error) {
	netns, err := proveSandboxNamespace(podNetworkNamespace(pod), pod.GetPid())
	if err != nil {
		return nil, err
	}
	// The live ruleset holds the base mesh rules plus whatever exits the pod
	// was granted, so verify against that combined ruleset, not the base alone.
	// A pod with no grant whose ruleset is the base alone passes; one whose
	// ruleset holds exits the empty grant cannot account for fails here, and the
	// undecided/refused cause, when there is one, names why the grant was empty.
	if err := verifyPodRuleset(netns, g.policy, pod.GetNamespace(), exits.exits); err != nil {
		if exits.cause != nil {
			return nil, fmt.Errorf("%w; the pod was granted no exits: %v", err, exits.cause)
		}
		return nil, err
	}
	state := &protectedPod{
		netns:         netns,
		kubeNamespace: pod.GetNamespace(),
		exitEntry:     exits.entry,
		exits:         exits.exits,
	}
	for _, c := range ctrs {
		if err := state.restore(g.policy, c); err != nil {
			return nil, fmt.Errorf("container %s: %w", c.ctr.GetName(), err)
		}
	}
	return state, nil
}

// restore records a container found running in a recovered sandbox, after the
// checks of a create that read the container alone. A mesh endpoint found
// running is the start the rest of the pod waits on.
func (s *protectedPod) restore(policy meshPolicy, c recoveredContainer) error {
	for _, check := range []func() error{
		func() error { return s.requireContainerAlone(policy, c.ctr, c.launch) },
		func() error { return s.requireSandboxNetwork(c.ctr) },
	} {
		if err := check(); err != nil {
			return err
		}
	}
	s.recordLaunch(c.launch)
	if c.running && c.launch.role == meshRole {
		s.meshStarted = true
	}
	return nil
}

// requireContainerAlone runs the checks a create makes from a container on its
// own, with no bearing on the order it started in or the rest of the pod: its
// role may run only where its pod admits it, it runs as the identity its role
// reserves, and it keeps its own PID namespace. Both admission (admissible) and
// recovery (restore) make these; each adds the checks its path alone can make.
func (s *protectedPod) requireContainerAlone(policy meshPolicy, ctr *api.Container, launch gatedContainer) error {
	for _, check := range []func() error{
		func() error { return s.requireRoleOnlyPod(launch) },
		func() error { return policy.requireRoleIdentity(ctr, launch.role) },
		func() error { return requirePrivatePIDNamespace(ctr) },
	} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// requireSandboxNetwork requires a container's network namespace, where its
// bundle names one, to be the sandbox's: the ruleset verified there says
// nothing about a container running in another.
func (s *protectedPod) requireSandboxNetwork(ctr *api.Container) error {
	for _, ns := range ctr.GetLinux().GetNamespaces() {
		if ns.GetType() == "network" && ns.GetPath() != "" && ns.GetPath() != s.netns.path {
			return fmt.Errorf("the container runs in the network namespace %s, not the sandbox's %s", ns.GetPath(), s.netns.path)
		}
	}
	return nil
}

func (g *meshGate) forget(sandboxID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.pods, sandboxID)
}

// noteMeshStarted records the start that opens the gate for the rest of a pod.
func (g *meshGate) noteMeshStarted(sandboxID string) {
	g.update(sandboxID, func(state *protectedPod) {
		state.meshStarted = true
	})
}

// noteLaunched records an admitted container for the order rules.
func (g *meshGate) noteLaunched(sandboxID string, launch gatedContainer) {
	g.update(sandboxID, func(state *protectedPod) {
		state.recordLaunch(launch)
	})
}

// recordLaunch records a container of the sandbox for the order rules.
func (s *protectedPod) recordLaunch(launch gatedContainer) {
	if launch.role == "" {
		s.workloadCreated = true
		return
	}
	if !s.admittedBefore(launch) {
		s.roleLaunches = append(s.roleLaunches, launch.identity())
	}
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
	netns, kubeNamespace, err := g.admissible(pod, ctr, launch)
	if err != nil {
		return fmt.Errorf("mesh gate: container %s of pod %s/%s: %w", ctr.GetName(), pod.GetNamespace(), pod.GetName(), err)
	}
	if err := verifyPodRuleset(netns, g.policy, kubeNamespace, g.grantedExits(pod.GetId())); err != nil {
		return fmt.Errorf("mesh gate: container %s of pod %s/%s: %w", ctr.GetName(), pod.GetNamespace(), pod.GetName(), err)
	}
	g.noteLaunched(pod.GetId(), launch)
	return nil
}

// grantedExits are the exits a protected sandbox was granted. A grant happens
// once and only adds, so a ruleset verified with what this reads is the pod's.
func (g *meshGate) grantedExits(sandboxID string) []exit {
	g.mu.Lock()
	defer g.mu.Unlock()
	if state := g.pods[sandboxID]; state != nil {
		return state.exits
	}
	return nil
}

// lockStarts holds a protected sandbox's container starts one at a time,
// from the exit decision to the inventory record. A sandbox off the record
// needs no lock: it holds no exit, and the startup gate refuses it.
func (g *meshGate) lockStarts(pod *api.PodSandbox) func() {
	g.mu.Lock()
	state := g.pods[pod.GetId()]
	g.mu.Unlock()
	if state == nil {
		return func() {}
	}
	state.starts.Lock()
	return state.starts.Unlock
}

// bindEntry applies the exit decision for a workload container about to start
// in a protected pod (decideExits): it refuses the container, grants the
// entry's exits, or holds a pod with exits to the entry they came from. The
// exits are fixed for the pod's life: an allowlist change applies to the next
// pod.
func (g *meshGate) bindEntry(pod *api.PodSandbox, decision exitDecision) error {
	if !g.hosts(pod) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// A sandbox off the record or refused is the startup gate's to refuse; it
	// holds no exit to grant or keep.
	state := g.pods[pod.GetId()]
	if state == nil || state.refusal != nil {
		return nil
	}
	if decision.undecided != nil {
		if state.exitEntry != "" {
			return fmt.Errorf("the pod holds the exits of allowlist entry %q, and whether it still matches that entry cannot be read: %w", state.exitEntry, decision.undecided)
		}
		g.logger.Warn("no exits granted: the pod's workload match cannot be read",
			"namespace", pod.GetNamespace(), "pod", pod.GetName(), "error", decision.undecided)
		return nil
	}
	if decision.refusal != nil {
		return decision.refusal
	}
	if state.exitEntry != "" {
		if decision.entry != state.exitEntry {
			return fmt.Errorf("the pod holds the exits of allowlist entry %q, and with this container it no longer matches that entry", state.exitEntry)
		}
		return nil
	}
	if decision.entry == "" {
		if len(decision.shadowed) > 0 {
			g.logger.Warn("no exits granted: each allowlist entry with exits is unpinned or shares its containers with another entry",
				"namespace", pod.GetNamespace(), "pod", pod.GetName(), "entries", decision.shadowed, "allowlist_version", decision.version)
		}
		return nil
	}
	if err := g.requireOffLimits(decision.exits); err != nil {
		return fmt.Errorf("allowlist entry %q: %w", decision.entry, err)
	}
	if err := g.extend(state.netns, g.policy, state.kubeNamespace, decision.exits); err != nil {
		return fmt.Errorf("grant the exits of allowlist entry %q: %w", decision.entry, err)
	}
	state.exitEntry, state.exits = decision.entry, decision.exits
	g.logger.Info("granted the pod its allowlist entry's exits",
		"namespace", pod.GetNamespace(), "pod", pod.GetName(), "entry", decision.entry,
		"exits", decision.exits, "allowlist_version", decision.version)
	return nil
}

// requireOffLimits refuses an exit into this cluster or onto this node: a
// connection to a member leaves the pod through the mesh or not at all, and
// the node's own services, its CDS and every service a platform role is bound
// to are reached under their own rules or not at all, on any port.
func (g *meshGate) requireOffLimits(exits []exit) error {
	if err := g.policy.requireOutsideCluster(exits); err != nil {
		return err
	}
	node, err := g.nodeAddress()
	if err != nil {
		return fmt.Errorf("no exit can be shown to stay off this node: %w", err)
	}
	offLimits := []netip.Addr{node, g.policy.Resolver}
	for _, role := range g.policy.Roles {
		for _, dst := range role.Destinations {
			offLimits = append(offLimits, dst.Addr())
		}
	}
	for _, e := range exits {
		for _, addr := range offLimits {
			if addr.IsValid() && e.Range.Contains(addr) {
				return fmt.Errorf("exit %s port %d reaches %s, an address of this node or of a service a platform role is bound to", e.Range, e.Port, addr)
			}
		}
	}
	return nil
}

// requireOutsideCluster refuses an exit into this cluster's pod or Service
// ranges: a connection to a member leaves the pod through the mesh or not at
// all. A policy naming no range of an exit's address family cannot show that
// exit stays outside them.
func (p meshPolicy) requireOutsideCluster(exits []exit) error {
	for _, e := range exits {
		family := false
		for _, in := range p.ClusterRanges {
			if in.Addr().Is4() != e.Range.Addr().Is4() {
				continue
			}
			family = true
			if e.Range.Overlaps(in) {
				return fmt.Errorf("exit %s port %d overlaps the cluster range %s", e.Range, e.Port, in)
			}
		}
		if !family {
			return fmt.Errorf("trusted mesh policy names no %s cluster range, so exit %s cannot be shown to stay outside the cluster", ipFamily(e.Range), e.Range)
		}
	}
	return nil
}

func ipFamily(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// admissible answers from the enforcer's record, and returns the namespace
// whose live ruleset is still to verify.
func (g *meshGate) admissible(pod *api.PodSandbox, ctr *api.Container, launch gatedContainer) (podNamespace, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.state(pod.GetId())
	if err != nil {
		return podNamespace{}, "", err
	}
	// Protection a pod never had cannot be established by a later check, so a
	// namespace that moved refuses the sandbox for its life.
	if reported := podNetworkNamespace(pod); reported != state.netns.path {
		state.refusal = fmt.Errorf("the reported network namespace moved from %s to %s", state.netns.path, reported)
		return podNamespace{}, "", state.refusal
	}
	// The installed ruleset was built for the namespace the sandbox started
	// in, so a container reported in another one is a container this pod's
	// rules say nothing about.
	if reported := pod.GetNamespace(); reported != state.kubeNamespace {
		state.refusal = fmt.Errorf("the reported namespace moved from %s to %s", state.kubeNamespace, reported)
		return podNamespace{}, "", state.refusal
	}
	for _, check := range []func() error{
		func() error { return state.requireRoleOrder(launch) },
		func() error { return state.requireContainerAlone(g.policy, ctr, launch) },
		func() error { return launch.requireNoNetworkChange() },
	} {
		if err := check(); err != nil {
			return podNamespace{}, "", err
		}
	}
	return state.netns, state.kubeNamespace, nil
}

// verifyMember is the verification an identity assertion requires: a current
// member pod whose live ruleset is the one trusted policy defines.
func (g *meshGate) verifyMember(sandboxID string) error {
	if err := g.verifyMemberRuleset(sandboxID); err != nil {
		g.logger.Warn("refusing to verify a sandbox as a protected mesh member", "sandbox", sandboxID, "error", err)
		return err
	}
	return nil
}

// verifyMemberRuleset verifies the live ruleset of a protected sandbox whose
// mesh endpoint is running.
func (g *meshGate) verifyMemberRuleset(sandboxID string) error {
	netns, kubeNamespace, err := g.memberNamespace(sandboxID)
	if err != nil {
		return err
	}
	return verifyPodRuleset(netns, g.policy, kubeNamespace, g.grantedExits(sandboxID))
}

// memberNamespace is the network namespace of a protected sandbox whose
// verified mesh endpoint is running, with the Kubernetes namespace its ruleset
// was built for.
func (g *meshGate) memberNamespace(sandboxID string) (podNamespace, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.state(sandboxID)
	if err != nil {
		return podNamespace{}, "", err
	}
	if !state.meshStarted {
		return podNamespace{}, "", fmt.Errorf("sandbox %s runs no verified mesh endpoint", sandboxID)
	}
	return state.netns, state.kubeNamespace, nil
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
// container, and every role to precede every container outside a role. A
// platform-role launch this gate admitted in this sandbox may start again
// later, so a crashed role can be replaced by what already ran.
func (s *protectedPod) requireRoleOrder(launch gatedContainer) error {
	switch {
	case launch.role != "" && s.workloadCreated && !s.admittedBefore(launch):
		return fmt.Errorf("the %s role cannot start after a container outside every platform role", launch.role)
	case launch.role == meshRole:
		return nil
	case !s.meshStarted:
		return errors.New("the pod's mesh endpoint is not running, so no other container may start")
	default:
		return nil
	}
}

// admittedBefore reports a launch of the same platform role, image digest and
// arguments as one this gate admitted in this sandbox.
func (s *protectedPod) admittedBefore(launch gatedContainer) bool {
	return slices.ContainsFunc(s.roleLaunches, func(admitted roleLaunch) bool {
		return admitted.role == launch.role &&
			admitted.digest == launch.digest &&
			slices.Equal(admitted.argv, launch.argv)
	})
}

// identity is the part of an admitted launch a replacement must repeat.
func (c gatedContainer) identity() roleLaunch {
	return roleLaunch{
		role:   c.role,
		digest: c.digest,
		argv:   slices.Clone(c.argv),
	}
}

// requireRoleOnlyPod requires a pod of the router's namespace to hold role
// containers only, from its first container: an inbound accept cannot be tied
// to a socket UID, so those listeners are open to anything that runs there.
// Each of them runs under a declaration that pins its mounts as well, because
// the credentials of this pod are separated by mount set alone: a role
// container whose mounts are left to the host could be given another role's
// credential volume, and the upstream role's mount set is what binds its
// uncaptured reach into the cluster to the sidecar that authenticates a
// backend itself.
func (s *protectedPod) requireRoleOnlyPod(launch gatedContainer) error {
	if s.kubeNamespace != routerNamespace {
		return nil
	}
	if launch.role == "" {
		return fmt.Errorf("this pod serves the %s role's own ports, so only its platform roles may run here", routerRole)
	}
	if !launch.mountsPinned {
		return fmt.Errorf("the %s role runs here only under a declaration that pins its mounts, which this launch has none of", launch.role)
	}
	return nil
}

// requirePrivatePIDNamespace requires a member pod's container to run in a pid
// namespace of its own. In a shared one every process of the pod is visible
// through one /proc, so a container reads another's credential volume at
// /proc/<pid>/root whatever the mount sets say.
//
// containerd points the namespace at a process only when the pod shares it
// (internal/cri/opts, WithPodNamespaces), and an absent entry is the node's
// own; its own namespace is the entry with no path.
func requirePrivatePIDNamespace(ctr *api.Container) error {
	for _, ns := range ctr.GetLinux().GetNamespaces() {
		if ns.GetType() != pidNamespace {
			continue
		}
		if path := ns.GetPath(); path != "" {
			return fmt.Errorf("the container joins the pid namespace at %s instead of running in its own", path)
		}
		return nil
	}
	return errors.New("the container declares no pid namespace of its own")
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
	return podNamespace{
		path: path,
		id: fileID{
			device: uint64(described.Dev),
			inode:  described.Ino,
		},
	}, nil
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
