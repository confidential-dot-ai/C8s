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

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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

// exit is one range and TCP port a pod reaches uncaptured, or one host the
// pod's mesh endpoint carries TLS to on that port (Range unset).
type exit struct {
	Range netip.Prefix
	Host  string
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

// refuseExisting refuses every sandbox already running when this enforcer
// connected: its containers ran unchecked, and a ruleset that is correct now
// says nothing about what already ran.
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
	g.update(sandboxID, func(state *protectedPod) {
		state.meshStarted = true
	})
}

// noteLaunched records an admitted container for the order rules.
func (g *meshGate) noteLaunched(sandboxID string, launch gatedContainer) {
	g.update(sandboxID, func(state *protectedPod) {
		if launch.role == "" {
			state.workloadCreated = true
			return
		}
		if !state.admittedBefore(launch) {
			state.roleLaunches = append(state.roleLaunches, launch.identity())
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
	if slices.ContainsFunc(exits, exit.isHost) && g.policy.Capture.Egress == 0 {
		return errors.New("trusted mesh policy names no egress listener, so this node grants no host exit")
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
			if addr.IsValid() && e.Range.IsValid() && e.Range.Contains(addr) {
				return fmt.Errorf("exit %s port %d reaches %s, an address of this node or of a service a platform role is bound to", e.Range, e.Port, addr)
			}
		}
	}
	return nil
}

func (e exit) isHost() bool {
	return e.Host != ""
}

// offLimits are the addresses no host exit connection may be dialed to,
// whatever a name resolves to: this cluster, this node, its resolver and every
// service a platform role is bound to. The mesh endpoint checks each address
// it resolves a granted host to against them.
func (g *meshGate) offLimits() ([]netip.Prefix, error) {
	node, err := g.nodeAddress()
	if err != nil {
		return nil, err
	}
	out := slices.Clone(g.policy.ClusterRanges)
	for _, addr := range []netip.Addr{node, g.policy.Resolver} {
		if addr.IsValid() {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	for _, role := range g.policy.Roles {
		for _, dst := range role.Destinations {
			out = append(out, netip.PrefixFrom(dst.Addr(), dst.Addr().BitLen()))
		}
	}
	return out, nil
}

// HostExits are the hosts a protected sandbox was granted, with the addresses
// none of them may be reached at; no hosts for a sandbox granted none.
func (g *meshGate) HostExits(sandboxID string) (workloadclaims.HostExits, error) {
	var hosts []workloadclaims.HostExit
	for _, e := range g.grantedExits(sandboxID) {
		if e.isHost() {
			hosts = append(hosts, workloadclaims.HostExit{Host: e.Host, Port: e.Port})
		}
	}
	if len(hosts) == 0 {
		return workloadclaims.HostExits{}, nil
	}
	offLimits, err := g.offLimits()
	if err != nil {
		return workloadclaims.HostExits{}, err
	}
	return workloadclaims.HostExits{Hosts: hosts, OffLimits: offLimits}, nil
}

// requireOutsideCluster refuses an exit into this cluster's pod or Service
// ranges: a connection to a member leaves the pod through the mesh or not at
// all. A policy naming no ranges cannot show any exit stays outside them.
func (p meshPolicy) requireOutsideCluster(exits []exit) error {
	if len(p.ClusterRanges) == 0 {
		return errors.New("trusted mesh policy names no cluster ranges, so no exit can be shown to stay outside the cluster")
	}
	for _, e := range exits {
		for _, in := range p.ClusterRanges {
			if e.Range.IsValid() && e.Range.Overlaps(in) {
				return fmt.Errorf("exit %s port %d overlaps the cluster range %s", e.Range, e.Port, in)
			}
		}
	}
	return nil
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
		func() error { return state.requireRoleOnlyPod(launch) },
		func() error { return g.policy.requireRoleIdentity(ctr, launch.role) },
		func() error { return launch.requireNoNetworkChange() },
		func() error { return requirePrivatePIDNamespace(ctr) },
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
