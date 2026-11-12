package nriimagepolicy

import (
	"maps"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Sandbox policy modes (policy.sandbox). The policy is the fixed host-privilege
// floor applied to every container the measured boot allowlist does not admit.
type sandboxMode string

const (
	// SandboxOff does not observe host privilege at all.
	SandboxOff sandboxMode = "off"
	// SandboxAudit records the observation and admits.
	SandboxAudit sandboxMode = "audit"
	// SandboxEnforce denies a container carrying host privilege.
	SandboxEnforce sandboxMode = "enforce"
)

// privilegeSubject is what a host-privilege refusal names in the node's log and
// its audit record. A sandbox is refused before it has a container or an image.
type privilegeSubject struct {
	rule                             string
	namespace, pod, container, image string
}

func sandboxSubject(rule string, pod *api.PodSandbox) privilegeSubject {
	return privilegeSubject{rule: rule, namespace: pod.GetNamespace(), pod: pod.GetName()}
}

func containerSubject(rule string, pod *api.PodSandbox, ctr *api.Container, imageRef string) privilegeSubject {
	return privilegeSubject{
		rule:      rule,
		namespace: pod.GetNamespace(),
		pod:       pod.GetName(),
		container: ctr.GetName(),
		image:     imageRef,
	}
}

func (s privilegeSubject) logAttrs() []any {
	return []any{
		"rule", s.rule,
		"namespace", s.namespace,
		"pod", s.pod,
		"container", s.container,
		"image", s.image,
	}
}

// denyPrivilege records a refusal the node enforces.
func (p *plugin) denyPrivilege(subject privilegeSubject, refusal error) {
	p.logger.Warn("refusing host privilege outside what an allowlist entry declares",
		append(subject.logAttrs(), "error", refusal)...)
	p.audit.Log(audit.Event{
		Action:    "deny",
		Reason:    subject.rule,
		Namespace: subject.namespace,
		Pod:       subject.pod,
		Container: subject.container,
		Image:     subject.image,
		Error:     refusal.Error(),
	})
}

// auditPrivilege records host privilege the sandbox policy's audit mode admits.
func (p *plugin) auditPrivilege(subject privilegeSubject, refusal error) {
	p.logger.Warn("admitting host privilege outside what an allowlist entry declares",
		append(subject.logAttrs(), "sandbox", SandboxAudit, "error", refusal)...)
	p.audit.Log(audit.Event{
		Action:    "allow",
		Reason:    subject.rule,
		Overrides: refusal.Error(),
		Namespace: subject.namespace,
		Pod:       subject.pod,
		Container: subject.container,
		Image:     subject.image,
	})
}

// sandboxNamespaces are the pod-sandbox namespaces whose ABSENCE from the
// sandbox OCI spec means the pod shares the node's own. containerd removes the
// entry rather than pointing it at the host: hostNetwork drops network and uts,
// hostPID drops pid, hostIPC drops ipc (containerd
// internal/cri/server/podsandbox/sandbox_run_linux.go). The container's own
// namespace list is no evidence — containerd always points it at
// /proc/<sandbox pid>/ns/*, which is the host's when the sandbox is
// (internal/cri/opts/spec_opts.go, WithPodNamespaces).
var sandboxNamespaces = []string{"ipc", "network", "pid", "uts"}

// pidNamespace is the namespace type a member pod's container must hold on
// its own (requirePrivatePIDNamespace).
const pidNamespace = "pid"

// networkNamespace is the namespace type a pod on its own network holds.
const networkNamespace = "network"

// cgroupNamespace is present on every container containerd creates under
// unified cgroups and omitted for a privileged one
// (internal/cri/server/container_create.go). NRI carries no privileged flag, so
// this and writable sysfs/cgroupfs are the evidence there is.
const cgroupNamespace = "cgroup"

// kernelFSTypes are the filesystem types oci.WithPrivileged rewrites from ro to
// rw (containerd pkg/oci/spec_opts.go, WithWriteableSysfs and
// WithWriteableCgroupfs).
var kernelFSTypes = []string{"sysfs", "cgroup"}

// sandboxObservation is the host-privilege surface of one container as NRI
// reports it on the persisted OCI spec. A denial logs the whole struct, so a reviewer
// can complete a node-TCB rule from the record rather than from a re-run.
//
// What NRI v0.12.3 does NOT carry is listed in
// docs/allowlist-and-capabilities.md: the privileged flag, no_new_privs,
// masked and readonly paths, and the AppArmor profile are all in the OCI spec
// containerd generates but absent from api.LinuxContainer, so this policy
// infers privilege instead of reading it.
type sandboxObservation struct {
	// PodNamespaces is the sandbox's OCI namespace types.
	PodNamespaces []string
	// CtrNamespaces is the container's own OCI namespace types.
	CtrNamespaces []string
	// HostBinds is every bind source the pod does not own.
	HostBinds []string
	// WritableKernelFS is the destinations of sysfs/cgroup mounts without ro.
	WritableKernelFS []string
	// Devices is the container's explicit device nodes.
	Devices []string
	// CDIDevices is the CDI devices containerd injected through the CRI field,
	// less those the node's trusted CDI specs expanded.
	CDIDevices []string
	// CDIExpanded is the trusted CDI devices whose device nodes, hooks and
	// bind mounts are set aside (cdi.go).
	CDIExpanded []string
	// Hooks is the OCI hook stages the spec populates.
	Hooks []string
	// NetDevices is host network interfaces moved into the container.
	NetDevices []string
	// Sysctls is the container's own sysctl settings.
	Sysctls []string
	// Seccomp is the spec's seccomp default action, or "none" when the
	// container runs unfiltered. Judged in the pod role only (violations): a
	// node's own pods may run unfiltered under the node TCB, a pod CVM's
	// kubelet applies the runtime default and the floor refuses an opt-out.
	Seccomp string
}

// hostBindGrant reports whether an allowlist declaration hands this launch the
// bind m is evidence of; it answers only for the mounts slice it was built from.
type hostBindGrant interface {
	grants(m allowlist.ObservedMount) bool
}

// declaredBindGrant hands a launch the binds an allowlist entry declares for it.
type declaredBindGrant struct {
	policy *policyStore
	launch allowlist.RunningContainer
}

func (g declaredBindGrant) grants(m allowlist.ObservedMount) bool {
	return g.policy.grantsHostBind(g.launch, m)
}

// noBindGrant hands a launch no bind.
type noBindGrant struct{}

func (noBindGrant) grants(allowlist.ObservedMount) bool { return false }

// observeSandbox reads the host-privilege surface out of the NRI view. A field
// the runtime did not fill reads as absent, which violations() treats as a
// violation rather than as consent.
//
// own names the binds this plugin adds itself (sidecarAdjustment); the policy
// put them there, so it does not hold them against a container. mounts is the
// container's mount evidence, as mountObserver.Observe returns it. A bind whose
// evidence grant accepts is one an allowlist entry hands this launch, so it is
// not a host bind either. The device nodes, hooks and binds cdi expanded are
// not observed.
func observeSandbox(pod *api.PodSandbox, ctr *api.Container, own enforcerMounts, mounts []allowlist.ObservedMount, grant hostBindGrant, cdi cdiExpansion) sandboxObservation {
	obs := sandboxObservation{
		PodNamespaces:    namespaceTypes(pod.GetLinux().GetNamespaces()),
		CtrNamespaces:    namespaceTypes(ctr.GetLinux().GetNamespaces()),
		HostBinds:        hostBinds(pod, ctr, own, mounts, grant, cdi),
		WritableKernelFS: writableKernelFS(ctr),
		Hooks:            hookStages(ctr.GetHooks(), cdi),
		Sysctls:          slices.Sorted(maps.Keys(ctr.GetLinux().GetSysctl())),
		NetDevices:       slices.Sorted(maps.Keys(ctr.GetLinux().GetNetDevices())),
		CDIExpanded:      cdi.names,
		Seccomp:          "none",
	}
	for _, d := range ctr.GetLinux().GetDevices() {
		if !slices.Contains(cdi.devices, d.GetPath()) {
			obs.Devices = append(obs.Devices, d.GetPath())
		}
	}
	for _, d := range ctr.GetCDIDevices() {
		if !slices.Contains(cdi.names, d.GetName()) {
			obs.CDIDevices = append(obs.CDIDevices, d.GetName())
		}
	}
	if s := ctr.GetLinux().GetSeccompPolicy(); s != nil {
		obs.Seccomp = s.GetDefaultAction()
	}
	return obs
}

// violations names every way the observation leaves the sandbox. An empty
// result is the only admission. requiresSeccompFilter adds the pod CVM floor:
// a container whose seccomp profile does not deny by default.
func (o sandboxObservation) violations(requiresSeccompFilter bool) []string {
	var out []string
	for _, ns := range sandboxNamespaces {
		if !slices.Contains(o.PodNamespaces, ns) {
			out = append(out, "host "+ns+" namespace")
		}
	}
	if !slices.Contains(o.CtrNamespaces, cgroupNamespace) {
		out = append(out, "no cgroup namespace (privileged container)")
	}
	if len(o.WritableKernelFS) > 0 {
		out = append(out, "writable sysfs or cgroupfs (privileged container)")
	}
	if len(o.HostBinds) > 0 {
		out = append(out, "host path bind mount")
	}
	if len(o.Devices) > 0 {
		out = append(out, "host device node")
	}
	if len(o.CDIDevices) > 0 {
		out = append(out, "CDI device injection")
	}
	if len(o.Hooks) > 0 {
		out = append(out, "OCI hook")
	}
	if len(o.NetDevices) > 0 {
		out = append(out, "host network device")
	}
	if len(o.Sysctls) > 0 {
		out = append(out, "container sysctl")
	}
	if requiresSeccompFilter && !slices.Contains(denyingSeccompActions, o.Seccomp) {
		out = append(out, "unfiltered seccomp")
	}
	return out
}

// denyingSeccompActions are the default actions under which a syscall the
// profile does not list fails. Any other default, including a missing
// profile, lets every syscall through and is unfiltered.
var denyingSeccompActions = []string{"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP"}

// logAttrs renders the observation as slog key/value pairs.
func (o sandboxObservation) logAttrs() []any {
	return []any{
		"pod_namespaces", o.PodNamespaces,
		"container_namespaces", o.CtrNamespaces,
		"host_binds", o.HostBinds,
		"writable_kernel_fs", o.WritableKernelFS,
		"devices", o.Devices,
		"cdi_devices", o.CDIDevices,
		"cdi_expanded", o.CDIExpanded,
		"hooks", o.Hooks,
		"net_devices", o.NetDevices,
		"sysctls", o.Sysctls,
		"seccomp", o.Seccomp,
	}
}

func namespaceTypes(nss []*api.LinuxNamespace) []string {
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		out = append(out, ns.GetType())
	}
	return out
}

// nodeNetwork reports whether the pod shares the node's network namespace, read
// from the absence of the sandbox's own entry as violations() reads it.
func nodeNetwork(pod *api.PodSandbox) bool {
	return !slices.Contains(namespaceTypes(pod.GetLinux().GetNamespaces()), networkNamespace)
}

// hostBinds returns the bind sources the pod does not own. A bind mount is one
// whose source is an absolute path; the rest name a filesystem type and carry
// nothing in. Every mount the kubelet and containerd stage for a pod lives
// under the pod's kubelet directory (/var/lib/kubelet/pods/<uid>/) or its
// containerd sandbox directory (resolv.conf, hostname and shm), so a source
// under neither is a hostPath — or another pod's directory.
//
// Ownership is a clean-path prefix, as in mounts.go: the control plane picks
// the pod UID, so a UID appearing anywhere in the source proves nothing, and an
// uncleaned source would let `<uid>/..` name the parent. A pod with neither
// identifier is unidentifiable, and every bind is then foreign.
func hostBinds(pod *api.PodSandbox, ctr *api.Container, own enforcerMounts, mounts []allowlist.ObservedMount, grant hostBindGrant, cdi cdiExpansion) []string {
	var owned []string
	if uid := pod.GetUid(); uid != "" {
		owned = append(owned, kubeletRoot+"/pods/"+uid+"/")
	}
	if id := pod.GetId(); id != "" {
		for _, root := range containerdRoots {
			owned = append(owned, root+"/io.containerd.grpc.v1.cri/sandboxes/"+id+"/")
		}
	}
	var out []string
	for _, m := range ctr.GetMounts() {
		src := m.GetSource()
		if !strings.HasPrefix(src, "/") {
			continue
		}
		if cleanAbsolute(src) && slices.ContainsFunc(owned, func(dir string) bool { return strings.HasPrefix(src, dir) }) {
			continue
		}
		if isInjectedNodeMount(pod, ctr, m, own) || cdi.mount(m) {
			continue
		}
		if grantsBind(src, m.GetDestination(), mounts, grant) {
			continue
		}
		out = append(out, src)
	}
	return out
}

// grantsBind reports whether mounts holds evidence for source at destination
// and grant accepts all of it. Keying on the pair, not on the position, keeps
// a duplicate bind with weaker evidence from riding on a granted one.
func grantsBind(source, destination string, mounts []allowlist.ObservedMount, grant hostBindGrant) bool {
	found := false
	for _, m := range mounts {
		if m.Source != source || m.Destination != destination {
			continue
		}
		if !grant.grants(m) {
			return false
		}
		found = true
	}
	return found
}

// enforcerMounts names the sources this enforcer binds into a container itself.
type enforcerMounts struct {
	socketDir      string
	cdsPins        string
	cdsAddress     string
	clientDocument string
}

// takesNodeMount reports whether ctr takes the node's own bind at destination:
// the one rule credentialMounts adds by and isInjectedNodeMount accepts by.
func takesNodeMount(pod *api.PodSandbox, ctr *api.Container, destination string) bool {
	injected := injectedCredentialSidecar(pod, ctr)
	switch destination {
	case workloadclaims.SidecarSocketDir:
		return injected
	case workloadclaims.CDSPinsPath:
		return injected || holdsCredentialsIdentity(ctr)
	case workloadclaims.RouterCDSPinsPath:
		return fetchesRouteManifest(pod, ctr)
	case workloadclaims.CDSAddressPath:
		return injected || holdsCredentialsIdentity(ctr) || fetchesRouteManifest(pod, ctr)
	case workloadclaims.ClientDocumentPath:
		// Only a Pod CVM with a client document has a source for it.
		return true
	}
	return false
}

// isInjectedNodeMount requires a credential client's read-only bind from the node's own source.
func isInjectedNodeMount(pod *api.PodSandbox, ctr *api.Container, m *api.Mount, own enforcerMounts) bool {
	source := map[string]string{
		workloadclaims.SidecarSocketDir:   own.socketDir,
		workloadclaims.CDSPinsPath:        own.cdsPins,
		workloadclaims.RouterCDSPinsPath:  own.cdsPins,
		workloadclaims.CDSAddressPath:     own.cdsAddress,
		workloadclaims.ClientDocumentPath: own.clientDocument,
	}[m.GetDestination()]
	return source != "" && m.GetSource() == source && endsReadOnly(m) && takesNodeMount(pod, ctr, m.GetDestination())
}

// endsReadOnly reports whether m is read-only once runc has applied its
// options: the last "ro" or "rw" wins, and "rrw" (a recursive setattr applied
// after the mount) leaves it writable whatever came before. "rro" alone is
// not taken as read-only, so a caller fails closed on it.
func endsReadOnly(m *api.Mount) bool {
	readOnly := false
	for _, option := range m.GetOptions() {
		switch option {
		case "ro":
			readOnly = true
		case "rw":
			readOnly = false
		case "rrw":
			return false
		}
	}
	return readOnly
}

// writableKernelFS returns the destinations of sysfs and cgroup mounts that are
// not read-only.
func writableKernelFS(ctr *api.Container) []string {
	var out []string
	for _, m := range ctr.GetMounts() {
		if !slices.Contains(kernelFSTypes, m.GetType()) {
			continue
		}
		if !endsReadOnly(m) {
			out = append(out, m.GetDestination())
		}
	}
	return out
}

// hookStages names the OCI hook stages that hold a hook cdi did not expand. A
// hook names code outside the reviewed image and entrypoint, so any such stage
// is a violation.
func hookStages(h *api.Hooks, cdi cdiExpansion) []string {
	stages := []struct {
		name  string
		hooks []*api.Hook
	}{
		{"prestart", h.GetPrestart()},
		{"createRuntime", h.GetCreateRuntime()},
		{"createContainer", h.GetCreateContainer()},
		{"startContainer", h.GetStartContainer()},
		{"poststart", h.GetPoststart()},
		{"poststop", h.GetPoststop()},
	}
	var out []string
	for _, s := range stages {
		if slices.ContainsFunc(s.hooks, func(hook *api.Hook) bool { return !cdi.hook(s.name, hook) }) {
			out = append(out, s.name)
		}
	}
	return out
}
