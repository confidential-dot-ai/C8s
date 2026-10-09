package nriimagepolicy

import (
	"maps"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"

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
// docs/allowlist-and-capabilities.md: Linux capabilities, the privileged flag,
// no_new_privs, masked and readonly paths, and the AppArmor profile are all in
// the OCI spec containerd generates but absent from api.LinuxContainer, so this
// policy infers privilege instead of reading it.
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
	// CDIDevices is the CDI devices containerd injected.
	CDIDevices []string
	// Hooks is the OCI hook stages the spec populates.
	Hooks []string
	// NetDevices is host network interfaces moved into the container.
	NetDevices []string
	// Sysctls is the container's own sysctl settings.
	Sysctls []string
	// Seccomp is the spec's seccomp default action, or "none" when the
	// container runs unfiltered. Observed, not judged — see the doc.
	Seccomp string
}

// observeSandbox reads the host-privilege surface out of the NRI view. A field
// the runtime did not fill reads as absent, which violations() treats as a
// violation rather than as consent.
//
// own names the binds this plugin adds itself (sidecarAdjustment); they are
// the host binds the policy does not hold against a container, because the
// policy put them there.
func observeSandbox(pod *api.PodSandbox, ctr *api.Container, own nodeMounts) sandboxObservation {
	obs := sandboxObservation{
		PodNamespaces:    namespaceTypes(pod.GetLinux().GetNamespaces()),
		CtrNamespaces:    namespaceTypes(ctr.GetLinux().GetNamespaces()),
		HostBinds:        hostBinds(pod, ctr, own),
		WritableKernelFS: writableKernelFS(ctr),
		Hooks:            hookStages(ctr.GetHooks()),
		Sysctls:          slices.Sorted(maps.Keys(ctr.GetLinux().GetSysctl())),
		NetDevices:       slices.Sorted(maps.Keys(ctr.GetLinux().GetNetDevices())),
		Seccomp:          "none",
	}
	for _, d := range ctr.GetLinux().GetDevices() {
		obs.Devices = append(obs.Devices, d.GetPath())
	}
	for _, d := range ctr.GetCDIDevices() {
		obs.CDIDevices = append(obs.CDIDevices, d.GetName())
	}
	if s := ctr.GetLinux().GetSeccompPolicy(); s != nil {
		obs.Seccomp = s.GetDefaultAction()
	}
	return obs
}

// violations names every way the observation leaves the sandbox. An empty
// result is the only admission.
func (o sandboxObservation) violations() []string {
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
	return out
}

// logAttrs renders the observation as slog key/value pairs.
func (o sandboxObservation) logAttrs() []any {
	return []any{
		"pod_namespaces", o.PodNamespaces,
		"container_namespaces", o.CtrNamespaces,
		"host_binds", o.HostBinds,
		"writable_kernel_fs", o.WritableKernelFS,
		"devices", o.Devices,
		"cdi_devices", o.CDIDevices,
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
func hostBinds(pod *api.PodSandbox, ctr *api.Container, own nodeMounts) []string {
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
		if isInjectedNodeMount(pod, ctr, m, own) {
			continue
		}
		out = append(out, src)
	}
	return out
}

// nodeMounts are the sources this plugin bind-mounts into an injected
// credential sidecar, each at its own destination (sidecarAdjustment). An
// empty source means the plugin mounts nothing there.
type nodeMounts struct {
	socketDir  string
	cdsPins    string
	cdsAddress string
}

// isInjectedNodeMount reports whether m is one of the mounts sidecarAdjustment
// adds: read-only, from this plugin's own source, at that source's
// destination, in a sidecar of an injected pod. Anything else at those
// destinations is a host bind like any other — a foreign source would point the
// client at another node's CDS, and a writable one would let the container
// replace the sockets, the pins or the address it was given.
func isInjectedNodeMount(pod *api.PodSandbox, ctr *api.Container, m *api.Mount, own nodeMounts) bool {
	source := ""
	switch m.GetDestination() {
	case workloadclaims.SidecarSocketDir:
		source = own.socketDir
	case workloadclaims.CDSPinsPath:
		source = own.cdsPins
	case workloadclaims.CDSAddressPath:
		source = own.cdsAddress
	}
	return source != "" && m.GetSource() == source &&
		slices.Contains(m.GetOptions(), "ro") &&
		pod.GetAnnotations()[workloadclaims.AnnotationInjected] == "true" &&
		workloadclaims.IsSidecarContainer(ctr.GetName())
}

// writableKernelFS returns the destinations of sysfs and cgroup mounts that are
// not read-only.
func writableKernelFS(ctr *api.Container) []string {
	var out []string
	for _, m := range ctr.GetMounts() {
		if !slices.Contains(kernelFSTypes, m.GetType()) {
			continue
		}
		if !slices.Contains(m.GetOptions(), "ro") {
			out = append(out, m.GetDestination())
		}
	}
	return out
}

// hookStages names the OCI hook stages the spec populates. A hook names code
// outside the reviewed image and entrypoint, so any stage is a violation.
func hookStages(h *api.Hooks) []string {
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
		if len(s.hooks) > 0 {
			out = append(out, s.name)
		}
	}
	return out
}
