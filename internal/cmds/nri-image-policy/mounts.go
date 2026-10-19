package nriimagepolicy

import (
	"path"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const (
	kubeletRoot               = "/var/lib/kubelet"
	emptyDirPlugin            = "kubernetes.io~empty-dir"
	projectedPlugin           = "kubernetes.io~projected"
	serviceAccountDestination = "/var/run/secrets/kubernetes.io/serviceaccount"
)

var containerdRoots = []string{
	"/var/lib/containerd",
	"/run/containerd",
	"/var/lib/rancher/rke2/agent/containerd",
	"/run/k3s/containerd",
}

// MountContext binds path-shaped runtime evidence to the object currently
// being admitted. Handlers must compare these identifiers exactly; a path that
// merely looks like kubelet or containerd state is untrusted.
type MountContext struct {
	PodUID    string
	SandboxID string
	Pod       *api.PodSandbox
	Container *api.Container
	Storage   mountStorageInspector
	// SocketDir is the inventory socket directory this plugin bind-mounts into
	// an injected pod's socket consumers itself; empty when the inventory is
	// disabled.
	SocketDir string
}

func (c MountContext) valid() bool {
	return c.PodUID != "" && c.SandboxID != "" && c.Container != nil && c.Container.GetPodSandboxId() == c.SandboxID
}

type mountHandler interface {
	Observe(MountContext, *api.Mount) (allowlist.ObservedMount, bool)
}

// mountObserver applies handlers in order. Each handler owns a disjoint,
// readable piece of the node's mount contract; unmatched mounts are host-backed.
type mountObserver struct {
	handlers  []mountHandler
	storage   mountStorageInspector
	socketDir string
}

func newMountObserver(storage mountStorageInspector, socketDir string) mountObserver {
	return mountObserver{storage: defaultStorage(storage), socketDir: socketDir, handlers: []mountHandler{
		injectedSocketMountHandler{},
		platformMountHandler{},
		emptyDirMountHandler{},
		kubeletDataMountHandler{},
		kubeletSubpathHandler{},
	}}
}

func (o mountObserver) Observe(pod *api.PodSandbox, ctr *api.Container) []allowlist.ObservedMount {
	ctx := MountContext{PodUID: pod.GetUid(), SandboxID: pod.GetId(), Pod: pod, Container: ctr, Storage: o.storage, SocketDir: o.socketDir}
	out := make([]allowlist.ObservedMount, 0, len(ctr.GetMounts()))
	for _, m := range ctr.GetMounts() {
		if carriesHostBytes(m) {
			out = append(out, o.observeMount(ctx, m))
		}
	}
	return out
}

func carriesHostBytes(m *api.Mount) bool {
	return m != nil && (path.IsAbs(m.GetSource()) || isBindMount(m))
}

func isBindMount(m *api.Mount) bool {
	return m.GetType() == "bind" || slices.Contains(m.GetOptions(), "bind") || slices.Contains(m.GetOptions(), "rbind")
}

// bindOptions are the mount options that leave a bind's bytes coming from its
// source. Anything else, such as an overlay's lowerdir, fails closed.
var bindOptions = []string{"bind", "rbind", "ro", "rw", "nosuid", "nodev", "noexec", "private", "rprivate", "slave", "rslave", "shared", "rshared"}

// fileBind reports whether m binds its source unchanged, the only mount whose
// bytes provenance evidence about the source describes.
func fileBind(m *api.Mount) bool {
	if m == nil || !slices.Contains([]string{"bind", "none", ""}, m.GetType()) || !isBindMount(m) {
		return false
	}
	for _, option := range m.GetOptions() {
		if !slices.Contains(bindOptions, option) {
			return false
		}
	}
	return true
}

func (o mountObserver) observeMount(ctx MountContext, m *api.Mount) allowlist.ObservedMount {
	if mount, ok := verifiedHostMount(ctx, m); ok {
		return mount
	}
	for _, handler := range o.handlers {
		if mount, ok := handler.Observe(ctx, m); ok {
			return mount
		}
	}
	return observeHostMount(m)
}

func defaultStorage(s mountStorageInspector) mountStorageInspector {
	if s != nil {
		return s
	}
	return newMountStorageInspector()
}

// injectedSocketMountHandler classifies the inventory socket directory this
// plugin bind-mounts itself (socketDirAdjustment) as a platform mount. The
// policy put it there, read-only, so no entry pins it: a host rule for it would
// refuse every secrets grant (allowlist.Workload.PinnedForGrant), and hostBinds
// already excuses the same bind. The source must be this plugin's own
// directory; a tenant bind at the same destination stays a host mount.
type injectedSocketMountHandler struct{}

func (injectedSocketMountHandler) Observe(ctx MountContext, m *api.Mount) (allowlist.ObservedMount, bool) {
	if ctx.SocketDir == "" || !ctx.valid() || m.GetSource() != ctx.SocketDir || !isInjectedSocketMount(ctx.Pod, ctx.Container, m) {
		return allowlist.ObservedMount{}, false
	}
	mount := observed(m, allowlist.MountPlatform, allowlist.MountUnknown)
	mount.ReadOnly = true
	return mount, true
}

type platformMountHandler struct{}

func (platformMountHandler) Observe(ctx MountContext, m *api.Mount) (allowlist.ObservedMount, bool) {
	src, dst := m.GetSource(), m.GetDestination()
	if !ctx.valid() || !cleanAbsolute(src) || !cleanAbsolute(dst) {
		return allowlist.ObservedMount{}, false
	}
	valid := false
	switch dst {
	case "/etc/hosts":
		valid = src == kubeletRoot+"/pods/"+ctx.PodUID+"/etc-hosts"
	case "/dev/termination-log":
		prefix := kubeletRoot + "/pods/" + ctx.PodUID + "/containers/" + ctx.Container.GetName() + "/"
		valid = strings.HasPrefix(src, prefix) && !strings.Contains(strings.TrimPrefix(src, prefix), "/")
	case "/etc/hostname", "/etc/resolv.conf", "/dev/shm":
		leaf := strings.TrimPrefix(dst, "/etc/")
		if dst == "/dev/shm" {
			leaf = "shm"
		}
		valid = containerdSandboxSource(src, ctx.SandboxID, leaf)
	case serviceAccountDestination:
		prefix := kubeletRoot + "/pods/" + ctx.PodUID + "/volumes/" + projectedPlugin + "/kube-api-access-"
		valid = strings.HasPrefix(src, prefix) && !strings.Contains(strings.TrimPrefix(src, prefix), "/")
	}
	if !valid {
		return allowlist.ObservedMount{}, false
	}
	return observed(m, allowlist.MountPlatform, allowlist.MountUnknown), true
}

func containerdSandboxSource(source, sandboxID, leaf string) bool {
	return sandboxID != "" && slices.ContainsFunc(containerdRoots, func(root string) bool {
		return source == root+"/io.containerd.grpc.v1.cri/sandboxes/"+sandboxID+"/"+leaf
	})
}

type emptyDirMountHandler struct{}

func (emptyDirMountHandler) Observe(ctx MountContext, m *api.Mount) (allowlist.ObservedMount, bool) {
	plugin, volumePath, ok := currentPodVolume(ctx, m)
	if !ok || plugin != emptyDirPlugin {
		return allowlist.ObservedMount{}, false
	}
	class := allowlist.MountEmptyDir
	if strings.HasPrefix(volumePath, volume.KubeVolumePrefix) {
		// Volumed fills these reserved placeholders with operator-supplied
		// data. Classify them before that mount propagates into the pod, too.
		class = allowlist.MountData
	}
	return observed(m, class, ctx.Storage.Inspect(m.GetSource())), true
}

type kubeletDataMountHandler struct{}

func (kubeletDataMountHandler) Observe(ctx MountContext, m *api.Mount) (allowlist.ObservedMount, bool) {
	plugin, _, ok := currentPodVolume(ctx, m)
	if !ok || plugin == emptyDirPlugin {
		return allowlist.ObservedMount{}, false
	}
	return observed(m, allowlist.MountData, ctx.Storage.Inspect(m.GetSource())), true
}

func currentPodVolume(ctx MountContext, m *api.Mount) (plugin, volumePath string, ok bool) {
	src := m.GetSource()
	if !ctx.valid() || !cleanAbsolute(src) || !cleanAbsolute(m.GetDestination()) {
		return "", "", false
	}
	prefix := kubeletRoot + "/pods/" + ctx.PodUID + "/volumes/"
	rest, ok := strings.CutPrefix(src, prefix)
	if !ok {
		return "", "", false
	}
	return cutTwoOrMore(rest)
}

type kubeletSubpathHandler struct{}

func (kubeletSubpathHandler) Observe(ctx MountContext, m *api.Mount) (allowlist.ObservedMount, bool) {
	src := m.GetSource()
	if !ctx.valid() || !cleanAbsolute(src) || !cleanAbsolute(m.GetDestination()) {
		return allowlist.ObservedMount{}, false
	}
	prefix := kubeletRoot + "/pods/" + ctx.PodUID + "/volume-subpaths/"
	rest, ok := strings.CutPrefix(src, prefix)
	if !ok {
		return allowlist.ObservedMount{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] != ctx.Container.GetName() || parts[2] == "" {
		return allowlist.ObservedMount{}, false
	}
	return observed(m, allowlist.MountData, ctx.Storage.Inspect(src)), true
}

func cutTwoOrMore(s string) (string, string, bool) {
	a, b, ok := strings.Cut(s, "/")
	return a, b, ok && a != "" && b != ""
}

// nodeRootEvidence is replaced in tests, which cannot boot from a measured root.
var nodeRootEvidence = nodeRootFile

// nodeRootUnavailableReason is replaced in tests, as nodeRootEvidence is.
var nodeRootUnavailableReason = nodeRootUnavailable

// nodeRootBindIneligible is why a bind lacks provenance on a measured root:
// observeHostMount withholds it from anything but a plain read-only bind of a
// regular file reached without symlinks or crossing mounts.
const nodeRootBindIneligible = "source is not a plain read-only bind of a regular file on the measured root"

// nodeRootMissing explains why a read-only host bind in mounts carries no
// node-root provenance, so a denial of a nodeRootFile rule names its cause. It
// returns "" when there is no such bind.
func nodeRootMissing(mounts []allowlist.ObservedMount) string {
	if !slices.ContainsFunc(mounts, unprovenFileBind) {
		return ""
	}
	if reason, _ := nodeRootUnavailableReason(); reason != "" {
		return reason
	}
	return nodeRootBindIneligible
}

// fsVerityNotStaged is why a read-only host bind carries no fs-verity evidence.
const fsVerityNotStaged = "mount was not staged at create time; the container's fs-verity staging warnings name the cause"

// unprovenFileBind reports whether m is a read-only host bind that carries no
// provenance, so a denial of a verified-file rule names its cause.
func unprovenFileBind(m allowlist.ObservedMount) bool {
	return m.Class == allowlist.MountHost && m.ReadOnly && m.HostSourceDigest != "" && m.Provenance == ""
}

func observeHostMount(m *api.Mount) allowlist.ObservedMount {
	mount := observed(m, allowlist.MountHost, allowlist.MountUnknown)
	for _, option := range m.GetOptions() {
		switch option {
		case "ro":
			mount.ReadOnly = true
		case "rw":
			mount.ReadOnly = false
		case "rro", "rrw":
			return mount
		}
	}
	digest, err := allowlist.HostSourceDigest(m.GetSource())
	if err != nil {
		return mount
	}
	mount.HostSourceDigest = digest
	if mount.ReadOnly && fileBind(m) && nodeRootEvidence(m.GetSource()) {
		mount.Provenance = allowlist.ProvenanceNodeRoot
	}
	return mount
}

func observed(m *api.Mount, class allowlist.MountClass, storage allowlist.MountStorage) allowlist.ObservedMount {
	return allowlist.ObservedMount{Destination: m.GetDestination(), Source: m.GetSource(), Class: class, Storage: storage}
}

func cleanAbsolute(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p
}
