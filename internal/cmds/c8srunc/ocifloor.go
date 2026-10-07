package c8srunc

// The measured privilege floor for the containers of a member pod. The
// enforcer cannot see these privileges in the NRI view, so the wrapper reads
// the bundle containerd persisted and refuses the create, which is where they
// are granted (MM2, MM5, MP4). Why each one is refused: docs/node-exec-mode.md,
// "The privilege floor".

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

// The CRI annotations containerd writes into every container's OCI spec
// (containerd internal/cri/annotations).
const (
	annotationSandboxNamespace = "io.kubernetes.cri.sandbox-namespace"
	annotationSandboxID        = "io.kubernetes.cri.sandbox-id"
	annotationContainerType    = "io.kubernetes.cri.container-type"
	containerTypeSandbox       = "sandbox"
)

// workloadCapabilities is what a container outside every platform role may
// hold: the runtime's default set less NET_RAW, SETUID and SETGID, each of
// which defeats the pod ruleset.
var workloadCapabilities = []string{
	"CAP_AUDIT_WRITE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_MKNOD", "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETPCAP",
	"CAP_SYS_CHROOT",
}

// kernelFSTypes are the filesystem types a privileged container is given
// writable (containerd pkg/oci, WithWriteableSysfs and WithWriteableCgroupfs).
var kernelFSTypes = []string{"sysfs", "cgroup", "cgroup2"}

// requireFloor refuses a bundle that would start a container of a member pod
// with privileges the pod's protection cannot survive. A role's container
// holds at most the capabilities trusted policy binds to it; the mesh
// endpoint holds none, because the enforcer installs the ruleset for it.
func requireFloor(spec *specs.Spec, containerID string, stdin *os.File, floor nriimagepolicy.MeshFloor) error {
	if !floorApplies(spec, containerID, floor) {
		return nil
	}
	if err := floorChecks(spec, stdin, floor); err != nil {
		return fmt.Errorf("the measured privilege floor refuses this container: %w", err)
	}
	return nil
}

func floorChecks(spec *specs.Spec, stdin *os.File, floor nriimagepolicy.MeshFloor) error {
	if spec.Process == nil || spec.Linux == nil {
		return errors.New("the bundle describes no Linux process to confine")
	}
	user := spec.Process.User
	allowed, role := workloadCapabilities, ""
	if bound, reserved := floor.ReservedIDs[user.UID]; reserved {
		allowed, role = bound.Capabilities, bound.Name
	}
	if err := requireFloorCapabilities(spec.Process.Capabilities, allowed); err != nil {
		return err
	}
	if err := requireNoNewPrivileges(spec.Process); err != nil {
		return err
	}
	if err := requireUnprivileged(spec); err != nil {
		return err
	}
	if err := requireOwnNamespaces(spec.Linux); err != nil {
		return err
	}
	if err := requireUnreservedIdentity(user, floor, role); err != nil {
		return err
	}
	if err := requireNoTerminal(spec.Process); err != nil {
		return err
	}
	return requireNoStdin(stdin)
}

// floorApplies reports a container the floor covers: a pod container — not the
// sandbox the runtime creates for the pod itself — in a namespace trusted
// policy does not exempt. A bundle that names no namespace is covered: the
// floor follows what the node measured, not what a bundle leaves out.
func floorApplies(spec *specs.Spec, containerID string, floor nriimagepolicy.MeshFloor) bool {
	if isPodSandbox(spec, containerID) {
		return false
	}
	return !slices.Contains(floor.ExemptNamespaces, spec.Annotations[annotationSandboxNamespace])
}

// isPodSandbox reports the one container the runtime creates for the pod
// itself, which keeps the privileges the runtime gives it. The claimed type
// alone would be forgeable; a sandbox is also the container whose own id is
// the sandbox's, which no other bundle can say of itself.
func isPodSandbox(spec *specs.Spec, containerID string) bool {
	sandboxID := spec.Annotations[annotationSandboxID]
	return spec.Annotations[annotationContainerType] == containerTypeSandbox &&
		sandboxID != "" && sandboxID == containerID
}

// requireFloorCapabilities refuses a capability outside the floor in any of
// the five sets: one in the bounding set is one an exec can still take. A
// bundle that names no sets at all is refused rather than read as none.
func requireFloorCapabilities(held *specs.LinuxCapabilities, allowed []string) error {
	if held == nil {
		return errors.New("the bundle names no capability sets")
	}
	for _, set := range []struct {
		name string
		caps []string
	}{
		{"bounding", held.Bounding}, {"effective", held.Effective}, {"permitted", held.Permitted},
		{"inheritable", held.Inheritable}, {"ambient", held.Ambient},
	} {
		for _, capability := range set.caps {
			if !slices.Contains(allowed, capability) {
				return fmt.Errorf("%s capability %s is outside the floor", set.name, capability)
			}
		}
	}
	return nil
}

// requireNoNewPrivileges requires the bit that bounds what an execve inside
// the container can add to what the floor just allowed.
func requireNoNewPrivileges(process *specs.Process) error {
	if !process.NoNewPrivileges {
		return errors.New("no_new_privs is not set")
	}
	return nil
}

// requireUnprivileged refuses what containerd writes for a privileged
// container, read from the bundle rather than inferred from the pod spec: a
// device cgroup rule that allows every device, no masked or read-only kernel
// paths, and a writable sysfs or cgroupfs.
func requireUnprivileged(spec *specs.Spec) error {
	if spec.Linux.Resources == nil {
		return errors.New("the bundle sets no device cgroup")
	}
	if slices.ContainsFunc(spec.Linux.Resources.Devices, allowsEveryDevice) {
		return errors.New("the device cgroup allows every device")
	}
	if len(spec.Linux.MaskedPaths) == 0 || len(spec.Linux.ReadonlyPaths) == 0 {
		return errors.New("the bundle masks no kernel paths of /proc")
	}
	for _, mount := range spec.Mounts {
		if slices.Contains(kernelFSTypes, mount.Type) && writable(mount.Options) {
			return fmt.Errorf("%s is mounted writable at %s", mount.Type, mount.Destination)
		}
	}
	return nil
}

// allowsEveryDevice matches the one rule a privileged container is given: the
// default rules allow a type with a major and minor number, or mknod alone.
func allowsEveryDevice(rule specs.LinuxDeviceCgroup) bool {
	return rule.Allow && rule.Major == nil && rule.Minor == nil &&
		(rule.Type == "" || rule.Type == "a") && strings.Contains(rule.Access, "w")
}

// writable reports a mount the container may write to. The last of the
// read-only and read-write options wins, as it does in the kernel.
func writable(options []string) bool {
	readOnly := false
	for _, option := range options {
		switch option {
		case "ro", "rro":
			readOnly = true
		case "rw", "rrw":
			readOnly = false
		}
	}
	return !readOnly
}

// requireOwnNamespaces requires the container's ids to be the node's own and
// its PID namespace to be its own: neither the node's nor a shared one.
func requireOwnNamespaces(linux *specs.Linux) error {
	mapped := len(linux.UIDMappings) > 0 || len(linux.GIDMappings) > 0
	if mapped || hasNamespace(linux, specs.UserNamespace) {
		return errors.New("the container maps ids into a user namespace of its own")
	}
	if !hasNamespace(linux, specs.PIDNamespace) {
		return errors.New("the container has no PID namespace entry, so it runs in the node's")
	}
	if shared := joinedNamespace(linux, specs.PIDNamespace); shared != "" {
		return fmt.Errorf("the container joins the PID namespace at %s", shared)
	}
	return nil
}

func hasNamespace(linux *specs.Linux, kind specs.LinuxNamespaceType) bool {
	return slices.ContainsFunc(linux.Namespaces, func(ns specs.LinuxNamespace) bool { return ns.Type == kind })
}

// joinedNamespace is the path of a namespace the container joins rather than
// gets of its own, and empty when it has its own.
func joinedNamespace(linux *specs.Linux, kind specs.LinuxNamespaceType) string {
	i := slices.IndexFunc(linux.Namespaces, func(ns specs.LinuxNamespace) bool {
		return ns.Type == kind && ns.Path != ""
	})
	if i < 0 {
		return ""
	}
	return linux.Namespaces[i].Path
}

// requireUnreservedIdentity requires a container outside every role to run as
// a non-root user, and every container to claim no id reserved for another
// role: trusted policy reserves the number as both a UID and a GID.
func requireUnreservedIdentity(user specs.User, floor nriimagepolicy.MeshFloor, role string) error {
	if role == "" && user.UID == 0 {
		return errors.New("a container outside every platform role runs as root")
	}
	for _, id := range append([]uint32{user.GID}, user.AdditionalGids...) {
		if owner, reserved := floor.ReservedIDs[id]; reserved && owner.Name != role {
			return fmt.Errorf("gid %d is reserved for the %s role", id, owner.Name)
		}
	}
	return nil
}

// requireNoTerminal refuses a terminal, which is half of what an attach
// session would write into (MP4).
func requireNoTerminal(process *specs.Process) error {
	if process.Terminal {
		return errors.New("the container asks for a terminal")
	}
	return nil
}

// requireNoStdin refuses a create whose own standard input is a pipe, which
// is the other half (MP4). The shim gives runc the container's stdin pipe only
// for a container asked to keep stdin open (containerd
// cmd/containerd-shim-runc-v2 createIO and withConditionalIO, go-runc
// pipeIO.Set and nullIO.Set).
func requireNoStdin(stdin *os.File) error {
	if stdin == nil {
		return nil
	}
	described, err := stdin.Stat()
	if err != nil {
		return fmt.Errorf("describe the create's standard input: %w", err)
	}
	if described.Mode()&os.ModeNamedPipe != 0 {
		return errors.New("the create carries the container's standard input")
	}
	return nil
}

// createVerbs start a container from a bundle: the floor reads that bundle's
// OCI configuration before either verb reaches the real runtime. deniedVerbs
// start one from a checkpoint instead, whose privileges the bundle does not
// describe, so no mode accepts them.
var (
	createVerbs = []string{"create", "run"}
	deniedVerbs = []string{"restore"}
)

// readBundle reads the OCI configuration of the bundle a create names, with
// the container id runc was told to create.
func readBundle(args []string) (*specs.Spec, string, error) {
	dir, containerID, err := bundleAndID(args)
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read the OCI configuration: %w", err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", path, err)
	}
	return &spec, containerID, nil
}

// bundleAndID finds the two things the floor needs: the --bundle option's
// value, in any spelling runc accepts, and the container id, which is the last
// argument runc is given. The rest of the option list is not modelled, so a
// runc that grows an option does not turn every create into a denial.
func bundleAndID(args []string) (bundle, containerID string, err error) {
	bundleAt := -1
	for i, arg := range args {
		name, value, hasValue := splitFlag(arg)
		if !isFlag(arg) || (name != "bundle" && name != "b") {
			continue
		}
		switch {
		case hasValue:
			bundle, bundleAt = value, i
		case i+1 < len(args):
			bundle, bundleAt = args[i+1], i+1
		}
	}
	if last := len(args) - 1; last >= 0 && last != bundleAt {
		containerID = args[last]
	}
	switch {
	case !filepath.IsAbs(bundle):
		return "", "", fmt.Errorf("the create names no absolute bundle directory, got %q", bundle)
	case containerID == "" || isFlag(containerID):
		return "", "", errors.New("the create names no container")
	}
	return bundle, containerID, nil
}
