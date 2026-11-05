package c8srunc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const (
	testMeshUID     = uint32(1337)
	testRouterUID   = uint32(1339)
	testWorkloadUID = uint32(65532)
)

// testFloor is a measured floor binding the mesh endpoint and the router.
func testFloor() nriimagepolicy.MeshFloor {
	return nriimagepolicy.MeshFloor{
		ExemptNamespaces: []string{"kube-system"},
		ReservedIDs: map[uint32]nriimagepolicy.RoleFloor{
			testMeshUID:   {Name: "mesh"},
			testRouterUID: {Name: "router"},
		},
	}
}

// podFloor is the measured floor of a pod CVM: the mesh endpoint alone, no
// exempt namespace, and the pod role's allowance for a root user.
func podFloor() nriimagepolicy.MeshFloor {
	return nriimagepolicy.MeshFloor{
		PodRole: true,
		ReservedIDs: map[uint32]nriimagepolicy.RoleFloor{
			testMeshUID: {Name: "mesh"},
		},
	}
}

// bundleCapabilities spells capability names the way a bundle carries them.
func bundleCapabilities(names ...string) []string {
	held := make([]string, 0, len(names))
	for _, name := range names {
		held = append(held, "CAP_"+name)
	}
	return held
}

// workloadBundle is the OCI configuration containerd writes for an ordinary
// member-pod container: the node's default capabilities, a non-root
// non-reserved user and its own namespaces.
func workloadBundle() *specs.Spec {
	return &specs.Spec{
		Annotations: map[string]string{
			annotationContainerType:    "container",
			annotationSandboxID:        "sandbox-1",
			annotationSandboxNamespace: "tenant",
		},
		Process: &specs.Process{
			User: specs.User{
				UID: testWorkloadUID,
				GID: testWorkloadUID,
			},
			Cwd:             "/",
			NoNewPrivileges: true,
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  bundleCapabilities(allowlist.DefaultCapabilities...),
				Effective: bundleCapabilities(allowlist.DefaultCapabilities...),
				Permitted: bundleCapabilities(allowlist.DefaultCapabilities...),
			},
		},
		Root: &specs.Root{Path: "/run/containerd/bundle/rootfs"},
		Mounts: []specs.Mount{
			{
				Destination: "/sys",
				Type:        "sysfs",
				Options:     []string{"nosuid", "noexec", "nodev", "ro"},
			},
		},
		Linux: &specs.Linux{
			MaskedPaths:   []string{"/proc/kcore"},
			ReadonlyPaths: []string{"/proc/sys"},
			Resources: &specs.LinuxResources{
				Devices: []specs.LinuxDeviceCgroup{
					{
						Allow:  false,
						Access: "rwm",
					},
				},
			},
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{
					Type: specs.NetworkNamespace,
					Path: "/run/netns/cni-1",
				},
				{
					Type: specs.IPCNamespace,
					Path: "/proc/9/ns/ipc",
				},
				{
					Type: specs.UTSNamespace,
					Path: "/proc/9/ns/uts",
				},
				{Type: specs.MountNamespace},
				{Type: specs.CgroupNamespace},
			},
		},
	}
}

// A pod CVM's floor admits a root user: the CVM runs one pod, so root is no
// other tenant's problem, and what root can do stays bounded by the same
// no_new_privs and namespace rules, with the capability bound the image policy
// plugin holds (nri-image-policy/capabilities.go). Reserved ids stay refused.
func TestPodFloorAdmitsRoot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bundle func(*specs.Spec)
		wants  string
	}{
		{
			name: "a root workload",
			bundle: func(s *specs.Spec) {
				s.Process.User.UID = 0
				s.Process.User.GID = 0
			},
		},
		{
			name: "a root workload with a data working directory",
			bundle: func(s *specs.Spec) {
				s.Process.User.UID = 0
				s.Process.User.GID = 0
				s.Process.Cwd = "/mnt/c8s-data/config"
				s.Annotations[annotationSandboxUID] = "pod-uid"
				s.Annotations[annotationContainerName] = "main"
				s.Mounts = append(s.Mounts, bind("/mnt/c8s-data/config", "/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~configmap/config"))
			},
			wants: "data or host mount at /mnt/c8s-data/config",
		},
		{
			name:   "a root workload in the mesh endpoint's group",
			bundle: func(s *specs.Spec) { s.Process.User.UID = 0; s.Process.User.GID = testMeshUID },
			wants:  "gid 1337 is reserved for the mesh role",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := workloadBundle()
			tc.bundle(bundle)
			err := requireFloor(bundle, "ctr", nil, podFloor(), "")
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("the pod floor refused %s: %v", tc.name, err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("the pod floor admitted %s", tc.name)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// The floor refuses every privilege a member pod's protection cannot survive,
// and admits the launch containerd writes for an ordinary container.
func TestFloorRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bundle func(*specs.Spec)
		wants  string
	}{
		{name: "an ordinary container"},
		{
			name: "a capability an entry may declare, with no grant for this container",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SYS_ADMIN")
			},
			wants: "capabilities SYS_ADMIN",
		},
		{
			name: "CAP_NET_ADMIN",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_NET_ADMIN")
			},
			wants: "capability NET_ADMIN, which no entry may declare",
		},
		{
			name:   "CAP_SETUID in the inheritable set",
			bundle: func(s *specs.Spec) { s.Process.Capabilities.Inheritable = []string{"CAP_SETUID"} },
			wants:  "capability SETUID, which no entry may declare",
		},
		{
			name:   "CAP_BPF in the ambient set",
			bundle: func(s *specs.Spec) { s.Process.Capabilities.Ambient = []string{"CAP_BPF"} },
			wants:  "capabilities BPF",
		},
		{
			name:   "no capability sets at all",
			bundle: func(s *specs.Spec) { s.Process.Capabilities = nil },
			wants:  "no capability sets",
		},
		{
			name:   "no_new_privs unset",
			bundle: func(s *specs.Spec) { s.Process.NoNewPrivileges = false },
			wants:  "no_new_privs is not set",
		},
		{
			name: "privileged: every device allowed",
			bundle: func(s *specs.Spec) {
				s.Linux.Resources.Devices = []specs.LinuxDeviceCgroup{
					{
						Allow:  true,
						Access: "rwm",
					},
				}
			},
			wants: "allows every device",
		},
		{
			name:   "privileged: no masked kernel paths",
			bundle: func(s *specs.Spec) { s.Linux.MaskedPaths = nil },
			wants:  "masks no kernel paths",
		},
		{
			name:   "privileged: writable sysfs",
			bundle: func(s *specs.Spec) { s.Mounts[0].Options = []string{"nosuid", "noexec", "nodev"} },
			wants:  "sysfs is mounted writable",
		},
		{
			name: "privileged: writable cgroup2",
			bundle: func(s *specs.Spec) {
				s.Mounts = append(s.Mounts, specs.Mount{
					Destination: "/sys/fs/cgroup",
					Type:        "cgroup2",
					Options:     []string{"ro", "rw"},
				})
			},
			wants: "cgroup2 is mounted writable",
		},
		{
			name: "host PID namespace",
			bundle: func(s *specs.Spec) {
				s.Linux.Namespaces = slices.DeleteFunc(s.Linux.Namespaces, func(ns specs.LinuxNamespace) bool {
					return ns.Type == specs.PIDNamespace
				})
			},
			wants: "no PID namespace entry",
		},
		{
			name: "id mappings without a user namespace entry",
			bundle: func(s *specs.Spec) {
				s.Linux.GIDMappings = []specs.LinuxIDMapping{
					{
						ContainerID: 0,
						HostID:      testMeshUID,
						Size:        1,
					},
				}
			},
			wants: "maps ids",
		},
		{
			name: "a forged sandbox claim",
			bundle: func(s *specs.Spec) {
				// Only the sandbox's own bundle carries its id as its own
				// container id; a workload claiming the type is still covered.
				s.Annotations[annotationContainerType] = containerTypeSandbox
				s.Process.NoNewPrivileges = false
			},
			wants: "no_new_privs is not set",
		},
		{
			name: "a user namespace",
			bundle: func(s *specs.Spec) {
				s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
				s.Linux.UIDMappings = []specs.LinuxIDMapping{
					{
						ContainerID: 0,
						HostID:      testMeshUID,
						Size:        10,
					},
				}
			},
			wants: "user namespace",
		},
		{
			name: "a shared PID namespace",
			bundle: func(s *specs.Spec) {
				s.Linux.Namespaces[0] = specs.LinuxNamespace{
					Type: specs.PIDNamespace,
					Path: "/proc/9/ns/pid",
				}
			},
			wants: "joins the PID namespace",
		},
		{
			name:   "a terminal",
			bundle: func(s *specs.Spec) { s.Process.Terminal = true },
			wants:  "asks for a terminal",
		},
		{
			name: "a root workload",
			bundle: func(s *specs.Spec) {
				s.Process.User.UID = 0
				s.Process.User.GID = 0
			},
			wants: "runs as root",
		},
		{
			name:   "a reserved gid",
			bundle: func(s *specs.Spec) { s.Process.User.GID = testMeshUID },
			wants:  "gid 1337 is reserved for the mesh role",
		},
		{
			name:   "a reserved supplementary group",
			bundle: func(s *specs.Spec) { s.Process.User.AdditionalGids = []uint32{testRouterUID} },
			wants:  "gid 1339 is reserved for the router role",
		},
		{
			name: "an image whose USER is the mesh endpoint's reserved uid",
			bundle: func(s *specs.Spec) {
				// An empty securityContext leaves the image's own USER, so
				// this container holds the default capabilities while
				// claiming the mesh endpoint's identity.
				s.Process.User.UID = testMeshUID
				s.Process.User.GID = testMeshUID
			},
			wants: "a container of the mesh role holds capabilities",
		},
		{
			name: "a bundle without a process",
			bundle: func(s *specs.Spec) {
				s.Process = nil
			},
			wants: "describes no process",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := workloadBundle()
			if tc.bundle != nil {
				tc.bundle(bundle)
			}
			err := requireFloor(bundle, "ctr", nil, testFloor(), "")
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("the floor refused an ordinary container: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("the floor admitted %s", tc.name)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// A capability beyond the node's default set needs a declaration admission
// recorded for that container before the create.
func TestFloorHoldsCapabilitiesToTheGrant(t *testing.T) {
	const (
		granted = "3f1c4e4f1e3a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
		other   = "aa1c4e4f1e3a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
	)
	dir := t.TempDir()
	record := filepath.Join(dir, granted)
	if err := os.WriteFile(record, []byte(`{"capabilities":[["SYS_ADMIN"],["NET_ADMIN"]]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := workloadBundle()
	bundle.Process.Capabilities.Effective = append(bundle.Process.Capabilities.Effective, "CAP_SYS_ADMIN")
	if err := requireFloor(bundle, granted, nil, testFloor(), dir); err != nil {
		t.Fatalf("a granted capability was refused: %v", err)
	}
	if err := requireFloor(bundle, other, nil, testFloor(), dir); err == nil {
		t.Fatal("a container with no record of its own kept SYS_ADMIN")
	}
	bundle.Process.Capabilities.Bounding = append(bundle.Process.Capabilities.Bounding, "CAP_BPF")
	err := requireFloor(bundle, granted, nil, testFloor(), dir)
	if err == nil || !strings.Contains(err.Error(), "capabilities BPF, SYS_ADMIN") {
		t.Fatalf("capabilities no one declaration grants were admitted: %v", err)
	}
	bundle.Process.Capabilities.Bounding = bundleCapabilities(allowlist.DefaultCapabilities...)
	bundle.Process.Capabilities.Effective = append(bundle.Process.Capabilities.Effective, "CAP_NET_ADMIN")
	if err := requireFloor(bundle, granted, nil, testFloor(), dir); err == nil {
		t.Fatal("a record naming NET_ADMIN granted it")
	}
	bundle.Process.Capabilities.Effective = bundleCapabilities(append(allowlist.DefaultCapabilities, "SYS_ADMIN")...)
	if err := os.Chmod(record, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := requireFloor(bundle, granted, nil, testFloor(), dir); err == nil {
		t.Fatal("a record anyone could write was read as admission's")
	}
}

// A role's container holds no capabilities, whichever role it is.
func TestFloorLeavesARoleNoCapabilities(t *testing.T) {
	for _, uid := range []uint32{testMeshUID, testRouterUID} {
		bundle := workloadBundle()
		bundle.Process.User = specs.User{
			UID: uid,
			GID: uid,
		}
		bundle.Process.Capabilities = &specs.LinuxCapabilities{}
		if err := requireFloor(bundle, "ctr", nil, testFloor(), ""); err != nil {
			t.Fatalf("the role at uid %d was refused with no capability: %v", uid, err)
		}
		bundle.Process.Capabilities.Effective = []string{"CAP_NET_BIND_SERVICE"}
		if err := requireFloor(bundle, "ctr", nil, testFloor(), ""); err == nil {
			t.Fatalf("the role at uid %d kept a capability", uid)
		}
	}
}

// Trusted policy names the namespaces that host no member pods, a static pod is
// the node's own, and the pod's own sandbox container is the runtime's: each
// keeps what it is given.
func TestFloorLeavesExemptContainersUntouched(t *testing.T) {
	cilium := workloadBundle()
	cilium.Annotations[annotationSandboxNamespace] = "kube-system"
	cilium.Process.User = specs.User{}
	cilium.Process.NoNewPrivileges = false
	cilium.Process.Capabilities.Effective = append(cilium.Process.Capabilities.Effective, "CAP_NET_ADMIN", "CAP_SYS_ADMIN")
	if err := requireFloor(cilium, "ctr", nil, testFloor(), ""); err != nil {
		t.Fatalf("an exempt namespace's container was refused: %v", err)
	}

	pause := workloadBundle()
	pause.Annotations[annotationContainerType] = containerTypeSandbox
	pause.Process.User = specs.User{}
	pause.Process.NoNewPrivileges = false
	pause.Process.Capabilities.Effective = append(pause.Process.Capabilities.Effective, "CAP_NET_RAW", "CAP_SETUID")
	if err := requireFloor(pause, "sandbox-1", nil, testFloor(), ""); err != nil {
		t.Fatalf("the pod's own sandbox container was refused: %v", err)
	}

	// A static pod is the node's own: its privileged container, in a
	// namespace the policy does not exempt, keeps what it is given.
	static := workloadBundle()
	static.Annotations["kubernetes.io/config.source"] = "file"
	static.Process.User = specs.User{}
	static.Process.NoNewPrivileges = false
	static.Linux.Resources.Devices = []specs.LinuxDeviceCgroup{{Allow: true, Access: "rwm"}}
	if err := requireFloor(static, "ctr", nil, testFloor(), ""); err != nil {
		t.Fatalf("a static pod's container was refused: %v", err)
	}
	for _, source := range []string{"api", ""} {
		apiPod := workloadBundle()
		apiPod.Annotations["kubernetes.io/config.source"] = source
		apiPod.Process.NoNewPrivileges = false
		if err := requireFloor(apiPod, "ctr", nil, testFloor(), ""); err == nil {
			t.Fatalf("a container of a pod from source %q escaped the floor", source)
		}
	}

	// A container of a pod in no namespace is covered, not exempt.
	unnamed := workloadBundle()
	delete(unnamed.Annotations, annotationSandboxNamespace)
	unnamed.Process.NoNewPrivileges = false
	if err := requireFloor(unnamed, "ctr", nil, testFloor(), ""); err == nil {
		t.Fatal("a container naming no namespace escaped the floor")
	}
}

// Attachability is refused for every container the wrapper creates, including
// the ones the floor exempts: an exempt namespace's container and the pod's
// own sandbox.
func TestNoContainerIsCreatedAttachable(t *testing.T) {
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pipeRead.Close()
		pipeWrite.Close()
	})

	exempt := func() *specs.Spec {
		bundle := workloadBundle()
		bundle.Annotations[annotationSandboxNamespace] = "kube-system"
		return bundle
	}
	sandbox := func() *specs.Spec {
		bundle := workloadBundle()
		bundle.Annotations[annotationContainerType] = containerTypeSandbox
		return bundle
	}
	for _, tc := range []struct {
		name        string
		bundle      func() *specs.Spec
		containerID string
	}{
		{name: "an exempt namespace's container", bundle: exempt, containerID: "ctr"},
		{name: "the pod's own sandbox", bundle: sandbox, containerID: "sandbox-1"},
	} {
		t.Run(tc.name+" with a terminal", func(t *testing.T) {
			bundle := tc.bundle()
			bundle.Process.Terminal = true
			if err := requireFloor(bundle, tc.containerID, nil, testFloor(), ""); err == nil {
				t.Fatalf("%s was created with a terminal", tc.name)
			}
		})
		t.Run(tc.name+" carrying standard input", func(t *testing.T) {
			if err := requireFloor(tc.bundle(), tc.containerID, pipeRead, testFloor(), ""); err == nil {
				t.Fatalf("%s was created with the container's standard input", tc.name)
			}
		})
	}
}

// measuredConfig writes the node's measured policy, which is where the floor
// and its role bindings come from.
func measuredConfig(t *testing.T, mesh bool) string {
	t.Helper()
	document := `
platform: snp
allowlist:
  node_tcb: true
  base:
    schema: c8s.allowlist/v1
    workloads:
      mesh:
        containers:
          - digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            role: mesh
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
policy:
  mode: fail-closed
  fatal_existing: true
  boot_marker_path: /run/nri-image-policy/registered
`
	if mesh {
		document += `
mesh:
  exempt_namespaces: [kube-system]
  resolver: "10.43.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`
	}
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A node's measured policy is not a pod CVM's: root stays refused there.
func TestNodeFloorRefusesRoot(t *testing.T) {
	floor, err := nriimagepolicy.LoadMeshFloor(measuredConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if floor.PodRole {
		t.Fatal("a node policy without mesh.pod loaded as a pod CVM's")
	}
	bundle := workloadBundle()
	bundle.Process.User.UID = 0
	bundle.Process.User.GID = 0
	if err := requireFloor(bundle, "ctr", nil, floor, ""); err == nil || !strings.Contains(err.Error(), "runs as root") {
		t.Fatalf("error = %v, want the root refusal", err)
	}
}

// bundleDirWith writes an OCI bundle the way containerd stages one.
func bundleDirWith(t *testing.T, spec *specs.Spec) string {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// floorWrapper is the locked wrapper with the floor New would have read.
func floorWrapper(rec *recorder, stderr *bytes.Buffer, configPath string) Wrapper {
	w := lockedWrapper(rec, stderr)
	w.MeshConfig = configPath
	w.Floor, w.FloorError = nriimagepolicy.LoadMeshFloor(configPath)
	return w
}

// A create reaches the real runtime only when the bundle it names satisfies
// the floor, whichever way runc was told where that bundle is.
func TestCreateIsGatedOnTheBundle(t *testing.T) {
	privileged := workloadBundle()
	privileged.Mounts[0].Options = []string{"nosuid", "noexec", "nodev"}
	for _, tc := range []struct {
		name string
		args func(bundle string) []string
		deny bool
	}{
		{name: "separated bundle option", args: func(b string) []string { return []string{"create", "--bundle", b, "ctr"} }},
		{name: "joined bundle option", args: func(b string) []string { return []string{"create", "--bundle=" + b, "ctr"} }},
		{name: "short bundle option", args: func(b string) []string { return []string{"create", "-b", b, "ctr"} }},
		{
			name: "run after other options",
			args: func(b string) []string {
				return []string{"run", "--no-pivot", "--pid-file", "/run/p", "--bundle", b, "-d", "ctr"}
			},
		},
		{
			name: "an option the wrapper does not model",
			args: func(b string) []string { return []string{"create", "--rootless-euid", "--bundle", b, "ctr"} },
		},
		{
			name: "no bundle option",
			args: func(string) []string { return []string{"create", "ctr"} },
			deny: true,
		},
		{
			name: "a relative bundle",
			args: func(string) []string { return []string{"create", "--bundle", "bundle", "ctr"} },
			deny: true,
		},
		{
			name: "no container id",
			args: func(b string) []string { return []string{"create", "--bundle", b} },
			deny: true,
		},
		{
			name: "a bundle with no configuration",
			args: func(string) []string { return []string{"create", "--bundle", t.TempDir(), "ctr"} },
			deny: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			stderr := &bytes.Buffer{}
			bundle := bundleDirWith(t, workloadBundle())
			code := floorWrapper(rec, stderr, measuredConfig(t, true)).Run(append([]string{"c8s-runc"}, tc.args(bundle)...))
			if tc.deny {
				if rec.called || code != exitDenied {
					t.Fatalf("%s reached the real runtime (code %d)", tc.name, code)
				}
				return
			}
			if !rec.called {
				t.Fatalf("an admitted bundle was denied: %s", stderr.String())
			}
		})
	}

	rec := &recorder{}
	stderr := &bytes.Buffer{}
	logPath := filepath.Join(t.TempDir(), "runc.log")
	bundle := bundleDirWith(t, privileged)
	code := floorWrapper(rec, stderr, measuredConfig(t, true)).Run([]string{
		"c8s-runc", "--log", logPath, "create", "--bundle", bundle, "ctr",
	})
	if rec.called || code != exitDenied {
		t.Fatalf("a privileged bundle reached the real runtime (code %d)", code)
	}
	if !strings.Contains(stderr.String(), "sysfs is mounted writable") {
		t.Fatalf("stderr = %q, want the refused privilege named", stderr.String())
	}
	logged, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(logged), "sysfs is mounted writable") {
		t.Fatalf("runc log = %q (%v), want the denial", string(logged), err)
	}
}

// The floor is the node's policy, not an option: a measured config the floor
// cannot be read from denies the create, whether the file is unreadable or
// carries no mesh policy.
func TestFloorFailsClosedOnTheMeasuredConfig(t *testing.T) {
	bundle := bundleDirWith(t, workloadBundle())
	create := []string{"c8s-runc", "create", "--bundle", bundle, "ctr"}

	for _, tc := range []struct {
		name   string
		config string
	}{
		{name: "unreadable file", config: filepath.Join(t.TempDir(), "absent.yaml")},
		{name: "no mesh policy", config: measuredConfig(t, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			stderr := &bytes.Buffer{}
			if code := floorWrapper(rec, stderr, tc.config).Run(create); rec.called || code != exitDenied {
				t.Fatalf("a measured config without a floor admitted a create (code %d)", code)
			}
		})
	}
}

// Cleanup does not require readable policy; starts must establish their role.
func TestOtherVerbsReadNoBundle(t *testing.T) {
	rec := &recorder{}
	stderr := &bytes.Buffer{}
	w := floorWrapper(rec, stderr, filepath.Join(t.TempDir(), "absent.yaml"))
	if code := w.Run([]string{"c8s-runc", "delete", "ctr"}); !rec.called {
		t.Fatalf("delete was denied by the floor (code %d): %s", code, stderr.String())
	}
}

// The floor reads the create's own standard input: the shim gives runc the
// container's stdin pipe only for a container asked to keep stdin open.
func TestFloorRefusesACreateCarryingStdin(t *testing.T) {
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pipeRead.Close()
		pipeWrite.Close()
	})
	if err := requireFloor(workloadBundle(), "ctr", pipeRead, testFloor(), ""); err == nil {
		t.Fatal("a create carrying the container's standard input was admitted")
	}

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { null.Close() })
	if err := requireFloor(workloadBundle(), "ctr", null, testFloor(), ""); err != nil {
		t.Fatalf("a create with the null device on its standard input was refused: %v", err)
	}
}

// A restore starts what a checkpoint holds, which the bundle does not
// describe, so no mode accepts it; and the floor itself holds in every mode.
func TestRestoreIsDeniedAndTheFloorIgnoresTheMode(t *testing.T) {
	for _, mode := range []string{ModeLocked, ModeDebug} {
		rec := &recorder{}
		stderr := &bytes.Buffer{}
		w := floorWrapper(rec, stderr, measuredConfig(t, true))
		w.Mode = mode
		if code := w.Run([]string{"c8s-runc", "restore", "--bundle", "/run/b", "ctr"}); rec.called || code != exitDenied {
			t.Fatalf("restore reached the real runtime in %s mode (code %d)", mode, code)
		}

		privileged := workloadBundle()
		privileged.Process.Terminal = true
		rec = &recorder{}
		stderr = &bytes.Buffer{}
		w = floorWrapper(rec, stderr, measuredConfig(t, true))
		w.Mode = mode
		args := []string{"c8s-runc", "create", "--bundle", bundleDirWith(t, privileged), "ctr"}
		if code := w.Run(args); rec.called || code != exitDenied {
			t.Fatalf("the floor let a terminal through in %s mode (code %d)", mode, code)
		}
	}
}

// An unknown exec mode is answered before anything else: a build the wrapper
// cannot classify runs nothing.
func TestUnknownModeIsAnsweredBeforeTheFloor(t *testing.T) {
	rec := &recorder{}
	stderr := &bytes.Buffer{}
	w := floorWrapper(rec, stderr, measuredConfig(t, true))
	w.Mode = "audit"
	code := w.Run([]string{"c8s-runc", "create", "--bundle", bundleDirWith(t, workloadBundle()), "ctr"})
	if rec.called || code != exitDenied {
		t.Fatalf("an unknown mode admitted a create (code %d)", code)
	}
	if !strings.Contains(stderr.String(), "unknown exec mode") {
		t.Fatalf("stderr = %q, want the unknown mode named", stderr.String())
	}
}

func TestFloorDeviceWildcardSemantics(t *testing.T) {
	negative := int64(-1)
	positive := int64(7)
	for _, deviceType := range []string{"", "a", "c", "b"} {
		for majorIndex, major := range []*int64{nil, &negative, &positive} {
			for minorIndex, minor := range []*int64{nil, &negative, &positive} {
				for _, access := range []string{"", "m", "rwm"} {
					name := fmt.Sprintf("type=%s/major=%d/minor=%d/access=%s", deviceType, majorIndex, minorIndex, access)
					t.Run(name, func(t *testing.T) {
						bundle := workloadBundle()
						bundle.Linux.Resources.Devices = append(bundle.Linux.Resources.Devices, specs.LinuxDeviceCgroup{
							Allow:  true,
							Type:   deviceType,
							Major:  major,
							Minor:  minor,
							Access: access,
						})
						err := requireFloor(bundle, "ctr", nil, testFloor(), "")
						if deviceType == "" || deviceType == "a" {
							if err == nil || !strings.Contains(err.Error(), "allows every device") {
								t.Fatalf("requireFloor = %v, want every-device refusal", err)
							}
						} else if err != nil {
							t.Fatalf("explicit device type refused: %v", err)
						}
					})
				}
			}
		}
	}
}

// TestFloorRefusesAWorkingDirOnSuppliedContent keeps the working directory off
// data and host mounts: a pinned interpreter launch resolves its first module
// path against it.
func TestFloorRefusesAWorkingDirOnSuppliedContent(t *testing.T) {
	const pod = "/var/lib/kubelet/pods/pod-uid/volumes/"
	root := t.TempDir()
	for _, dir := range []string{"run", "app", "mnt/c8s-data"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"var-run": "/run",
		"data":    "mnt/c8s-data/config",
		"loop":    "loop",
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		cwd    string
		mount  specs.Mount
		noRoot bool
		wants  string
	}{
		{name: "the image root", cwd: "/"},
		{name: "the parent of a data mount", cwd: "/mnt/c8s-data"},
		{name: "a data mount", cwd: "/mnt/c8s-data/config", wants: "data or host mount at /mnt/c8s-data/config"},
		{name: "below a data mount", cwd: "/mnt/c8s-data/config/pkg", wants: "mount at /mnt/c8s-data/config"},
		{name: "an unclean path onto a data mount", cwd: "/app/../mnt/c8s-data/config/", wants: "mount at /mnt/c8s-data/config"},
		{name: "a relative link onto a data mount", cwd: "/data", wants: "mount at /mnt/c8s-data/config"},
		{name: "an emptyDir", cwd: "/app/cache", mount: bind("/app/cache", pod+"kubernetes.io~empty-dir/cache")},
		{name: "the pod's shared memory", cwd: "/dev/shm", mount: bind("/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/sandbox-1/shm")},
		{name: "a kernel filesystem", cwd: "/tmp", mount: specs.Mount{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs"}},
		{name: "a host mount", cwd: "/srv", mount: bind("/srv", "/srv/data"), wants: "mount at /srv"},
		{name: "another pod's emptyDir", cwd: "/app/cache", mount: bind("/app/cache", "/var/lib/kubelet/pods/other/volumes/kubernetes.io~empty-dir/cache"), wants: "mount at /app/cache"},
		{name: "a volume placeholder", cwd: "/app/vol", mount: bind("/app/vol", pod+"kubernetes.io~empty-dir/c8s-volume-app"), wants: "mount at /app/vol"},
		{name: "an absolute link onto a host mount", cwd: "/var-run/x", mount: bind("/run/x", "/srv/x"), wants: "mount at /run/x"},
		{name: "a host mount named through a link", cwd: "/run/x", mount: bind("/var-run/x", "/srv/x"), wants: "mount at /run/x"},
		{name: "a link loop", cwd: "/loop", wants: "too many levels"},
		{name: "a relative working directory", cwd: "app", wants: "not absolute"},
		{name: "no root filesystem", cwd: "/", noRoot: true, wants: "no root filesystem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := workloadBundle()
			bundle.Annotations[annotationSandboxUID] = "pod-uid"
			bundle.Annotations[annotationContainerName] = "main"
			bundle.Root.Path = root
			if tc.noRoot {
				bundle.Root = nil
			}
			bundle.Process.Cwd = tc.cwd
			bundle.Mounts = append(bundle.Mounts, bind("/mnt/c8s-data/config", pod+"kubernetes.io~configmap/config"))
			if tc.mount.Destination != "" {
				bundle.Mounts = append(bundle.Mounts, tc.mount)
			}
			err := requireFloor(bundle, "ctr", nil, testFloor(), "")
			if tc.wants == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("got %v, want an error containing %q", err, tc.wants)
			}
		})
	}
}

func bind(destination, source string) specs.Mount {
	return specs.Mount{Destination: destination, Type: "bind", Source: source, Options: []string{"rbind", "ro"}}
}
