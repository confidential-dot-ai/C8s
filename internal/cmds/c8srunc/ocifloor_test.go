package c8srunc

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
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

// workloadBundle is the OCI configuration containerd writes for an ordinary
// member-pod container: the runtime's default capabilities less the three the
// floor removes, a non-root non-reserved user, and its own namespaces.
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
			NoNewPrivileges: true,
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  append([]string{}, workloadCapabilities...),
				Effective: append([]string{}, workloadCapabilities...),
				Permitted: append([]string{}, workloadCapabilities...),
			},
		},
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
			name: "CAP_NET_ADMIN",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_NET_ADMIN")
			},
			wants: "effective capability CAP_NET_ADMIN",
		},
		{
			name: "CAP_NET_RAW",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Permitted = append(s.Process.Capabilities.Permitted, "CAP_NET_RAW")
			},
			wants: "permitted capability CAP_NET_RAW",
		},
		{
			name: "CAP_SYS_ADMIN in the bounding set alone",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
			},
			wants: "bounding capability CAP_SYS_ADMIN",
		},
		{
			name: "CAP_BPF",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_BPF")
			},
			wants: "capability CAP_BPF",
		},
		{
			name: "CAP_SETUID",
			bundle: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SETUID")
			},
			wants: "capability CAP_SETUID",
		},
		{
			name:   "CAP_SETGID in the ambient set",
			bundle: func(s *specs.Spec) { s.Process.Capabilities.Ambient = []string{"CAP_SETGID"} },
			wants:  "ambient capability CAP_SETGID",
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
			name:   "no capability sets at all",
			bundle: func(s *specs.Spec) { s.Process.Capabilities = nil },
			wants:  "no capability sets",
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
				s.Process.Terminal = true
			},
			wants: "asks for a terminal",
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
			wants: "capability",
		},
		{
			name: "a bundle without a process",
			bundle: func(s *specs.Spec) {
				s.Process = nil
			},
			wants: "no Linux process",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := workloadBundle()
			if tc.bundle != nil {
				tc.bundle(bundle)
			}
			err := requireFloor(bundle, "ctr", nil, testFloor())
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

// A role's container holds no capabilities, whichever role it is.
func TestFloorLeavesARoleNoCapabilities(t *testing.T) {
	for _, uid := range []uint32{testMeshUID, testRouterUID} {
		bundle := workloadBundle()
		bundle.Process.User = specs.User{
			UID: uid,
			GID: uid,
		}
		bundle.Process.Capabilities = &specs.LinuxCapabilities{}
		if err := requireFloor(bundle, "ctr", nil, testFloor()); err != nil {
			t.Fatalf("the role at uid %d was refused with no capability: %v", uid, err)
		}
		bundle.Process.Capabilities.Effective = []string{"CAP_NET_BIND_SERVICE"}
		if err := requireFloor(bundle, "ctr", nil, testFloor()); err == nil {
			t.Fatalf("the role at uid %d kept a capability", uid)
		}
	}
}

// Trusted policy names the namespaces that host no member pods, and the pod's
// own sandbox container is the runtime's: both keep what they are given.
func TestFloorLeavesExemptContainersUntouched(t *testing.T) {
	canal := workloadBundle()
	canal.Annotations[annotationSandboxNamespace] = "kube-system"
	canal.Process.User = specs.User{}
	canal.Process.Terminal = true
	canal.Process.NoNewPrivileges = false
	canal.Process.Capabilities.Effective = append(canal.Process.Capabilities.Effective, "CAP_NET_ADMIN", "CAP_SYS_ADMIN")
	if err := requireFloor(canal, "ctr", nil, testFloor()); err != nil {
		t.Fatalf("an exempt namespace's container was refused: %v", err)
	}

	pause := workloadBundle()
	pause.Annotations[annotationContainerType] = containerTypeSandbox
	pause.Process.Capabilities.Effective = append(pause.Process.Capabilities.Effective, "CAP_NET_RAW", "CAP_SETUID")
	if err := requireFloor(pause, "sandbox-1", nil, testFloor()); err != nil {
		t.Fatalf("the pod's own sandbox container was refused: %v", err)
	}

	// A container of a pod in no namespace is covered, not exempt.
	unnamed := workloadBundle()
	delete(unnamed.Annotations, annotationSandboxNamespace)
	unnamed.Process.Terminal = true
	if err := requireFloor(unnamed, "ctr", nil, testFloor()); err == nil {
		t.Fatal("a container naming no namespace escaped the floor")
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
  server:
    namespace: c8s-router
    listeners: [8443]
`
	}
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
	privileged.Process.Capabilities.Effective = append(privileged.Process.Capabilities.Effective, "CAP_NET_ADMIN")
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
	if !strings.Contains(stderr.String(), "CAP_NET_ADMIN") {
		t.Fatalf("stderr = %q, want the refused capability named", stderr.String())
	}
	logged, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(logged), "CAP_NET_ADMIN") {
		t.Fatalf("runc log = %q (%v), want the denial", string(logged), err)
	}
}

// The floor is the node's policy, not an option: a measured config that
// cannot be read denies the create, while one carrying no mesh policy hosts
// no member pods and leaves every create alone.
func TestFloorFailsClosedOnTheMeasuredConfig(t *testing.T) {
	bundle := bundleDirWith(t, workloadBundle())
	create := []string{"c8s-runc", "create", "--bundle", bundle, "ctr"}

	rec := &recorder{}
	stderr := &bytes.Buffer{}
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if code := floorWrapper(rec, stderr, missing).Run(create); rec.called || code != exitDenied {
		t.Fatalf("an unreadable measured config admitted a create (code %d)", code)
	}

	rec = &recorder{}
	stderr = &bytes.Buffer{}
	floorWrapper(rec, stderr, measuredConfig(t, false)).Run(create)
	if !rec.called {
		t.Fatalf("a config with no mesh policy denied a create: %s", stderr.String())
	}
}

// Only the verbs that start a container from a bundle read one: a start or a
// delete is handed over whatever the bundle says.
func TestOtherVerbsReadNoBundle(t *testing.T) {
	rec := &recorder{}
	stderr := &bytes.Buffer{}
	w := floorWrapper(rec, stderr, filepath.Join(t.TempDir(), "absent.yaml"))
	if code := w.Run([]string{"c8s-runc", "start", "ctr"}); !rec.called {
		t.Fatalf("start was denied by the floor (code %d): %s", code, stderr.String())
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
	if err := requireFloor(workloadBundle(), "ctr", pipeRead, testFloor()); err == nil {
		t.Fatal("a create carrying the container's standard input was admitted")
	}

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { null.Close() })
	if err := requireFloor(workloadBundle(), "ctr", null, testFloor()); err != nil {
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
