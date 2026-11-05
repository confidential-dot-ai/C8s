package nriimagepolicy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// capabilitySets adds a capability to one of a spec's five sets.
var capabilitySets = map[string]func(*specs.LinuxCapabilities, string){
	"bounding":    func(sets *specs.LinuxCapabilities, name string) { sets.Bounding = append(sets.Bounding, name) },
	"effective":   func(sets *specs.LinuxCapabilities, name string) { sets.Effective = append(sets.Effective, name) },
	"permitted":   func(sets *specs.LinuxCapabilities, name string) { sets.Permitted = append(sets.Permitted, name) },
	"inheritable": func(sets *specs.LinuxCapabilities, name string) { sets.Inheritable = append(sets.Inheritable, name) },
	"ambient":     func(sets *specs.LinuxCapabilities, name string) { sets.Ambient = append(sets.Ambient, name) },
}

// capabilityBase is a measured base holding a tracer whose pinned launch
// declares SYS_PTRACE, and an open entry for the same image declaring none.
func capabilityBase(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	tracer := allowlist.Container{
		Digest:       mustDigest(t, pushDigestB),
		Command:      allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
		Args:         allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts:       allowlist.MountPolicy{Policy: allowlist.PolicyDeny},
		Env:          allowlist.EnvPolicy{Policy: allowlist.PolicyDeny},
		Capabilities: allowlist.CapabilityList{"SYS_PTRACE"},
	}
	open := allowlist.Container{
		Digest:  mustDigest(t, pushDigestB),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	base := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{
		"tracer": {Containers: []allowlist.Container{tracer}},
		"open":   {Containers: []allowlist.Container{open}},
	}}
	if err := base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return base
}

func capabilityPlugin(t *testing.T, sandbox sandboxMode) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: capabilityBase(t), NodeTCB: true},
		Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: sandbox},
	}
	p, _ := newCachedPlugin(cfg, &allowlist.Allowlist{Schema: allowlist.Schema})
	return p
}

// capabilityVerdict runs an /app launch of the tracer's image through the final phase.
func capabilityVerdict(t *testing.T, p *plugin, pod *api.PodSandbox, argv []string) (imageVerdict, string) {
	t.Helper()
	imageRef := "registry/repo@" + pushDigestB
	ctr := sandboxedContainer()
	ctr.Mounts = mountsADenyPolicyAdmits(ctr)
	ctr.Annotations = map[string]string{annotationImageName: imageRef}
	ctr.Args = argv
	return p.checkContainerPhase(context.Background(), p.cfg, pod, ctr, imageRef, launchFinal)
}

// Each of the five OCI capability sets is held: a capability in the bounding
// set alone is one an exec can still take.
func TestEveryCapabilitySetNeedsItsDeclaration(t *testing.T) {
	for set, hold := range capabilitySets {
		for _, tc := range []struct {
			name       string
			capability string
			want       imageVerdict
		}{
			{name: "declared", capability: "CAP_SYS_PTRACE", want: verdictAllow},
			{name: "undeclared", capability: "CAP_SYS_ADMIN", want: verdictDeny},
		} {
			t.Run(set+" "+tc.name, func(t *testing.T) {
				spec := workloadSpec()
				hold(spec.Process.Capabilities, tc.capability)
				p := capabilityPlugin(t, SandboxEnforce)
				p.containerd = &fakeContainerd{spec: func(context.Context, string) (*specs.Spec, error) {
					return spec, nil
				}}
				verdict, reason := capabilityVerdict(t, p, sandboxedPod(), []string{"/app"})
				if verdict != tc.want {
					t.Fatalf("checkContainerPhase = %d %q, want %d", verdict, reason, tc.want)
				}
			})
		}
	}
}

// Admission records a container's capability grant at the validation check,
// the hook whose failure fails the create, and drops the record with the
// container.
func TestValidationRecordsTheCapabilityGrant(t *testing.T) {
	const containerID = "7c1c4e4f1e3a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
	p := capabilityPlugin(t, SandboxEnforce)
	p.SetReady()
	dir := t.TempDir()
	p.capGrants = &capabilityGrants{dir: dir}
	// A mesh-exempt namespace: the gate's own record is a node fixture.
	pod := sandboxedPod()
	pod.Namespace = "kube-system"
	imageRef := "registry/repo@" + pushDigestB
	ctr := sandboxedContainer()
	ctr.Id = containerID
	ctr.Mounts = mountsADenyPolicyAdmits(ctr)
	ctr.Annotations = map[string]string{annotationImageName: imageRef}
	ctr.Args = []string{"/app"}
	req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err != nil {
		t.Fatalf("the tracer's launch was refused: %v", err)
	}
	granted, err := ReadCapabilityGrant(dir, containerID)
	if err != nil || len(granted) != 1 || !slices.Equal(granted[0], []string{"SYS_PTRACE"}) {
		t.Fatalf("ReadCapabilityGrant = %v, %v, want [[SYS_PTRACE]]", granted, err)
	}
	if err := p.RemoveContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if granted, err := ReadCapabilityGrant(dir, containerID); err != nil || granted != nil {
		t.Fatalf("the removed container kept the grant %v, %v", granted, err)
	}
	// The open entry admits any launch of the same image and declares nothing.
	ctr.Args = []string{"/other"}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err != nil {
		t.Fatalf("the open entry's launch was refused: %v", err)
	}
	if granted, err := ReadCapabilityGrant(dir, containerID); err != nil || granted != nil {
		t.Fatalf("a launch no declaration grants holds %v, %v", granted, err)
	}
}

// A container holds the node's default capability set, and beyond it only what
// the entry admitting its whole launch declares.
func TestCapabilitiesNeedADeclaringEntry(t *testing.T) {
	undeclared := func(s *specs.Spec) {
		s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SYS_ADMIN")
	}
	for _, tc := range []struct {
		name    string
		sandbox sandboxMode
		argv    []string
		pod     func(*api.PodSandbox)
		spec    func(*specs.Spec)
		lookup  error
		reads   bool
		want    imageVerdict
		// names is what a refusal must say, "capabilities" by default.
		names string
	}{
		{name: "the default set", reads: true, want: verdictAllow},
		{
			name: "a declared capability under another launch",
			argv: []string{"/other"},
			spec: func(s *specs.Spec) {
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SYS_PTRACE")
			},
			reads: true, want: verdictDeny,
		},
		{
			name: "a static pod holding an undeclared capability",
			pod: func(pod *api.PodSandbox) {
				pod.Annotations = map[string]string{configSourceAnnotation: staticPodSource}
			},
			spec: undeclared, reads: true, want: verdictDeny,
		},
		{
			name:  "a spec describing no process",
			spec:  func(s *specs.Spec) { s.Process = nil },
			reads: true, want: verdictDeny, names: "describes no process",
		},
		{
			name:  "a spec naming no capability sets",
			spec:  func(s *specs.Spec) { s.Process.Capabilities = nil },
			reads: true, want: verdictDeny, names: "no capability sets",
		},
		{
			name: "a platform role holding a declared capability",
			spec: func(s *specs.Spec) {
				s.Process.User.UID = testMeshUID
				s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SYS_PTRACE")
			},
			reads: true, want: verdictDeny, names: "mesh role",
		},
		{
			name: "a platform role's reserved supplementary group",
			spec: func(s *specs.Spec) {
				s.Process.User.AdditionalGids = []uint32{testMeshUID}
			},
			reads: true, want: verdictDeny, names: "mesh role",
		},
		{
			name: "a platform role holding none",
			spec: func(s *specs.Spec) {
				s.Process.User.UID = testMeshUID
				s.Process.Capabilities = &specs.LinuxCapabilities{}
			},
			reads: true, want: verdictAllow,
		},
		{
			name:   "an unreadable spec",
			lookup: errors.New("containerd is down"),
			reads:  true, want: verdictDeny, names: "stored OCI spec",
		},
		{
			name:   "a container containerd no longer has",
			spec:   undeclared,
			lookup: errdefs.ErrNotFound,
			reads:  true, want: verdictAllow,
		},
		{
			name: "an exempt namespace holding an undeclared capability",
			pod:  func(pod *api.PodSandbox) { pod.Namespace = "kube-system" },
			spec: undeclared, want: verdictAllow,
		},
		{name: "sandbox audit admits an undeclared capability", sandbox: SandboxAudit, spec: undeclared, reads: true, want: verdictAllow},
		{
			name:    "sandbox audit does not excuse an unreadable spec",
			sandbox: SandboxAudit,
			lookup:  errors.New("containerd is down"),
			reads:   true, want: verdictDeny, names: "stored OCI spec",
		},
		{name: "off does not read the spec", sandbox: SandboxOff, spec: undeclared, want: verdictAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandbox := tc.sandbox
			if sandbox == "" {
				sandbox = SandboxEnforce
			}
			spec := workloadSpec()
			if tc.spec != nil {
				tc.spec(spec)
			}
			read := false
			p := capabilityPlugin(t, sandbox)
			p.containerd = &fakeContainerd{spec: func(_ context.Context, id string) (*specs.Spec, error) {
				read = true
				if want := sandboxedContainer().GetId(); id != want {
					t.Errorf("read the spec of container %s, want %s", id, want)
				}
				return spec, tc.lookup
			}}
			pod := sandboxedPod()
			if tc.pod != nil {
				tc.pod(pod)
			}
			argv := tc.argv
			if argv == nil {
				argv = []string{"/app"}
			}
			verdict, reason := capabilityVerdict(t, p, pod, argv)
			if verdict != tc.want {
				t.Fatalf("checkContainerPhase = %d %q, want %d", verdict, reason, tc.want)
			}
			if read != tc.reads {
				t.Fatalf("read the container's spec = %v, want %v", read, tc.reads)
			}
			names := tc.names
			if names == "" {
				names = "capabilities"
			}
			if tc.want == verdictDeny && !strings.Contains(reason, names) {
				t.Fatalf("reason = %q, want it to name %q", reason, names)
			}
		})
	}
}
