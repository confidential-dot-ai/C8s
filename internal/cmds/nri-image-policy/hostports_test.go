package nriimagepolicy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/containerd/nri/pkg/api"

	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The front door's mapping, as containerd records it and as an entry declares it.
var (
	recordedHTTPS = ctrdresolver.HostPort{Protocol: ctrdresolver.ProtocolTCP, ContainerPort: 8443, HostPort: 443}
	declaredHTTPS = []allowlist.HostPort{{Protocol: "TCP", HostPort: 443, ContainerPort: 8443}}
)

// hostPortBase holds the front door's pinned launch publishing host port 443, an
// open entry for the same image, and the mesh client the node injects.
func hostPortBase(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	pinned := allowlist.Container{
		Digest:  mustDigest(t, pushDigestB),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/nginx"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyDeny},
		Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyDeny},
	}
	open := allowlist.Container{
		Digest:  mustDigest(t, pushDigestB),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	mesh := allowlist.Container{
		Digest:  mustDigest(t, pushDigestA),
		Role:    meshRole,
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/mesh"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	base := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{
		"front-door": {Containers: []allowlist.Container{pinned}, HostPorts: declaredHTTPS},
		"open":       {Containers: []allowlist.Container{open}},
		"mesh":       {Containers: []allowlist.Container{mesh}},
	}}
	if err := base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return base
}

func hostPortPlugin(t *testing.T, sandbox sandboxMode, mode string) *plugin {
	t.Helper()
	if sandbox == "" {
		sandbox = SandboxEnforce
	}
	if mode == "" {
		mode = ModeFailClosed
	}
	base := hostPortBase(t)
	cfg := &config{
		Allowlist: allowlistConfig{Base: base, NodeTCB: true},
		Policy:    policyConfig{Mode: mode, Sandbox: sandbox},
	}
	p, _ := newCachedPlugin(cfg, &allowlist.Allowlist{Schema: allowlist.Schema})
	return p
}

// onNodeNetwork is a pod sharing the node's network, as NRI reports one.
func onNodeNetwork(pod *api.PodSandbox) {
	pod.Linux.Namespaces = slices.DeleteFunc(pod.Linux.Namespaces, func(ns *api.LinuxNamespace) bool {
		return ns.Type == networkNamespace
	})
}

func ports(recorded ...ctrdresolver.HostPort) ctrdresolver.SandboxNetwork {
	return ctrdresolver.SandboxNetwork{HostPorts: recorded}
}

// A sandbox is refused unless an entry declares every host port containerd
// recorded for it.
func TestSandboxHostPortsNeedADeclaringEntry(t *testing.T) {
	addressBound := recordedHTTPS
	addressBound.HostIP = netip.MustParseAddr("10.0.0.5")
	undeclared := ports(ctrdresolver.HostPort{Protocol: ctrdresolver.ProtocolTCP, ContainerPort: 8080, HostPort: 8080})
	for _, tc := range []struct {
		name     string
		sandbox  sandboxMode
		mode     string
		pod      func(*api.PodSandbox)
		network  ctrdresolver.SandboxNetwork
		lookup   error
		reads    bool
		admitted bool
	}{
		{name: "a declared host port", network: ports(recordedHTTPS), reads: true, admitted: true},
		{name: "no host port", network: ports(), reads: true, admitted: true},
		{name: "a host port no entry declares", network: undeclared, reads: true},
		{name: "a declared host port on one node address", network: ports(addressBound), reads: true},
		{name: "an unreadable record", lookup: errors.New("sandbox not found"), reads: true},
		{name: "a sandbox containerd no longer has", lookup: errdefs.ErrNotFound, reads: true},
		{name: "a record on the node's network", network: ctrdresolver.SandboxNetwork{HostNetwork: true}, reads: true},
		{name: "a pod on the node's network", pod: onNodeNetwork, admitted: true},
		{name: "sandbox audit admits what no entry declares", sandbox: SandboxAudit, network: undeclared, reads: true, admitted: true},
		{name: "sandbox audit does not excuse an unreadable record", sandbox: SandboxAudit, lookup: errors.New("sandbox not found"), reads: true},
		{name: "audit mode enforces nothing", mode: ModeAudit, network: undeclared, reads: true, admitted: true},
		{name: "off does not read the record", sandbox: SandboxOff, network: undeclared, admitted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := hostPortPlugin(t, tc.sandbox, tc.mode)
			pod := sandboxedPod()
			if tc.pod != nil {
				tc.pod(pod)
			}
			read := false
			p.containerd = &fakeContainerd{network: func(_ context.Context, id string, recorded ctrdresolver.SandboxPod) (ctrdresolver.SandboxNetwork, error) {
				read = true
				if want := (ctrdresolver.SandboxPod{Name: pod.GetName(), Namespace: pod.GetNamespace(), UID: pod.GetUid()}); id != pod.GetId() || recorded != want {
					t.Errorf("read sandbox %s for %+v, want %s for %+v", id, recorded, pod.GetId(), want)
				}
				return tc.network, tc.lookup
			}}
			err := p.RunPodSandbox(context.Background(), pod)
			if (err == nil) != tc.admitted {
				t.Fatalf("RunPodSandbox = %v, want admitted %v", err, tc.admitted)
			}
			if read != tc.reads {
				t.Fatalf("read the sandbox record = %v, want %v", read, tc.reads)
			}
		})
	}
}

// mountsADenyPolicyAdmits drops the kubelet's binds, which a deny-mounts policy refuses.
func mountsADenyPolicyAdmits(ctr *api.Container) []*api.Mount {
	return slices.DeleteFunc(slices.Clone(ctr.Mounts), func(m *api.Mount) bool {
		return m.Type == "bind"
	})
}

// In a pod that maps host ports only a launch the declaring entry admits runs.
func TestHostPortLaunchNeedsTheDeclaringEntry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sandbox sandboxMode
		argv    []string
		image   string
		pod     func(*api.PodSandbox)
		network ctrdresolver.SandboxNetwork
		lookup  error
		want    imageVerdict
	}{
		{name: "the declaring entry's launch", network: ports(recordedHTTPS), want: verdictAllow},
		{name: "another launch beside it", argv: []string{"/other"}, network: ports(recordedHTTPS), want: verdictDeny},
		{name: "another launch in a pod mapping no host port", argv: []string{"/other"}, network: ports(), want: verdictAllow},
		{name: "the mesh client the node injects", argv: []string{"/mesh"}, image: pushDigestA, network: ports(recordedHTTPS), want: verdictAllow},
		{name: "an unreadable record", lookup: errors.New("sandbox not found"), want: verdictDeny},
		{name: "a sandbox containerd no longer has", lookup: errdefs.ErrNotFound, want: verdictAllow},
		{
			name: "a static pod with an unreadable record",
			pod: func(pod *api.PodSandbox) {
				pod.Annotations = map[string]string{configSourceAnnotation: staticPodSource}
			},
			lookup: errors.New("sandbox not found"), want: verdictDeny,
		},
		{name: "sandbox audit admits another launch", sandbox: SandboxAudit, argv: []string{"/other"}, network: ports(recordedHTTPS), want: verdictAllow},
		{name: "sandbox audit does not excuse an unreadable record", sandbox: SandboxAudit, lookup: errors.New("sandbox not found"), want: verdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := hostPortPlugin(t, tc.sandbox, "")
			p.containerd = &fakeContainerd{network: func(context.Context, string, ctrdresolver.SandboxPod) (ctrdresolver.SandboxNetwork, error) {
				return tc.network, tc.lookup
			}}
			pod, ctr := sandboxedPod(), sandboxedContainer()
			if tc.pod != nil {
				tc.pod(pod)
			}
			image := tc.image
			if image == "" {
				image = pushDigestB
			}
			argv := tc.argv
			if argv == nil {
				argv = []string{"/nginx"}
			}
			imageRef := "registry/repo@" + image
			ctr.Mounts = mountsADenyPolicyAdmits(ctr)
			ctr.Annotations = map[string]string{annotationImageName: imageRef}
			ctr.Args = argv
			verdict, reason := p.checkContainerPhase(context.Background(), p.cfg, pod, ctr, imageRef, launchFinal)
			if verdict != tc.want {
				t.Fatalf("checkContainerPhase = %d %q, want %d", verdict, reason, tc.want)
			}
			if tc.want == verdictDeny && !strings.Contains(reason, "host ports") {
				t.Fatalf("reason = %q, want the host ports named", reason)
			}
		})
	}
}
