package nriimagepolicy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

var (
	routerHTTPS = ctrdresolver.HostPort{Protocol: "TCP", ContainerPort: 8443, HostPort: 443}
	routerHTTP  = ctrdresolver.HostPort{Protocol: "TCP", ContainerPort: 8080, HostPort: 80}
)

// hostPortWorker is a worker whose router workload pins /router with a host
// bind and maps 443 and 80.
func hostPortWorker(t *testing.T) *config {
	t.Helper()
	router := allowlist.Container{
		Digest:  mustDigestOrPanic(pushDigestA),
		Image:   "floor",
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/router"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/host", Kind: allowlist.MountHost, Source: "/"}}},
		Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"PATH": "/bin"}},
	}
	open := allowlist.Container{
		Digest:  mustDigestOrPanic(pushDigestA),
		Image:   "floor",
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/open"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	base := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{
		testRouterWorkload: {Containers: []allowlist.Container{router}},
		"open":             {Containers: []allowlist.Container{open}},
	}}
	if err := base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return &config{
		Allowlist: allowlistConfig{Base: base, NodeTCB: true},
		Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce},
		Worker: &workerConfig{RouterWorkload: testRouterWorkload, RouterHostPorts: []routerHostPort{
			{Protocol: "TCP", ContainerPort: 8443, HostPort: 443},
			{Protocol: "TCP", ContainerPort: 8080, HostPort: 80},
		}},
	}
}

func podIn(namespace, source string) *api.PodSandbox {
	pod := sandboxedPod()
	pod.Namespace = namespace
	pod.Annotations = map[string]string{configSourceAnnotation: source}
	return pod
}

// On a worker only the router's pod maps host ports, and only the router's,
// on every node address.
func TestWorkerAdmitsOnlyTheRoutersHostPorts(t *testing.T) {
	w := hostPortWorker(t).Worker
	withIP := routerHTTPS
	withIP.HostIP = "10.0.0.5"
	for _, tc := range []struct {
		name  string
		pod   *api.PodSandbox
		ports []ctrdresolver.HostPort
		ok    bool
	}{
		{"no host ports", podIn("default", "api"), nil, true},
		{"the router's ports", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{routerHTTPS, routerHTTP}, true},
		{"some of the router's ports", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{routerHTTPS}, true},
		{"a router port outside its namespace", podIn("default", "api"), []ctrdresolver.HostPort{routerHTTPS}, false},
		{"a static pod's port", podIn(routerNamespace, staticPodSource), []ctrdresolver.HostPort{routerHTTPS}, false},
		{"another host port", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{{Protocol: "TCP", ContainerPort: 8443, HostPort: 1019}}, false},
		{"another container port", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{{Protocol: "TCP", ContainerPort: 9000, HostPort: 443}}, false},
		{"another protocol", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{{Protocol: "UDP", ContainerPort: 8443, HostPort: 443}}, false},
		{"one node address", podIn(routerNamespace, "api"), []ctrdresolver.HostPort{withIP}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := w.admitHostPorts(tc.pod, tc.ports); (err == nil) != tc.ok {
				t.Fatalf("admitHostPorts = %v, want admitted %v", err, tc.ok)
			}
		})
	}
}

// A sandbox is refused before any container is created when it maps a host
// port other than the router's, when containerd's record of it cannot be read,
// or when that record and NRI disagree on whether it is on the node's network.
func TestWorkerRefusesASandboxMappingHostPorts(t *testing.T) {
	cfg := hostPortWorker(t)
	onNodeNetwork := func(pod *api.PodSandbox) *api.PodSandbox {
		pod.Linux.Namespaces = slices.DeleteFunc(pod.Linux.Namespaces, func(ns *api.LinuxNamespace) bool { return ns.Type == "network" })
		return pod
	}
	ports := func(p ...ctrdresolver.HostPort) ctrdresolver.SandboxNetwork {
		return ctrdresolver.SandboxNetwork{HostPorts: p}
	}
	for _, tc := range []struct {
		name    string
		pod     *api.PodSandbox
		network ctrdresolver.SandboxNetwork
		lookup  error
		ok      bool
	}{
		{"the router's pod", podIn(routerNamespace, "api"), ports(routerHTTPS), nil, true},
		{"a pod mapping no host port", podIn("default", "api"), ports(), nil, true},
		{"another pod with a host port", podIn("default", "api"), ports(ctrdresolver.HostPort{Protocol: "TCP", ContainerPort: 1019, HostPort: 1019}), nil, false},
		{"an unreadable sandbox", podIn("default", "api"), ports(), errors.New("sandbox not found"), false},
		{"a static pod on the node's network", onNodeNetwork(podIn("kube-system", staticPodSource)), ctrdresolver.SandboxNetwork{HostNetwork: true}, nil, true},
		{"a pod NRI shows on its own network, recorded on the node's", podIn("default", "api"), ctrdresolver.SandboxNetwork{HostNetwork: true}, nil, false},
		{"a pod NRI shows on the node's network, recorded on its own", onNodeNetwork(podIn("default", "api")), ports(), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(cfg)
			p.containerd = &fakeContainerd{network: func(_ context.Context, id string, pod ctrdresolver.SandboxPod) (ctrdresolver.SandboxNetwork, error) {
				if id != tc.pod.GetId() || pod.Namespace != tc.pod.GetNamespace() || pod.UID != tc.pod.GetUid() || pod.Name != tc.pod.GetName() {
					t.Errorf("looked up sandbox %s for %+v", id, pod)
				}
				return tc.network, tc.lookup
			}}
			if err := p.RunPodSandbox(context.Background(), tc.pod); (err == nil) != tc.ok {
				t.Fatalf("RunPodSandbox = %v, want admitted %v", err, tc.ok)
			}
		})
	}
}

// In the router's port-mapped pod only the router's pinned launch runs: an
// unprivileged container the base admits is refused there, through the whole
// final check, and admitted in a router pod that maps no host port.
func TestWorkerRunsOnlyTheRoutersLaunchBehindItsHostPorts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		argv   string
		bind   bool
		ports  []ctrdresolver.HostPort
		lookup error
		want   imageVerdict
	}{
		{"the router's launch", "/router", true, []ctrdresolver.HostPort{routerHTTPS}, nil, verdictAllow},
		{"another launch beside it", "/open", false, []ctrdresolver.HostPort{routerHTTPS}, nil, verdictDeny},
		{"another launch in a router pod mapping no host port", "/open", false, nil, nil, verdictAllow},
		{"an unreadable sandbox", "/router", true, nil, errors.New("sandbox not found"), verdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostPortWorker(t)
			p := newTestPlugin(cfg)
			p.containerd = &fakeContainerd{network: func(context.Context, string, ctrdresolver.SandboxPod) (ctrdresolver.SandboxNetwork, error) {
				return ctrdresolver.SandboxNetwork{HostPorts: tc.ports}, tc.lookup
			}}
			pod, ctr := podIn(routerNamespace, "api"), sandboxedContainer()
			ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool { return m.Type == "bind" })
			if tc.bind {
				ctr.Mounts = append(ctr.Mounts, &api.Mount{Destination: "/host", Type: "bind", Source: "/", Options: []string{"rbind", "rw"}})
			}
			ctr.Annotations = map[string]string{annotationImageName: testFloorImage}
			ctr.Args = []string{tc.argv}
			ctr.Env = []string{"PATH=/bin"}
			verdict, reason := p.checkContainerPhase(context.Background(), cfg, pod, ctr, testFloorImage, launchFinal)
			if verdict != tc.want {
				t.Fatalf("checkContainerPhase = %d %q, want %d", verdict, reason, tc.want)
			}
			if tc.want == verdictDeny && !strings.Contains(reason, "host ports") {
				t.Fatalf("reason = %q, want the host ports named", reason)
			}
		})
	}
}
