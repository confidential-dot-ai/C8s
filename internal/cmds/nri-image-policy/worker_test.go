package nriimagepolicy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const testRouterWorkload = "c8s-router-0123456789ab"

// workerDocument is a worker's measured config: a router workload pinning
// its launch and a host bind, beside the mesh role it runs with.
const workerDocument = `
allowlist:
  node_tcb: true
  base:
    schema: ` + allowlist.Schema + `
    workloads:
      mesh:
        containers:
          - digest: "` + pushDigestA + `"
            role: mesh
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
      ` + testRouterWorkload + `:
        containers:
          - digest: "` + pushDigestB + `"
            command: {policy: exact, argv: [/router]}
            args: {policy: deny}
            mounts:
              policy: exact
              rules:
                - {destination: /host, kind: host, source: /}
            env: {policy: exact, values: {PATH: /bin}}
policy:
  mode: fail-closed
  fatal_existing: true
  boot_marker_path: /run/nri-image-policy/registered
mesh:
  resolver: "10.43.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
worker:
  router_workload: ` + testRouterWorkload + `
`

// A worker trusts its static pods and the router's pinned launch, never a
// namespace, and refuses a config that would let it.
func TestWorkerConfigValidation(t *testing.T) {
	routerContainer := func(cfg *config) *allowlist.Container {
		return &cfg.Allowlist.Base.Workloads[testRouterWorkload].Containers[0]
	}
	for _, tc := range []struct {
		name   string
		change func(*config)
		want   string
	}{
		{"a worker", func(*config) {}, ""},
		{"no node TCB", func(c *config) { c.Allowlist.NodeTCB = false }, "allowlist.node_tcb"},
		{"no base", func(c *config) { c.Allowlist.Base = nil }, "allowlist.base"},
		{"an audited policy", func(c *config) { c.Policy.Mode = ModeAudit }, "policy.mode"},
		{"no worker", func(c *config) { c.Worker = nil }, ""},
		{"an audited sandbox", func(c *config) { c.Policy.Sandbox = SandboxAudit }, "policy.sandbox"},
		{"containers without an image annotation", func(c *config) { c.Policy.DenyMissingAnnotation = false }, "deny_missing_annotation"},
		{"a mesh-exempt namespace", func(c *config) { c.Mesh.ExemptNamespaces = []string{"kube-system"} }, "mesh.exempt_namespaces"},
		{"no router workload", func(c *config) { c.Worker.RouterWorkload = "" }, "not an allowlist.base workload"},
		{"an unknown router workload", func(c *config) { c.Worker.RouterWorkload = "c8s-router-other" }, "not an allowlist.base workload"},
		{"an open router command", func(c *config) { routerContainer(c).Command = allowlist.ArgvPolicy{Policy: allowlist.PolicyAny} }, "does not pin its launch"},
		{"open router args", func(c *config) { routerContainer(c).Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyAny} }, "does not pin its launch"},
		{"open router mounts", func(c *config) { routerContainer(c).Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyAny} }, "does not pin its launch"},
		{"an open router environment", func(c *config) { routerContainer(c).Env = allowlist.EnvPolicy{Policy: allowlist.PolicyAny} }, "does not pin its launch"},
		{"an open router init container", func(c *config) {
			w := c.Allowlist.Base.Workloads[testRouterWorkload]
			open := *routerContainer(c)
			open.Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyAny}
			w.InitContainers = []allowlist.Container{open}
			c.Allowlist.Base.Workloads[testRouterWorkload] = w
		}, "does not pin its launch"},
		{"a router data mount", func(c *config) {
			r := routerContainer(c)
			r.Mounts.Rules = append(r.Mounts.Rules, allowlist.MountRule{Destination: allowlist.DataMountPrefix + "keys", Kind: allowlist.MountData})
		}, "mounts other than"},
		{"router Service links", func(c *config) { routerContainer(c).Env.ServiceLinks = true }, "Service links"},
		{"a router host port without a protocol", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{ContainerPort: 8443, HostPort: 443}}
		}, "protocol"},
		{"a router host port of zero", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{Protocol: "TCP", ContainerPort: 8443}}
		}, "non-zero"},
		{"a router container port of zero", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{Protocol: "TCP", HostPort: 443}}
		}, "non-zero"},
		{"a lowercase protocol", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{Protocol: "tcp", ContainerPort: 8443, HostPort: 443}}
		}, "protocol"},
		{"one host port on two protocols", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{Protocol: "TCP", ContainerPort: 8443, HostPort: 443}, {Protocol: "UDP", ContainerPort: 8443, HostPort: 443}}
		}, ""},
		{"a router host port mapped twice", func(c *config) {
			c.Worker.RouterHostPorts = []routerHostPort{{Protocol: "TCP", ContainerPort: 8443, HostPort: 443}, {Protocol: "TCP", ContainerPort: 9443, HostPort: 443}}
		}, "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig([]byte(workerDocument))
			if err != nil {
				t.Fatalf("the worker fixture was refused: %v", err)
			}
			tc.change(cfg)
			err = cfg.validateWorker()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate = %v, want a worker accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Validate = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// On a worker, an API pod holds host privilege only as the router, in its
// namespace, for its pinned host binds alone; a static pod holds it only for a
// pinned launch. A copy of any other pinned launch, the router's outside its
// namespace, from another image, with more privilege, another bind or
// environment, and a pod without a source, are refused.
func TestWorkerExemptsOnlyTheRoutersBindsAndPinnedStaticPods(t *testing.T) {
	pinned := func(argv string) allowlist.Container {
		return allowlist.Container{
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{argv}},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
			Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{
				{Destination: "/host", Kind: allowlist.MountHost, Source: "/"},
			}},
			Env: allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"PATH": "/bin"}},
		}
	}
	open := allowlist.Container{
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/open"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	hostBind := func(ctr *api.Container) {
		ctr.Mounts = append(ctr.Mounts, &api.Mount{Destination: "/host", Type: "bind", Source: "/", Options: []string{"rbind", "rw"}})
	}
	extraBind := func(ctr *api.Container) {
		hostBind(ctr)
		ctr.Mounts = append(ctr.Mounts, &api.Mount{Destination: "/etc/kubernetes", Type: "bind", Source: "/etc/kubernetes", Options: []string{"rbind", "ro"}})
	}
	privileged := func(ctr *api.Container) {
		hostBind(ctr)
		ctr.Linux.Namespaces = slices.DeleteFunc(ctr.Linux.Namespaces, func(ns *api.LinuxNamespace) bool { return ns.Type == cgroupNamespace })
	}
	hostPID := func(pod *api.PodSandbox) {
		pod.Linux.Namespaces = slices.DeleteFunc(pod.Linux.Namespaces, func(ns *api.LinuxNamespace) bool { return ns.Type == "pid" })
	}
	hostNetwork := func(pod *api.PodSandbox) {
		pod.Linux.Namespaces = slices.DeleteFunc(pod.Linux.Namespaces, func(ns *api.LinuxNamespace) bool {
			return ns.Type == "network" || ns.Type == "uts"
		})
	}
	tests := []struct {
		name         string
		source       string
		namespace    string
		pod          func(*api.PodSandbox)
		ctr          func(*api.Container)
		argv         string
		env          string
		routerDigest string
		want         imageVerdict
	}{
		{name: "the router's launch and binds", source: "api", namespace: routerNamespace, ctr: hostBind, argv: "/router", want: verdictAllow},
		{name: "the router's launch with another bind", source: "api", namespace: routerNamespace, ctr: extraBind, argv: "/router", want: verdictDeny},
		{name: "the router's launch with another environment", source: "api", namespace: routerNamespace, ctr: hostBind, argv: "/router", env: "PATH=/tmp", want: verdictDeny},
		{name: "the router's launch from another image", source: "api", namespace: routerNamespace, ctr: hostBind, argv: "/router", routerDigest: pushDigestB, want: verdictDeny},
		{name: "the router's launch on the host PID namespace", source: "api", namespace: routerNamespace, pod: hostPID, ctr: hostBind, argv: "/router", want: verdictDeny},
		{name: "the router's launch outside its namespace", source: "api", namespace: "kube-system", ctr: hostBind, argv: "/router", want: verdictDeny},
		{name: "the router's launch on the host network", source: "api", namespace: routerNamespace, pod: hostNetwork, ctr: hostBind, argv: "/router", want: verdictDeny},
		{name: "the router's launch, privileged", source: "api", namespace: routerNamespace, ctr: privileged, argv: "/router", want: verdictDeny},
		{name: "a copy of a pinned static pod", source: "api", namespace: routerNamespace, ctr: hostBind, argv: "/floor", want: verdictDeny},
		{name: "a pod without a source, copying a static pod", namespace: "kube-system", ctr: privileged, argv: "/floor", want: verdictDeny},
		{name: "a pinned static pod", source: staticPodSource, namespace: "kube-system", pod: hostNetwork, ctr: privileged, argv: "/floor", want: verdictAllow},
		{name: "a static pod an open entry admits", source: staticPodSource, namespace: "kube-system", ctr: privileged, argv: "/open", want: verdictDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workloads := map[string]allowlist.Workload{
				testRouterWorkload: {Containers: []allowlist.Container{pinned("/router")}},
				"floor":            {Containers: []allowlist.Container{pinned("/floor")}},
				"open":             {Containers: []allowlist.Container{open}},
			}
			for name, w := range workloads {
				w.Containers[0].Digest = mustDigestOrPanic(pushDigestA)
				w.Containers[0].Image = "floor"
				workloads[name] = w
			}
			if tt.routerDigest != "" {
				workloads[testRouterWorkload].Containers[0].Digest = mustDigestOrPanic(tt.routerDigest)
			}
			base := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: workloads}
			if err := base.Normalize(); err != nil {
				t.Fatal(err)
			}
			cfg := &config{
				Allowlist: allowlistConfig{Base: base, NodeTCB: true},
				Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce},
				Worker:    &workerConfig{RouterWorkload: testRouterWorkload},
			}
			p := newTestPlugin(cfg)
			p.policy = newPolicyStore(base)

			pod, ctr := sandboxedPod(), sandboxedContainer()
			ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool { return m.Type == "bind" })
			pod.Namespace = tt.namespace
			pod.Annotations = map[string]string{}
			if tt.source != "" {
				pod.Annotations[configSourceAnnotation] = tt.source
			}
			if tt.pod != nil {
				tt.pod(pod)
			}
			tt.ctr(ctr)
			ctr.Annotations = map[string]string{annotationImageName: testFloorImage}
			ctr.Args = []string{tt.argv}
			ctr.Env = []string{"PATH=/bin"}
			if tt.env != "" {
				ctr.Env = []string{tt.env}
			}
			mounts := newMountObserver(nil, nodeMounts{}).Observe(pod, ctr)
			verdict, reason := p.checkSandbox(context.Background(), cfg, pod, ctr, testFloorImage, containerEnv(ctr), mounts)
			if verdict != tt.want {
				t.Fatalf("checkSandbox = %d %q, want %d", verdict, reason, tt.want)
			}
		})
	}
}

// A pod's traffic leaves it through the mesh or not at all: on a worker, whose
// config exempts no namespace, the mesh protects every API pod with its own
// network namespace wherever the control plane puts it. A static pod, such as
// a worker's CoreDNS, is the node's own on any node.
func TestMeshGateHostsBySource(t *testing.T) {
	worker, _ := gateWithPod(meshPod("default", "pod", testNetNS))
	worker.policy.ExemptNamespaces = nil
	server, _ := gateWithPod(meshPod("default", "pod", testNetNS))
	withSource := func(pod *api.PodSandbox, source string) *api.PodSandbox {
		pod.Annotations = map[string]string{configSourceAnnotation: source}
		return pod
	}
	for _, tc := range []struct {
		name  string
		gate  *meshGate
		pod   *api.PodSandbox
		hosts bool
	}{
		{"a worker's API pod in kube-system", worker, withSource(meshPod("kube-system", "app", testNetNS), "api"), true},
		{"a worker's pod without a source", worker, meshPod("kube-system", "app", testNetNS), true},
		{"a worker's static pod", worker, withSource(meshPod("kube-system", "coredns", testNetNS), staticPodSource), false},
		{"a server's static pod outside the exempt namespaces", server, withSource(meshPod("default", "static", testNetNS), staticPodSource), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.gate.hosts(tc.pod); got != tc.hosts {
				t.Fatalf("hosts = %v, want %v", got, tc.hosts)
			}
		})
	}
}

// A worker's registry is its control plane's, so a tag is refused even for an
// image the base admits, which elsewhere keeps its tags.
func TestWorkerAdmitsOnlyDigestReferences(t *testing.T) {
	base := anyAllowlist(map[string]string{pushDigestB: "image-b"})
	worker := &workerConfig{RouterWorkload: testRouterWorkload}
	for _, tt := range []struct {
		name   string
		worker *workerConfig
		ref    string
		want   imageVerdict
	}{
		{"a worker refuses a base tag", worker, "registry/base:v1", verdictDeny},
		{"a worker admits a base digest", worker, "registry/base@" + pushDigestB, verdictAllow},
		{"a server admits a base tag", nil, "registry/base:v1", verdictAllow},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newCachedPlugin(&config{
				Allowlist: allowlistConfig{Base: base},
				Policy:    policyConfig{Mode: ModeFailClosed},
				Worker:    tt.worker,
			}, anyAllowlist(map[string]string{}))
			p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
				return pushDigestB, nil
			}}
			verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
				Namespace: "kube-system", PodName: "pod", Container: "ctr",
				ImageRef: tt.ref, Mounts: []allowlist.ObservedMount{},
			}, launchFinal)
			if verdict != tt.want {
				t.Fatalf("verdict %d, want %d (reason %q)", verdict, tt.want, reason)
			}
		})
	}
}
