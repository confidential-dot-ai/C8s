package worker

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const agentDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// agentTemplate is a static pod with an init container, host and emptyDir
// mounts, a declared value and the node name from the kubelet.
const agentTemplate = `apiVersion: v1
kind: Pod
metadata:
  name: agent
  namespace: kube-system
spec:
  hostNetwork: true
  dnsPolicy: Default
  enableServiceLinks: false
  initContainers:
    - name: install
      image: quay.io/example/agent:v1@` + agentDigest + `
      command: [/install]
      volumeMounts:
        - {name: cni, mountPath: /host/opt/cni/bin}
  containers:
    - name: agent
      image: quay.io/example/agent@` + agentDigest + `
      command: [/agent]
      args: ["--cluster-cidr=${POD_CIDR}", "--node=${NODE_NAME}"]
      env:
        - {name: PATH, value: /bin}
        - name: NODE
          valueFrom: {fieldRef: {fieldPath: spec.nodeName}}
      volumeMounts:
        - {name: kubeconfig, mountPath: /var/lib/kubelet/kubeconfig, readOnly: true}
        - {name: run, mountPath: /run/agent}
  volumes:
    - {name: cni, hostPath: {path: /opt/cni/bin}}
    - {name: kubeconfig, hostPath: {path: /var/lib/kubelet/kubeconfig, type: File}}
    - {name: run, emptyDir: {medium: Memory}}
`

// observed is the agent's launch as the kubelet and containerd run it: argv,
// the environment it declared with the variables they add, its mounts and a
// mount the runtime adds.
func observed(t *testing.T, digest string, argv []string, declared ...string) allowlist.RunningContainer {
	t.Helper()
	env, err := allowlist.ObserveEnv(append(declared, "HOSTNAME=n-1", "KUBERNETES_SERVICE_HOST=10.200.0.1", "KUBERNETES_SERVICE_PORT=443"))
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig, err := allowlist.HostSourceDigest("/var/lib/kubelet/kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	return allowlist.RunningContainer{Digest: digest, Argv: argv, Env: env, Mounts: []allowlist.ObservedMount{
		{Destination: "/etc/hosts", Class: allowlist.MountPlatform},
		{Destination: "/var/lib/kubelet/kubeconfig", Class: allowlist.MountHost, HostSourceDigest: kubeconfig, ReadOnly: true},
		{Destination: "/run/agent", Class: allowlist.MountEmptyDir, Volume: "run", Storage: allowlist.MountMemory},
	}}
}

// withMounts is launch with mounts in place of its own.
func withMounts(launch allowlist.RunningContainer, mounts ...allowlist.ObservedMount) allowlist.RunningContainer {
	launch.Mounts = mounts
	return launch
}

// A template's entry pins each container's digest, argv, environment and
// mounts; staged, it admits the pod stage renders and no other launch.
func TestStaticPodEntryPinsTheTemplate(t *testing.T) {
	name, w, err := staticPodEntry([]byte(agentTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if name != "agent" || len(w.InitContainers) != 1 || len(w.Containers) != 1 || !w.StaticPod {
		t.Fatalf("entry %s = %+v, want the pod's init container and container, marked a static pod's", name, w)
	}
	agent := w.Containers[0]
	if !agent.LaunchPinned() || agent.Digest.String() != agentDigest {
		t.Fatalf("agent = %+v, want its launch pinned at %s", agent, agentDigest)
	}
	wantRules := []allowlist.MountRule{
		{Destination: "/var/lib/kubelet/kubeconfig", Kind: allowlist.MountHost, Source: "/var/lib/kubelet/kubeconfig", ReadOnly: true},
		{Destination: "/run/agent", Kind: allowlist.MountEmptyDir, Source: "run"},
	}
	if agent.Mounts.Policy != allowlist.PolicyExact || !reflect.DeepEqual(agent.Mounts.Rules, wantRules) {
		t.Fatalf("agent mounts = %+v, want %+v", agent.Mounts, wantRules)
	}
	if install := w.InitContainers[0]; install.Args.Policy != allowlist.PolicyDeny || !install.LaunchPinned() {
		t.Fatalf("install = %+v, want its launch pinned and no args", install)
	}

	root := workerRoot(t)
	floor, err := Floor(renderedTemplate(t), routerSeed("/run/c8s-node/cds.json"), map[string][]byte{"agent.yaml": []byte(agentTemplate)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s/image-policy.yaml"), floor, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, staticPodTemplates, "kube-proxy.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, staticPodTemplates, "agent.yaml"), []byte(agentTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	data := workerDocumentBytes(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}
	if staged := stagedWorkloads(t, root); !staged["agent"].StaticPod || staged[testRouterEntry].StaticPod {
		t.Fatal("the staged floor marks another entry than the agent's a static pod's")
	}
	base := stagedBase(t, root)
	node := "n-10-0-0-7"
	argv := []string{"/agent", "--cluster-cidr=10.100.0.0/16", "--node=" + node}
	launch := observed(t, agentDigest, argv, "PATH=/bin", "NODE="+node)
	if !base.AdmitsContainer(launch) {
		t.Fatalf("the staged floor refuses the rendered agent's launch %q", argv)
	}
	cni, err := allowlist.HostSourceDigest("/opt/cni/bin")
	if err != nil {
		t.Fatal(err)
	}
	install := withMounts(observed(t, agentDigest, []string{"/install"}), allowlist.ObservedMount{Destination: "/host/opt/cni/bin", Class: allowlist.MountHost, HostSourceDigest: cni})
	if !base.AdmitsContainer(install) {
		t.Fatal("the staged floor refuses the rendered install init container")
	}
	other, err := allowlist.HostSourceDigest("/etc")
	if err != nil {
		t.Fatal(err)
	}
	for what, launch := range map[string]allowlist.RunningContainer{
		"another pod range":      observed(t, agentDigest, []string{"/agent", "--cluster-cidr=10.99.0.0/16", "--node=" + node}, "PATH=/bin", "NODE="+node),
		"another declared value": observed(t, agentDigest, argv, "PATH=/tmp", "NODE="+node),
		"an undeclared variable": observed(t, agentDigest, argv, "PATH=/bin", "NODE="+node, "CILIUM_DEBUG=true"),
		"no node name":           observed(t, agentDigest, argv, "PATH=/bin"),
		"another image":          observed(t, "sha256:"+strings.Repeat("e", 64), argv, "PATH=/bin", "NODE="+node),
		"another argument added": observed(t, agentDigest, append(slices.Clone(argv), "--debug"), "PATH=/bin", "NODE="+node),
		"a writable kubeconfig":  withMounts(launch, allowlist.ObservedMount{Destination: "/var/lib/kubelet/kubeconfig", Class: allowlist.MountHost, HostSourceDigest: launch.Mounts[1].HostSourceDigest}, launch.Mounts[2]),
		"another host source":    withMounts(launch, allowlist.ObservedMount{Destination: "/var/lib/kubelet/kubeconfig", Class: allowlist.MountHost, HostSourceDigest: other, ReadOnly: true}, launch.Mounts[2]),
		"a mount missing":        withMounts(launch, launch.Mounts[1]),
		"an extra mount":         withMounts(launch, append(slices.Clone(launch.Mounts), allowlist.ObservedMount{Destination: "/host/etc", Class: allowlist.MountHost, HostSourceDigest: other})...),
	} {
		if base.AdmitsContainer(launch) {
			t.Errorf("the staged floor admits the agent with %s", what)
		}
	}
	rendered, err := staticPods(root, workerValues(node, mustDocument(t, data).Kubernetes))
	if err != nil {
		t.Fatal(err)
	}
	if len(rendered) != 1 || !strings.Contains(string(rendered[0].Data), "--cluster-cidr=10.100.0.0/16") {
		t.Fatalf("rendered %v, want the agent with this worker's pod range", fileNames(rendered))
	}
}

func mustDocument(t *testing.T, data []byte) *Document {
	t.Helper()
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func fileNames(files []fileutil.NewFile) []string {
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	return names
}

// A template whose pod could take anything from the control plane, or reach
// the node's protected paths, builds no floor.
func TestStaticPodEntryRefusesTemplatesTheControlPlaneCouldShape(t *testing.T) {
	for _, tc := range []struct{ name, old, new, want string }{
		{"a tag", "agent@" + agentDigest + "\n      command: [/agent]", "agent:v1\n      command: [/agent]", "not referenced by digest"},
		{"no command", "      command: [/agent]\n", "", "names no command"},
		{"Service links", "enableServiceLinks: false", "enableServiceLinks: true", "enableServiceLinks must be false"},
		{"default Service links", "  enableServiceLinks: false\n", "", "enableServiceLinks must be false"},
		{"a runtime class", "  hostNetwork: true\n", "  hostNetwork: true\n  runtimeClassName: other\n", "runtime class"},
		{"a service account", "  hostNetwork: true\n", "  hostNetwork: true\n  serviceAccountName: agent\n", "service account"},
		{"pull secrets", "  hostNetwork: true\n", "  hostNetwork: true\n  imagePullSecrets: [{name: registry}]\n", "pull secrets"},
		{"an ephemeral container", "  hostNetwork: true\n", "  hostNetwork: true\n  ephemeralContainers: [{name: debug, image: debug}]\n", "ephemeral containers"},
		{"a hostPath that is also an emptyDir", "path: /opt/cni/bin", "path: /opt/cni/bin}, emptyDir: {medium: Memory", "neither a hostPath nor an in-memory emptyDir"},
		{"a ConfigMap volume", "{name: run, emptyDir: {medium: Memory}}", "{name: run, configMap: {name: agent}}", "neither a hostPath nor an in-memory emptyDir"},
		{"a relative hostPath", "path: /opt/cni/bin", "path: opt/cni/bin", "neither a hostPath nor an in-memory emptyDir"},
		{"a disk-backed emptyDir", "emptyDir: {medium: Memory}", "emptyDir: {}", "neither a hostPath nor an in-memory emptyDir"},
		{"a read-only emptyDir", "mountPath: /run/agent}", "mountPath: /run/agent, readOnly: true}", "emptyDir run read-only"},
		{"cluster DNS", "dnsPolicy: Default", "dnsPolicy: ClusterFirstWithHostNet", "dnsPolicy must be Default"},
		{"no DNS policy", "  dnsPolicy: Default\n", "", "dnsPolicy must be Default"},
		{"a deprecated service account", "  hostNetwork: true\n", "  hostNetwork: true\n  serviceAccount: agent\n", "service account"},
		{"a resource claim", "  hostNetwork: true\n", "  hostNetwork: true\n  resourceClaims: [{name: gpu, resourceClaimName: gpu}]\n", "resource claims"},
		{"a container's resource claim", "      command: [/agent]\n", "      command: [/agent]\n      resources: {claims: [{name: gpu}]}\n", "resource claims"},
		{"an expanded argument", "--node=${NODE_NAME}", "--node=$(NODE)", "expands"},
		{"an escaped value", "{name: PATH, value: /bin}", "{name: PATH, value: $$bin}", "expands"},
		{"a subPath", "mountPath: /run/agent}", "mountPath: /run/agent, subPath: x}", "subPath"},
		{"envFrom", "      env:\n", "      envFrom: [{configMapRef: {name: agent}}]\n      env:\n", "envFrom"},
		{"a Secret value", "valueFrom: {fieldRef: {fieldPath: spec.nodeName}}", "valueFrom: {secretKeyRef: {name: s, key: k}}", "other than spec.nodeName"},
		{"the pod's IP", "fieldPath: spec.nodeName", "fieldPath: status.podIP", "other than spec.nodeName"},
		{"an undeclared volume", "{name: run, mountPath: /run/agent}", "{name: other, mountPath: /run/agent}", "undeclared volume"},
		{"not a Pod", "kind: Pod", "kind: Deployment", "not a named v1 Pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := strings.Replace(agentTemplate, tc.old, tc.new, 1)
			if template == agentTemplate {
				t.Fatalf("agentTemplate holds no %q", tc.old)
			}
			if _, _, err := staticPodEntry([]byte(template)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("staticPodEntry = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
	if _, err := Floor(renderedTemplate(t), routerSeed("/run/c8s-node/cds.json"), map[string][]byte{"agent.yaml": []byte(strings.Replace(agentTemplate, "name: agent\n  namespace", "name: c8s-mesh-endpoint\n  namespace", 1))}); err == nil || !strings.Contains(err.Error(), "named as another entry") {
		t.Fatalf("Floor = %v, want a template named as a platform role refused", err)
	}
}
