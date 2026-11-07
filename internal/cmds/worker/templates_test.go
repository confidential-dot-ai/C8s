package worker

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

// imageTree is the worker profile's tree, as the image holds it.
const imageTree = "../../../images/node-guest/worker/mkosi.extra"

// The worker image's static pods each build a floor entry, render with this
// boot's values, and mount only files the image holds from under
// /usr/lib/c8s/worker.
func TestWorkerImageStaticPods(t *testing.T) {
	templates, err := readTemplates(filepath.Join(imageTree, staticPodTemplates))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(maps.Keys(templates)), []string{"cilium.yaml", "coredns.yaml", "kube-proxy.yaml"}; !slices.Equal(got, want) {
		t.Fatalf("templates = %v, want %v", got, want)
	}
	for file, data := range templates {
		if _, _, err := staticPodEntry(data); err != nil {
			t.Errorf("%s builds no floor entry: %v", file, err)
		}
	}
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, staticPodTemplates), os.DirFS(filepath.Join(imageTree, staticPodTemplates))); err != nil {
		t.Fatal(err)
	}
	pods, err := staticPods(root, map[string]string{nodeservices.NodeNamePlaceholder: "n-0123456789abcdef", nodeservices.PodCIDRPlaceholder: "10.42.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range pods {
		pod, err := decodeStaticPod(rendered.Data)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range pod.Spec.Volumes {
			if v.HostPath == nil || !strings.HasPrefix(v.HostPath.Path, "/usr/lib/c8s/worker/") {
				continue
			}
			if _, err := os.Stat(filepath.Join(imageTree, v.HostPath.Path)); err != nil {
				t.Errorf("%s mounts %s, which the image does not hold: %v", rendered.Name, v.HostPath.Path, err)
			}
		}
		if rendered.Name == "kube-proxy.yaml" && !slices.Contains(pod.Spec.Containers[0].Args, "--cluster-cidr=10.42.0.0/16") {
			t.Errorf("kube-proxy args = %v, want this worker's pod range", pod.Spec.Containers[0].Args)
		}
	}
}

// Cilium ignores a configuration key it does not read, and some default on, so
// the worker's measured configuration states each one the worker rests on: no
// configuration, secrets or L7 proxy from the control plane, no listener on a
// node address beyond its own, kube-proxy left to route Services, and the
// datapath the mesh expects.
func TestWorkerCiliumConfiguration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(imageTree, "usr/lib/c8s/worker/cilium/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]string
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"enable-dynamic-config":           "false",
		"enable-policy-secrets-sync":      "false",
		"enable-l7-proxy":                 "false",
		"enable-hubble":                   "false",
		"enable-health-checking":          "false",
		"enable-endpoint-health-checking": "false",
		"kube-proxy-replacement":          "false",
		"bpf-lb-sock":                     "false",
		"datapath-mode":                   "veth",
		"routing-mode":                    "tunnel",
		"tunnel-protocol":                 "vxlan",
		"tunnel-port":                     "8473",
		"ipam":                            "kubernetes",
		"k8s-require-ipv4-pod-cidr":       "true",
		"k8s-kubeconfig-path":             "/var/lib/kubelet/kubeconfig",
	} {
		if got, ok := config[key]; !ok || got != want {
			t.Errorf("%s = %q (set %v), want %q", key, got, ok, want)
		}
	}
	for _, listener := range []string{"proxy-prometheus-port", "prometheus-serve-addr", "hubble-listen-address", "hubble-metrics-server"} {
		if value, ok := config[listener]; ok {
			t.Errorf("%s = %q opens a listener on the node", listener, value)
		}
	}
}

// kube-proxy serves only the iptables proxier on the worker, with no Service
// reaching a node's loopback and its health and metrics on loopback alone; the
// CoreDNS it fronts reads the Corefile the image holds.
func TestWorkerKubeProxyAndCoreDNS(t *testing.T) {
	proxy, err := os.ReadFile(filepath.Join(imageTree, staticPodTemplates, "kube-proxy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pod, err := decodeStaticPod(proxy)
	if err != nil {
		t.Fatal(err)
	}
	args := pod.Spec.Containers[0].Args
	for _, want := range []string{"--proxy-mode=iptables", "--iptables-localhost-nodeports=false", "--healthz-bind-address=127.0.0.1"} {
		if !slices.Contains(args, want) {
			t.Errorf("kube-proxy args %v lack %s", args, want)
		}
	}
	if i := slices.IndexFunc(args, func(a string) bool { return strings.HasPrefix(a, "--metrics-bind-address=") }); i >= 0 && !strings.HasPrefix(args[i], "--metrics-bind-address=127.0.0.1:") {
		t.Errorf("kube-proxy serves metrics at %s, off loopback", args[i])
	}
	dns, err := os.ReadFile(filepath.Join(imageTree, staticPodTemplates, "coredns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if pod, err = decodeStaticPod(dns); err != nil {
		t.Fatal(err)
	}
	if args := pod.Spec.Containers[0].Args; !slices.Equal(args, []string{"-conf", "/etc/coredns/Corefile"}) {
		t.Fatalf("coredns args = %v, want the Corefile the image mounts at /etc/coredns", args)
	}
	corefile, err := os.ReadFile(filepath.Join(imageTree, "usr/lib/c8s/worker/coredns/Corefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(corefile), "kubernetes cluster.local") || !strings.Contains(string(corefile), "kubeconfig /var/lib/kubelet/kubeconfig") {
		t.Fatalf("Corefile serves no cluster.local through the kubelet's kubeconfig:\n%s", corefile)
	}
}

// nodeCertificateBinding is the group a binding grants and the role it binds,
// of the bindings a kubelet's certificates rest on.
type nodeCertificateBinding struct {
	group string
	role  string
}

// grantsNodeCertificates holds of a binding that lets a node request a
// certificate or have one approved without an admin.
func grantsNodeCertificates(b nodeCertificateBinding) bool {
	return b.group == "system:bootstrappers" ||
		b.role == "system:node-bootstrapper" ||
		strings.HasPrefix(b.role, "system:certificates.k8s.io:")
}

// A worker's kubelet joins with a bootstrap token and rotates the client
// certificate it gets, so the render binds the three grants that carry it, and
// binds nothing else a node's certificates rest on.
func TestWorkerKubeletCertificateBindings(t *testing.T) {
	objects, err := ControlPlaneObjects(&Document{Kubernetes: Kubernetes{ClusterDNS: "10.53.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]nodeCertificateBinding{
		"c8s-worker-bootstrap":             {"system:bootstrappers", "system:node-bootstrapper"},
		"c8s-worker-bootstrap-client-cert": {"system:bootstrappers", "system:certificates.k8s.io:certificatesigningrequests:nodeclient"},
		"c8s-worker-client-cert-renewal":   {"system:nodes", "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient"},
	}
	got := map[string]nodeCertificateBinding{}
	for _, doc := range strings.Split(string(objects), "\n---\n") {
		var binding rbacv1.ClusterRoleBinding
		if err := yaml.Unmarshal([]byte(doc), &binding); err != nil || binding.Kind != "ClusterRoleBinding" {
			continue
		}
		if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != rbacv1.GroupKind {
			continue
		}
		b := nodeCertificateBinding{binding.Subjects[0].Name, binding.RoleRef.Name}
		if grantsNodeCertificates(b) {
			got[binding.Name] = b
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("certificate bindings = %v, want %v", got, want)
	}
}

// The control plane's kube-dns Service, at the document's clusterDNS, selects
// the CoreDNS static pod on the asking pod's own node.
func TestKubeDNSSelectsTheWorkersCoreDNS(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(imageTree, staticPodTemplates, "coredns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pod, err := decodeStaticPod(data)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := ControlPlaneObjects(&Document{Kubernetes: Kubernetes{ClusterDNS: "10.53.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	var service *corev1.Service
	for _, doc := range strings.Split(string(objects), "\n---\n") {
		var s corev1.Service
		if err := yaml.Unmarshal([]byte(doc), &s); err == nil && s.Kind == "Service" && s.Name == "kube-dns" {
			service = &s
		}
	}
	if service == nil || len(service.Spec.Selector) == 0 || service.Spec.ClusterIP != "10.53.0.10" {
		t.Fatalf("kube-dns = %+v, want a selector and the document's clusterDNS", service)
	}
	if p := service.Spec.InternalTrafficPolicy; p == nil || *p != corev1.ServiceInternalTrafficPolicyLocal {
		t.Fatalf("kube-dns internalTrafficPolicy = %v, want Local: a lookup leaves its node otherwise", p)
	}
	for k, v := range service.Spec.Selector {
		if pod.Labels[k] != v {
			t.Fatalf("kube-dns selects %v, which the CoreDNS static pod's labels %v do not carry", service.Spec.Selector, pod.Labels)
		}
	}
}

// The kubelet dials the socket the worker image's containerd binds.
func TestKubeletDialsTheImagesContainerd(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(imageTree, "etc/containerd/config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Plugins map[string]struct {
			Address string `toml:"address"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if want := "unix://" + config.Plugins["io.containerd.server.v1.grpc"].Address; containerdEndpoint != want {
		t.Errorf("the kubelet's runtime endpoint is %s, and the image's containerd binds %s", containerdEndpoint, want)
	}
}
