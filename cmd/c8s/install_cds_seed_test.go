//go:build !c8s_node

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A component entry this release renders and the named CDS does not serve is a
// component no node would admit, so the install refuses before it applies
// anything.
func TestCheckSeedServed(t *testing.T) {
	seed, err := pkgallowlist.ParseJSON([]byte(testSeedDocument("app")))
	if err != nil {
		t.Fatal(err)
	}
	served, err := cdsPinConfig(cdsPinDocument(t, []string{"app"}, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(seed, served); err != nil {
		t.Fatalf("checkSeedServed with the same entry = %v", err)
	}
	other, err := cdsPinConfig(cdsPinDocument(t, []string{"other"}, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(seed, other); err == nil {
		t.Fatal("an unserved component entry was accepted")
	}
	// The same name under another policy is a different component shape.
	widened, err := pkgallowlist.ParseJSON([]byte(strings.Replace(testSeedDocument("app"), `"command":{"policy":"any"}`, `"command":{"policy":"exact","argv":["/app"]}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(widened, served); err == nil {
		t.Fatal("an entry of another shape was accepted under the same name")
	}
}

// --allowlist-seed-out is the render an operator needs before the CDS exists:
// it writes the component entries and touches neither the cluster nor helm.
func TestInstallWritesTheAllowlistSeedAndStops(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	out := s.f.dir + "/seed.json"
	values := s.f.dir + "/values.yaml"
	if err := os.WriteFile(values, []byte("router:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runC8s(t, "install", "--platform=aks-snp", "--wait=false", "--force", "-f", values, flagArg(flagSeedOut), out); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The seed is rendered from the values the release carries, the
	// operator's files among them.
	render := lineIndex(s.f.calls(t), "helm template ")
	if render < 0 || !strings.Contains(s.f.calls(t)[render], "-f "+values) {
		t.Fatalf("the seed render does not carry the operator's values: %v", s.f.calls(t))
	}
	document, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pkgallowlist.ParseJSON(document)
	if err != nil {
		t.Fatalf("the written seed does not parse: %v\n%s", err, document)
	}
	if _, ok := seed.Workloads[installSeedEntryName]; !ok {
		t.Fatalf("written seed = %v, want the rendered component entries", seed.Workloads)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm upgrade")
	mustNotContainPrefix(t, calls, "kubectl apply")

	// The render precedes the CDS it is configured into, so it names none.
	err = runC8s(t, "install", "--platform=aks-snp", "--force", flagArg(flagSeedOut), out,
		flagArg(flagCDSAddress), "10.9.9.9:8443",
		flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "192.0.2.0/24"))
	if err == nil || !strings.Contains(err.Error(), "runs before") {
		t.Fatalf("install = %v, want the refusal to name a CDS while writing its seed", err)
	}
}

// The CDS dials a node's admission inventory inside its configured subnets, so
// a subnet holding pod addresses would let a pod answer as that inventory.
func TestInstallRefusesNodeSubnetsHoldingPodAddresses(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))

	// The stubbed node assigns pod addresses from 10.42.0.0/24.
	err := runC8s(t, "install", "--platform=aks-snp", "--wait=false", "--force",
		flagArg(flagCDSAddress), "10.9.9.9:8443",
		flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "10.42.0.0/16"))
	if err == nil || !strings.Contains(err.Error(), "where this cluster's pods answer") {
		t.Fatalf("install = %v, want the overlapping node-subnet refusal", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// A CNI that owns IP allocation leaves spec.podCIDR empty, so nothing in the
// cluster states the range the CDS's node subnets must stay out of: the
// operator states it with --pod-cidr, and the pods answering check the claim.
func TestInstallPodCIDRWhereNodesPublishNone(t *testing.T) {
	t.Run("refused without --pod-cidr", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, podAt("ws", "app", "10.244.0.5")))
		err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
		if err == nil || !strings.Contains(err.Error(), "publishes no podCIDR") || !strings.Contains(err.Error(), flagPodCIDR) {
			t.Fatalf("install = %v, want the refusal naming --%s", err, flagPodCIDR)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	})

	t.Run("installs with a --pod-cidr holding the pods", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, podAt("ws", "app", "10.244.0.5")))
		if err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", flagArg(flagPodCIDR), "10.244.0.0/16"); err != nil {
			t.Fatalf("install: %v", err)
		}
		if lineIndex(s.f.calls(t), "helm upgrade ") < 0 {
			t.Fatalf("no helm upgrade logged:\n%s", strings.Join(s.f.calls(t), "\n"))
		}
	})

	t.Run("refused when a pod answers outside --pod-cidr", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, podAt("ws", "app", "10.99.0.5")))
		err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", flagArg(flagPodCIDR), "10.244.0.0/16")
		if err == nil || !strings.Contains(err.Error(), "pod ws/app answers at 10.99.0.5") {
			t.Fatalf("install = %v, want the refusal naming the pod and its address", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	})

	t.Run("refused when a pod answers in a family no range covers", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, podAt("ws", "app", "fd00::5")))
		err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", flagArg(flagPodCIDR), "10.244.0.0/16")
		if err == nil || !strings.Contains(err.Error(), "pod ws/app answers at fd00::5") {
			t.Fatalf("install = %v, want the refusal naming the address family's pod", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	})

	t.Run("refused when no pod answers at an address of its own", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, hostNetworkPod("kube-system", "coredns", "192.0.2.10")))
		err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", flagArg(flagPodCIDR), "10.244.0.0/16")
		if err == nil || !strings.Contains(err.Error(), "nothing confirms the pod ranges") {
			t.Fatalf("install = %v, want the refusal of an unconfirmed range", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	})

	t.Run("refused when the inventory bound reaches --pod-cidr", func(t *testing.T) {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", overlayKubectl(t, s.applied, podAt("ws", "app", "10.244.0.5")))
		err := runC8s(t, "install", "--platform=aks-snp", "--wait=false", "--force",
			flagArg(flagPodCIDR), "10.244.0.0/16",
			flagArg(flagCDSAddress), "10.9.9.9:8443",
			flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "10.244.1.0/24"))
		if err == nil || !strings.Contains(err.Error(), "where this cluster's pods answer") {
			t.Fatalf("install = %v, want the overlapping node-subnet refusal", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	})
}

// A cluster whose CNI publishes a pod range its pods answer outside of is the
// same blind spot: the operator declares the range the pods are in.
func TestInstallRefusesAPodOutsideThePublishedRange(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, `"get pods --all-namespaces -o json") /bin/cat '`+podListFile(t, podAt("ws", "app", "10.99.0.5"))+`' ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "pod ws/app answers at 10.99.0.5") {
		t.Fatalf("install = %v, want the refusal naming the pod outside the published range", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// overlayKubectl is a cluster whose CNI owns IP allocation: its node publishes
// no spec.podCIDR, and these are the pods answering in it.
func overlayKubectl(t *testing.T, applied string, pods ...corev1.Pod) string {
	t.Helper()
	nodes := nodeListFile(t, corev1.Node{
		Name: "node-a",
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "192.0.2.10"},
		}},
	})
	return clusterKubectl(applied, `"get nodes -o json") /bin/cat '`+nodes+`' ;;
"get pods --all-namespaces -o json") /bin/cat '`+podListFile(t, pods...)+`' ;;
`)
}

// nodeListFile writes a typed NodeList as the JSON `kubectl get nodes -o json`
// would emit and returns its path.
func nodeListFile(t *testing.T, nodes ...corev1.Node) string {
	t.Helper()
	data, err := json.Marshal(corev1.NodeList{Items: nodes})
	if err != nil {
		t.Fatalf("marshal node list: %v", err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write node list: %v", err)
	}
	return path
}

// podAt is a pod answering at its own address.
func podAt(namespace, name, ip string) corev1.Pod {
	return corev1.Pod{
		Namespace: namespace, Name: name,
		Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

// hostNetworkPod answers at its node's address, which the node subnets hold by
// design.
func hostNetworkPod(namespace, name, ip string) corev1.Pod {
	return corev1.Pod{
		Namespace: namespace, Name: name,
		Spec:   corev1.PodSpec{HostNetwork: true},
		Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

// flagArg is a flag as its command line spells it.
func flagArg(name string) string {
	return "--" + name
}
