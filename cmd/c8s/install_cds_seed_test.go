//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A component entry the CDS does not serve is a component no node would admit.
func TestCheckSeedServed(t *testing.T) {
	seed, err := pkgallowlist.ParseJSON([]byte(testSeedDocument("app")))
	if err != nil {
		t.Fatal(err)
	}
	serves := func(document string) *pkgallowlist.Allowlist {
		t.Helper()
		al, err := pkgallowlist.ParseServedJSON([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		return al
	}
	withExtraField := func(field string) string {
		return strings.Replace(testSeedDocument("app"), `"app":{`, `"app":{`+field+",", 1)
	}
	narrowed := strings.Replace(testSeedDocument("app"), `"command":{"policy":"any"}`, `"command":{"policy":"exact","argv":["/app"]}`, 1)
	otherImage := strings.ReplaceAll(testSeedDocument("app"), testSeedDigest, strings.Repeat("22", 32))
	granted := withExtraField(`"secrets":{"policy":"allow","read":["/app/token"]}`)
	beside := withExtraField(`"initContainers":[{"digest":"sha256:` + strings.Repeat("33", 32) + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]`)
	asInit := `{"schema":"c8s.allowlist/v1","workloads":{"app":{"initContainers":` + testSeedContainers + `,"containers":[]}}}`

	const notTheImages = `entry "app" that does not declare this component's images`
	tests := []struct {
		name    string
		served  *pkgallowlist.Allowlist
		wantErr string
	}{
		{name: "the entry this release renders", served: serves(testSeedDocument("app"))},
		{name: "beside the entries of another release", served: serves(testSeedDocument("app", "older"))},
		{name: "the operator granted it a secret", served: serves(granted)},
		{name: "the operator pinned its command", served: serves(narrowed)},
		{name: "another component only", served: serves(testSeedDocument("older")), wantErr: `serves no entry "app"`},
		{name: "another image under the name", served: serves(otherImage), wantErr: notTheImages},
		{name: "an image beside the component's", served: serves(beside), wantErr: notTheImages},
		{name: "the component's image in another role", served: serves(asInit), wantErr: notTheImages},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSeedServed(seed, tc.served)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkSeedServed = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkSeedServed = %v, want an error containing %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "c8s allowlist apply") {
				t.Fatalf("checkSeedServed = %v, want the publish advice", err)
			}
		})
	}
}

// An unattested endpoint serves this install nothing, however good the allowlist it answers with.
func TestServedAllowlistRefusesAnUnattestedEndpoint(t *testing.T) {
	resetCLIState(t)
	installCDS = &cdsPin{path: cdsPinFile(t, []string{installSeedEntryName}, "192.0.2.0/24")}
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testSeedDocument(installSeedEntryName))
	}))
	t.Cleanup(cds.Close)
	if al, err := servedAllowlist(context.Background(), cds.URL); err == nil {
		t.Fatalf("servedAllowlist read %v from an unattested endpoint", al.Workloads)
	}
}

// An unreachable CDS warns and installs, naming the publish command.
func TestInstallWarnsWhenTheServedAllowlistIsUnreadable(t *testing.T) {
	var s *installStubs
	var err error
	stderr := captureStderr(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	})
	if err != nil {
		t.Fatalf("install: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "cannot read the allowlist https://"+installCDSAddressUnreachable+" serves") ||
		!strings.Contains(stderr, "c8s allowlist apply") {
		t.Fatalf("stderr = %q, want the warning naming the CDS and the publish command", stderr)
	}
	if lineIndex(s.f.calls(t), "helm upgrade ") < 0 {
		t.Fatalf("no helm upgrade logged:\n%s", strings.Join(s.f.calls(t), "\n"))
	}
}

// --allowlist-seed-out is the render an operator needs before the CDS exists.
func TestInstallWritesTheAllowlistSeedAndStops(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
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
	mustContainPrefix(t, calls, "kubectl version")
	mustNotContainPrefix(t, calls, "helm upgrade")
	mustNotContainPrefix(t, calls, "kubectl apply")

	// The render precedes the CDS it is configured into, so it names none.
	err = runC8s(t, "install", "--platform=aks-snp", "--force", flagArg(flagSeedOut), out,
		flagArg(flagCDSAddress), installCDSAddressUnreachable,
		flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "192.0.2.0/24"))
	if err == nil || !strings.Contains(err.Error(), "runs before") {
		t.Fatalf("install = %v, want the refusal to name a CDS while writing its seed", err)
	}
}

// The CDS dials a node's admission inventory inside its configured subnets, so
// a subnet holding pod addresses would let a pod answer as that inventory.
func TestInstallRefusesNodeSubnetsHoldingPodAddresses(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))

	// The stubbed node assigns pod addresses from 10.42.0.0/24.
	err := runC8s(t, "install", "--platform=aks-snp", "--wait=false", "--force",
		flagArg(flagCDSAddress), installCDSAddressUnreachable,
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
			flagArg(flagCDSAddress), installCDSAddressUnreachable,
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
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get pods --all-namespaces -o json") /bin/cat '`+podListFile(t, podAt("ws", "app", "10.99.0.5"))+`' ;;
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
	return clusterKubectl(t, applied, `"get nodes -o json") /bin/cat '`+nodes+`' ;;
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
