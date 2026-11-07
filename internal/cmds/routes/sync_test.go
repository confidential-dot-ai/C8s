package routes

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
)

func routedPod(name, host string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agents",
		CreationTimestamp: metav1.NewTime(time.Unix(1_700_000_000, 0).Add(-age)),
		Annotations:       map[string]string{RouteHostAnnotation: host, RouteWorkloadAnnotation: "opencode"}}}
}

func podService(name, ip string, ports ...int32) *corev1.Service {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agents"}, Spec: corev1.ServiceSpec{ClusterIP: ip}}
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: p})
	}
	return svc
}

func fakeKube(t *testing.T, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	kube := fake.NewClientset(objs...)
	old := newKubeClient
	newKubeClient = func(string) (kubernetes.Interface, error) { return kube, nil }
	t.Cleanup(func() { newKubeClient = old })
	return kube
}

func TestSyncRoutesPodsAndWritesOnlyOnChange(t *testing.T) {
	h := newHarness(t)
	// A host outside the suffix that sync must keep.
	h.mustRun(t, "add", "--new", "--host", "gateway.example", "--path", "/", "--address", "gw:443", "--workload", "gateway")
	kube := fakeKube(t,
		routedPod("alice", "alice.agents.example", time.Hour), podService("alice", "10.43.0.10", 4096),
		routedPod("bob", "bob.agents.example", time.Minute), podService("bob", "10.43.0.11", 4096, 8080),
		routedPod("mallory", "alice.agents.example", 0), podService("mallory", "10.43.0.12", 4096),
		routedPod("eve", "gateway.example", 0), podService("eve", "10.43.0.13", 4096),
	)
	bob, _ := kube.CoreV1().Pods("agents").Get(t.Context(), "bob", metav1.GetOptions{})
	bob.Annotations[RoutePortAnnotation] = "8080"
	if _, err := kube.CoreV1().Pods("agents").Update(t.Context(), bob, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	sync := []string{"sync", "--host-suffix", ".agents.example"}
	h.mustRun(t, sync...)
	m := h.cds.stored(t)
	want := map[string]string{"alice.agents.example": "10.43.0.10:4096", "bob.agents.example": "10.43.0.11:8080", "gateway.example": "gw:443"}
	if len(m.Hosts) != len(want) {
		t.Fatalf("hosts = %+v", m.Hosts)
	}
	for host, addr := range want {
		rs := m.Hosts[host].Routes
		if len(rs) != 1 || rs[0].Backend.Address != addr || rs[0].Path != "/" || rs[0].Match != pkgroutes.MatchPrefix {
			t.Fatalf("%s routes = %+v, want %s", host, rs, addr)
		}
	}
	if m.Hosts["alice.agents.example"].Routes[0].Backend.Workload != "opencode" || m.Hosts["gateway.example"].Routes[0].Backend.Workload != "gateway" {
		t.Fatalf("workloads = %+v", m.Hosts)
	}
	for _, skipped := range []string{"agents/mallory", "agents/eve"} {
		if !strings.Contains(h.stderr.String(), "skipping pod "+skipped) {
			t.Fatalf("stderr does not report %s: %s", skipped, h.stderr.String())
		}
	}

	puts := h.cds.puts
	if out := h.mustRun(t, sync...); !strings.Contains(out, "unchanged") || h.cds.puts != puts {
		t.Fatalf("unchanged sync wrote: puts %d -> %d, out %q", puts, h.cds.puts, out)
	}

	// A deleted pod loses its host; other hosts stay.
	if err := kube.CoreV1().Pods("agents").Delete(t.Context(), "bob", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	h.mustRun(t, sync...)
	m = h.cds.stored(t)
	if _, ok := m.Hosts["bob.agents.example"]; ok || len(m.Hosts) != 2 || h.cds.puts != puts+1 {
		t.Fatalf("after delete: hosts %+v, puts %d", m.Hosts, h.cds.puts)
	}
}

func TestSyncRefusesBadSuffixAndUnroutableServices(t *testing.T) {
	h := newHarness(t)
	fakeKube(t,
		routedPod("multi", "multi.agents.example", 0), podService("multi", "10.43.0.20", 80, 81),
		routedPod("headless", "headless.agents.example", 0), podService("headless", corev1.ClusterIPNone, 80),
		routedPod("nosvc", "nosvc.agents.example", 0),
	)
	if _, err := h.run(t, "sync", "--host-suffix", "agents.example"); err == nil {
		t.Fatal("accepted a suffix without a leading dot")
	}
	h.mustRun(t, "sync", "--new", "--host-suffix", ".agents.example")
	if h.cds.puts != 0 {
		t.Fatalf("routed unroutable pods: %d writes", h.cds.puts)
	}
	for _, pod := range []string{"multi", "headless", "nosvc"} {
		if !strings.Contains(h.stderr.String(), "skipping pod agents/"+pod) {
			t.Fatalf("stderr does not report %s: %s", pod, h.stderr.String())
		}
	}
}
