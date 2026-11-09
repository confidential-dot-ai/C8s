package routing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const agentSuffix = "agents.example"

// publishingPod is a Ready pod publishing doc as its client document and addr as
// the endpoint of application port 4096.
func publishingPod(t testing.TB, name string, doc []byte, addr string, created time.Time) *corev1.Pod {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	endpoints, err := json.Marshal([]podEndpoint{{Name: "pod-status", Host: host, Port: 1}, {Name: "app-4096", Host: host, Port: n}})
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "agents", CreationTimestamp: metav1.NewTime(created),
			Annotations: map[string]string{
				workloadclaims.AnnotationClientDocument:  base64.StdEncoding.EncodeToString(doc),
				workloadclaims.AnnotationPodCVMEndpoints: string(endpoints),
			},
		},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func labelOf(doc []byte) string {
	h := sha256.Sum256(doc)
	return armtls.AgentLabel(h[:])
}

func TestAgentIndexUpdates(t *testing.T) {
	x := NewAgentIndex()
	doc := []byte("agent one")
	label := labelOf(doc)
	now := time.Now()

	x.Update(publishingPod(t, "a", doc, "192.0.2.1:30001", now))
	if got, ok := x.Lookup(label, 4096); !ok || got != "192.0.2.1:30001" {
		t.Fatalf("Lookup = %q, %v; want the published endpoint", got, ok)
	}
	if _, ok := x.Lookup(label, 8080); ok {
		t.Error("a port the pod does not publish resolves")
	}
	if _, ok := x.Lookup(labelOf([]byte("other")), 4096); ok {
		t.Error("an unknown label resolves")
	}

	// A newer pod with the same document does not take over; the oldest wins
	// until it goes.
	x.Update(publishingPod(t, "b", doc, "192.0.2.2:30002", now.Add(time.Minute)))
	if got, _ := x.Lookup(label, 4096); got != "192.0.2.1:30001" {
		t.Fatalf("Lookup with two pods = %q, want the oldest", got)
	}
	x.Delete("agents/a")
	if got, _ := x.Lookup(label, 4096); got != "192.0.2.2:30002" {
		t.Fatalf("Lookup after the oldest went = %q, want the other pod", got)
	}

	// An update that moves the endpoint replaces it; one that stops being
	// Ready, or loses either annotation, drops the pod.
	x.Update(publishingPod(t, "b", doc, "192.0.2.3:30003", now))
	if got, _ := x.Lookup(label, 4096); got != "192.0.2.3:30003" {
		t.Fatalf("Lookup after a move = %q", got)
	}
	for name, edit := range map[string]func(*corev1.Pod){
		"not ready":    func(p *corev1.Pod) { p.Status.Conditions[0].Status = corev1.ConditionFalse },
		"terminating":  func(p *corev1.Pod) { p.DeletionTimestamp = &metav1.Time{Time: now} },
		"no document":  func(p *corev1.Pod) { delete(p.Annotations, workloadclaims.AnnotationClientDocument) },
		"bad document": func(p *corev1.Pod) { p.Annotations[workloadclaims.AnnotationClientDocument] = "not base64!" },
		"no endpoints": func(p *corev1.Pod) { delete(p.Annotations, workloadclaims.AnnotationPodCVMEndpoints) },
	} {
		pod := publishingPod(t, "b", doc, "192.0.2.3:30003", now)
		edit(pod)
		x.Update(pod)
		if got, ok := x.Lookup(label, 4096); ok {
			t.Errorf("%s: Lookup = %q, want none", name, got)
		}
		x.Update(publishingPod(t, "b", doc, "192.0.2.3:30003", now))
	}
}

func (f *fixture) getHost(host, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}

// A pattern route reaches the agent its host names, and only a backend whose
// leaf carries the workload and that agent's client document digest: the
// address discovery reports is never trusted.
func TestPatternRouteReachesTheAgentItsHostNames(t *testing.T) {
	f := newFixture(t)
	doc, otherDoc := []byte("agent one"), []byte("agent two")
	h, otherH := sha256.Sum256(doc), sha256.Sum256(otherDoc)
	label := labelOf(doc)

	agent := startBackend(t, "agent", issueAgentLeaf(t, f.mesh, "opencode", testDigest, h[:]))
	impostor := startBackend(t, "impostor", issueAgentLeaf(t, f.mesh, "opencode", testDigest, otherH[:]))
	unnamed := startBackend(t, "unnamed", issueLeaf(t, f.mesh, "opencode"))
	wrongWorkload := startBackend(t, "wrong", issueAgentLeaf(t, f.mesh, "other", testDigest, h[:]))
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, manifestSpec{
		revision: 1,
		hosts:    map[string][]route{testHost: {workloadRoute("/", "prefix", web.addr(), "web")}},
		patterns: []routes.Pattern{{HostSuffix: agentSuffix, Workload: "opencode", Port: 4096}},
	})
	host := label + "." + agentSuffix

	if got := f.getHost(host, "/").Code; got != http.StatusNotFound {
		t.Fatalf("GET before discovery knows the agent = %d, want 404", got)
	}

	f.agents.Update(publishingPod(t, "a", doc, agent.addr(), time.Now()))
	w := f.getHost(host, "/v1/x?y=1")
	if w.Code != http.StatusOK || w.Body.String() != "agent" {
		t.Fatalf("GET the agent = %d %q, want 200 from the agent", w.Code, w.Body.String())
	}
	if s := agent.seen(); s.requestURI != "/v1/x?y=1" || s.host != host {
		t.Fatalf("agent saw %q for host %q", s.requestURI, s.host)
	}

	for _, wrong := range []*testBackend{impostor, unnamed, wrongWorkload} {
		f.agents.Update(publishingPod(t, "a", doc, wrong.addr(), time.Now()))
		if got := f.getHost(host, "/").Code; got != http.StatusBadGateway {
			t.Errorf("GET with discovery pointing at %s = %d, want 502", wrong.name, got)
		}
		if n := wrong.hits.Load(); n != 0 {
			t.Errorf("%s served %d requests, want 0", wrong.name, n)
		}
	}

	if got := f.getHost(labelOf(otherDoc)+"."+agentSuffix, "/").Code; got != http.StatusNotFound {
		t.Errorf("GET an unknown label = %d, want 404", got)
	}
	if w := f.get("/"); w.Code != http.StatusOK || w.Body.String() != "web" {
		t.Errorf("GET the exact host = %d %q, want 200 from web", w.Code, w.Body.String())
	}
}

// Retain keeps an agent's pool only while a pattern gives it and discovery
// still reports it at that address.
func TestRetainDropsAgentPoolsDiscoveryNoLongerReports(t *testing.T) {
	f := newFixture(t)
	doc := []byte("agent one")
	b := routes.Backend{Address: "192.0.2.1:30001", Workload: "opencode", AgentLabel: labelOf(doc), AgentPort: 4096}
	m := &routes.Manifest{Patterns: []routes.Pattern{{HostSuffix: agentSuffix, Workload: "opencode", Port: 4096}}}
	f.agents.Update(publishingPod(t, "a", doc, b.Address, time.Now()))
	first := f.transports.For(b)
	f.transports.Retain(m)
	if f.transports.For(b) != first {
		t.Fatal("Retain dropped a pool discovery still reports")
	}
	f.agents.Update(publishingPod(t, "a", doc, "192.0.2.9:30009", time.Now()))
	f.transports.Retain(m)
	if f.transports.For(b) == first {
		t.Fatal("Retain kept a pool for an address discovery no longer reports")
	}
	second := f.transports.For(b)
	f.agents.Update(publishingPod(t, "a", doc, b.Address, time.Now()))
	f.transports.Retain(&routes.Manifest{})
	if f.transports.For(b) == second {
		t.Fatal("Retain kept an agent pool no pattern gives")
	}
}
