package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestCloudWireContractAndFailureRedaction(t *testing.T) {
	cfg := fixtureConfig(t)
	req, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer test-provider-token" || r.Header.Get("Api-Version") != "2026-10-15" {
			t.Error("missing authenticated versioned API contract")
		}
		switch calls {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/v1/instances" || r.Header.Get("Idempotency-Key") != "frozen-key" {
				t.Error("wrong create operation")
			}
			var got createRequest
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if err := json.Unmarshal(b, &got); err != nil {
				t.Error(err)
			}
			if got.Count != 1 || len(got.Readiness.TCPPorts) != 0 || string(got.Trust.InitData.Document) != string(req.Trust.InitData.Document) || string(got.Trust.InitData.Signature) != string(req.Trust.InitData.Signature) {
				t.Error("wire launch differs from frozen intent")
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []*instance{instanceFor(got)}})
		case 2:
			if r.URL.Query().Get("idempotencyKey") != "frozen-key" {
				t.Error("missing recovery key")
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		case 3:
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"code":"idempotency_in_flight","detail":"private launch policy"}`)
		case 4:
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Error("unexpected Cloud operation")
		}
	}))
	defer srv.Close()
	c := newCloudClient(cfg)
	c.base = srv.URL
	c.http.Transport = srv.Client().Transport
	if _, err := c.Create(context.Background(), "frozen-key", req); err != nil {
		t.Fatal(err)
	}
	if in, err := c.Find(context.Background(), "frozen-key"); err != nil || in != nil {
		t.Fatalf("lookup: %v %v", in, err)
	}
	if _, err := c.Create(context.Background(), "frozen-key", req); err == nil || !strings.Contains(err.Error(), "idempotency_in_flight") || strings.Contains(err.Error(), "private launch") {
		t.Fatalf("error must expose code only: %v", err)
	}
	if err := c.Delete(context.Background(), "i-test"); err != nil {
		t.Fatal(err)
	}
}

func TestCloudRefusesRedirectAndBoundsResponse(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { followed.Add(1); _, _ = io.WriteString(w, `{}`) }))
	defer destination.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = io.WriteString(w, strings.Repeat("a", 8*maxFile+1))
			return
		}
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := newCloudClient(&Config{CloudURL: srv.URL, token: "private-token"})
	c.http.Transport = srv.Client().Transport
	if err := c.Ping(context.Background()); err == nil || followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	if err := c.do(context.Background(), http.MethodGet, "/large", "", nil, nil); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("response not bounded: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("canceled Cloud request succeeded")
	}
}

func TestOwnedNodeRefusesReplacementAndPinsStatusPatch(t *testing.T) {
	cfg := fixtureConfig(t)
	node := nodeObject(cfg)
	node.UID = "original-node"
	node.ResourceVersion = "7"
	kube := kubefake.NewClientset(node)
	guard := &ownedNodes{NodeInterface: kube.CoreV1().Nodes(), uid: node.UID, name: node.Name, provider: cfg.ProviderID}
	if _, err := guard.Patch(context.Background(), node.Name, types.StrategicMergePatchType, []byte(`{"status":{"conditions":[]}}`), metav1.PatchOptions{}, "status"); err != nil {
		t.Fatal(err)
	}
	actions := kube.Actions()
	patch := actions[len(actions)-1].(interface{ GetPatch() []byte }).GetPatch()
	var data struct {
		Metadata struct {
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(patch, &data); err != nil {
		t.Fatal(err)
	}
	if data.Metadata.UID != "original-node" || data.Metadata.ResourceVersion != "7" {
		t.Fatal("patch lacks atomic identity preconditions")
	}
	if err := kube.CoreV1().Nodes().Delete(context.Background(), node.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := node.DeepCopy()
	replacement.UID = "foreign-node"
	if _, err := kube.CoreV1().Nodes().Create(context.Background(), replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Get(context.Background(), node.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("replacement UID adopted")
	}
	if _, err := guard.Patch(context.Background(), node.Name, types.StrategicMergePatchType, []byte(`{"status":{}}`), metav1.PatchOptions{}, "status"); err == nil {
		t.Fatal("foreign replacement status updated")
	}
	if _, err := guard.Create(context.Background(), node, metav1.CreateOptions{}); err == nil {
		t.Fatal("SDK allowed to recreate a disappeared node")
	}
	replacement.Labels[ownerLabel] = "another-provider"
	if _, err := kube.CoreV1().Nodes().Update(context.Background(), replacement, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ensureOwnedNode(context.Background(), kube.CoreV1().Nodes(), node); err == nil {
		t.Fatal("startup adopted foreign provider")
	}
}

func TestCloudStartupOutageKeepsProviderRunnableAlive(t *testing.T) {
	cfg := fixtureConfig(t)
	node := nodeObject(cfg)
	node.UID = "provider-node"
	node.Status.Conditions[0].Status = corev1.ConditionUnknown
	kube := kubefake.NewClientset(node)
	pinged := make(chan struct{}, 1)
	cloud := &fakeCloud{ping: func() error {
		select {
		case pinged <- struct{}{}:
		default:
		}
		return errors.New("cloud unavailable")
	}}
	n := &virtualNode{cfg: cfg, cloud: cloud, kube: kube, node: nodeObject(cfg)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- n.Start(ctx) }()
	select {
	case <-pinged:
	case err := <-done:
		t.Fatalf("provider terminated during dependency outage: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Cloud health was not checked")
	}
	select {
	case err := <-done:
		t.Fatalf("provider terminated during startup outage: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	got, err := kube.CoreV1().Nodes().Get(context.Background(), cfg.NodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			t.Fatal("Cloud outage published Ready")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not stop on cancellation")
	}
}
