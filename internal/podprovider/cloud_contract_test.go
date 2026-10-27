package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestCloudResponseIdentityAndCardinalityContract(t *testing.T) {
	for _, kind := range []string{"create-empty", "create-many", "find-many", "find-page", "find-error", "get-valid", "get-not-found", "get-invalid-json", "delete-error", "delete-accepted", "problem-code-redaction"} {
		t.Run(kind, func(t *testing.T) {
			body := `{"items":[{"id":"i-one"}]}`
			status := http.StatusOK
			switch kind {
			case "create-empty":
				body = `{"items":[]}`
			case "create-many", "find-many":
				body = `{"items":[{"id":"i-one"},{"id":"i-two"}]}`
			case "find-page":
				body = `{"items":[{"id":"i-one"}],"nextPageToken":"more"}`
			case "find-error", "delete-error":
				status = http.StatusServiceUnavailable
				body = `{"code":"cloud_unavailable"}`
			case "get-valid":
				body = `{"id":"i-one","status":"running"}`
			case "get-not-found":
				status = http.StatusNotFound
			case "get-invalid-json":
				body = `{`
			case "delete-accepted":
				status = http.StatusAccepted
				body = ""
			case "problem-code-redaction":
				status = http.StatusBadRequest
				body = `{"code":"bad\nsecret","detail":"private launch contents"}`
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(kind, "get-") && (r.Method != http.MethodGet || r.URL.Path != "/v1/instances/i-one") {
					t.Error("invalid Get operation")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			c := newCloudClient(&Config{CloudURL: srv.URL, token: "test"})
			c.http.Transport = srv.Client().Transport
			var in *instance
			var err error
			switch {
			case strings.HasPrefix(kind, "get-"):
				in, err = c.Get(context.Background(), "i-one")
			case strings.HasPrefix(kind, "find-"):
				in, err = c.Find(context.Background(), "key")
			case strings.HasPrefix(kind, "delete-"):
				err = c.Delete(context.Background(), "i-one")
			default:
				in, err = c.Create(context.Background(), "key", createRequest{})
			}
			if kind == "get-valid" {
				if err != nil || in.ID != "i-one" || in.Status != "running" {
					t.Fatalf("Get response: %v %v", in, err)
				}
				return
			}
			if kind == "delete-accepted" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid/ambiguous Cloud response accepted")
			}
			if kind == "get-not-found" && !errors.Is(err, errCloudNotFound) {
				t.Fatal("Get lost not-found identity")
			}
			if kind == "problem-code-redaction" && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private launch")) {
				t.Fatalf("unsafe Cloud error text leaked: %v", err)
			}
		})
	}
	// An exact, unique lookup is a recovery result even when terminated.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []instance{{ID: "i-old", Status: "terminated"}}})
	}))
	defer srv.Close()
	c := newCloudClient(&Config{CloudURL: srv.URL})
	c.http.Transport = srv.Client().Transport
	if in, err := c.Find(context.Background(), "key"); err != nil || in.ID != "i-old" || in.Status != "terminated" {
		t.Fatalf("tombstone lookup: %v %v", in, err)
	}
}

func TestNodeRegistrationPreservesForeignMetadataAndRestoresRouting(t *testing.T) {
	cfg := fixtureConfig(t)
	want := nodeObject(cfg)
	kube := kubefake.NewClientset()
	if err := ensureOwnedNode(context.Background(), kube.CoreV1().Nodes(), want); err != nil {
		t.Fatal(err)
	}
	got, err := kube.CoreV1().Nodes().Get(context.Background(), want.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Conditions[0].Status != corev1.ConditionUnknown || got.Spec.ProviderID != want.Spec.ProviderID {
		t.Fatal("new node was Ready before health or lacks ownership")
	}
	got.Labels["example.invalid/operator"] = "preserve"
	delete(got.Labels, Annotation)
	got.Spec.Taints = []corev1.Taint{{Key: "maintenance", Effect: corev1.TaintEffectNoExecute}}
	if _, err := kube.CoreV1().Nodes().Update(context.Background(), got, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ensureOwnedNode(context.Background(), kube.CoreV1().Nodes(), want); err != nil {
		t.Fatal(err)
	}
	got, err = kube.CoreV1().Nodes().Get(context.Background(), want.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels[Annotation] != "true" || got.Labels["example.invalid/operator"] != "preserve" || len(got.Spec.Taints) != 2 || got.Spec.Taints[0].Key != "maintenance" || got.Spec.Taints[1] != want.Spec.Taints[0] {
		t.Fatal("registration lost operator metadata or failed to restore routing")
	}
	n := &virtualNode{cfg: cfg, cloud: &fakeCloud{}, kube: kube, node: want}
	if err := n.checkOwnership(context.Background()); err == nil {
		t.Fatal("ownership accepted before UID registration")
	}
}
