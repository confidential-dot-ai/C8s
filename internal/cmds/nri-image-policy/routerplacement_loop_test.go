package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestWorkerWithoutCDSConnectionRetainsUnknownDecision(t *testing.T) {
	check := workerPolicyCheck(&config{Worker: true}, nil)
	if eligible, err := check(t.Context()); eligible || err == nil {
		t.Fatalf("missing CDS produced a decision: %v, %v", eligible, err)
	}
}

func TestWorkerRouterStartupClearsBeforeChecking(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1", Labels: map[string]string{routerEligibleLabel: "true"}}}
	client := fake.NewClientset(node, strandedRouter())
	placement := testPlacement(client)
	if err := placement.clearStaleEligibility(t.Context()); err != nil {
		t.Fatal(err)
	}
	node, err := client.CoreV1().Nodes().Get(t.Context(), "worker", metav1.GetOptions{})
	if err != nil || node.Labels[routerEligibleLabel] != "" {
		t.Fatalf("stale eligibility: %v, %v", node, err)
	}
	if placement.decision != routerEligibilityUnknown {
		t.Fatal("startup made an authorization decision")
	}
	if _, err := client.CoreV1().Pods("c8s-router").Get(t.Context(), "c8s-router-pod", metav1.GetOptions{}); err != nil {
		t.Fatal("startup deleted the router")
	}
}

func TestReadWorkerNodeName(t *testing.T) {
	for _, tc := range []struct {
		contents string
		want     string
	}{
		{"NODE_NAME=n-10-0-0-1\nNODE_IP=10.0.0.1\n", "n-10-0-0-1"},
		{"NODE_IP=10.0.0.1\n", ""},
		{"NODE_NAME=\n", ""},
		{"NODE_NAME=first\nNODE_NAME=second\n", ""},
		{"NODE_NAME=$(hostname)\n", ""},
		{"NODE_NAME=not a node\n", ""},
	} {
		path := filepath.Join(t.TempDir(), "kubelet.env")
		if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
			t.Fatal(err)
		}
		name, err := readWorkerNodeName(path)
		if name != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("%q: got %q, %v", tc.contents, name, err)
		}
	}
	if _, err := readWorkerNodeName(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing staged identity accepted")
	}
}
