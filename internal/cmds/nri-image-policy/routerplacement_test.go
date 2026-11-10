package nriimagepolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

func TestWorkerRouterEligibilityTransitions(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1", Labels: map[string]string{routerEligibleLabel: "true", "keep": "value"}}, Spec: corev1.NodeSpec{Unschedulable: true, Taints: []corev1.Taint{{Key: "keep", Effect: corev1.TaintEffectNoSchedule}}}}
	client := fake.NewClientset(node)
	eligible, checkErr := false, errors.New("CDS unavailable")
	observer := testPlacement(client)
	observer.check = func(context.Context) (bool, error) { return eligible, checkErr }
	for _, step := range []struct {
		name      string
		eligible  bool
		err       error
		wantLabel bool
	}{
		{"startup unknown clears stale label", false, checkErr, false},
		{"match", true, nil, true},
		{"unknown preserves match", false, checkErr, true},
		{"mismatch", false, nil, false},
		{"unknown preserves mismatch", true, checkErr, false},
		{"readmitted", true, nil, true},
	} {
		t.Run(step.name, func(t *testing.T) {
			eligible, checkErr = step.eligible, step.err
			if err := observer.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			got, err := client.CoreV1().Nodes().Get(t.Context(), "worker", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if (got.Labels[routerEligibleLabel] == "true") != step.wantLabel {
				t.Fatalf("labels: %v", got.Labels)
			}
			if got.Labels["keep"] != "value" || !got.Spec.Unschedulable || len(got.Spec.Taints) != 1 {
				t.Fatal("changed unrelated node state")
			}
		})
	}
}

func TestWorkerRouterRecoveryRetriesAfterExclusion(t *testing.T) {
	client := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1"}})
	observer := testPlacement(client)
	for range 2 {
		pod := strandedRouter()
		if _, err := client.CoreV1().Pods(pod.Namespace).Create(t.Context(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := observer.reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("stranded router survives: %v", err)
		}
	}
	for _, action := range client.Actions() {
		deletion, ok := action.(clienttesting.DeleteAction)
		if !ok {
			continue
		}
		preconditions := deletion.GetDeleteOptions().Preconditions
		if preconditions == nil || preconditions.UID == nil || *preconditions.UID != "pod-1" || preconditions.ResourceVersion == nil || *preconditions.ResourceVersion != "10" {
			t.Fatalf("unsafe deletion: %#v", preconditions)
		}
	}
}

func TestWorkerRouterRecoveryScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"Ready", func(p *corev1.Pod) {
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}},
		{"other worker", func(p *corev1.Pod) { p.Spec.NodeName = "other" }},
		{"tenant namespace", func(p *corev1.Pod) { p.Namespace = "tenant" }},
		{"other component", func(p *corev1.Pod) { p.Labels["app.kubernetes.io/name"] = "other" }},
		{"other release", func(p *corev1.Pod) { p.Labels["app.kubernetes.io/instance"] = "other" }},
		{"other service account", func(p *corev1.Pod) { p.Spec.ServiceAccountName = "other" }},
		{"ownerless", func(p *corev1.Pod) { p.OwnerReferences = nil }},
		{"other controller", func(p *corev1.Pod) { p.OwnerReferences[0].Kind = "DaemonSet" }},
		{"other ReplicaSet", func(p *corev1.Pod) { p.OwnerReferences[0].Name = "other" }},
		{"another init", func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].Name = "other" }},
		{"gate pending", func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}
		}},
		{"gate finished", func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
		}},
		{"deleting", func(p *corev1.Pod) { now := metav1.Now(); p.DeletionTimestamp = &now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := strandedRouter()
			tc.change(pod)
			if isWorkerRouterWaitingForCertificate(pod, "worker") {
				t.Fatal("unrelated or healthy pod selected")
			}
		})
	}
}

func TestWorkerRouterRecoveryRequiresKnownMismatchAndAcknowledgedExclusion(t *testing.T) {
	for _, failure := range []string{"startup unknown", "exclusion conflict", "node replaced"} {
		t.Run(failure, func(t *testing.T) {
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1", Labels: map[string]string{routerEligibleLabel: "true"}}}
			pod := strandedRouter()
			client := fake.NewClientset(node, pod)
			observer := testPlacement(client)
			switch failure {
			case "startup unknown":
				observer.check = func(context.Context) (bool, error) { return false, errors.New("unavailable") }
			case "exclusion conflict":
				client.PrependReactor("update", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "nodes"}, "worker", errors.New("changed"))
				})
			case "node replaced":
				observer.nodeUID = "old-node"
				observer.decision = routerIneligible
				observer.check = func(context.Context) (bool, error) { return false, errors.New("unavailable") }
			}
			err := observer.reconcile(t.Context())
			if (err != nil) != (failure == "exclusion conflict") {
				t.Fatalf("reconcile: %v", err)
			}
			if _, err := client.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{}); err != nil {
				t.Fatalf("router deleted without acknowledged mismatch: %v", err)
			}
		})
	}
}

func testPlacement(client *fake.Clientset) *workerRouterPlacement {
	return newWorkerRouterPlacement(
		"worker",
		func() (coreclient.CoreV1Interface, error) { return client.CoreV1(), nil },
		func(context.Context) (bool, error) { return false, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func TestWorkerRouterRechecksNodeAfterEvidence(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1"}}
		pod := strandedRouter()
		client := fake.NewClientset(node, pod)
		observer := testPlacement(client)
		observer.check = func(ctx context.Context) (bool, error) {
			node.Labels = map[string]string{routerEligibleLabel: "true"}
			if replacement {
				node.UID = "replacement"
			}
			_, err := client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
			return false, err
		}
		if err := observer.reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		got, err := client.CoreV1().Nodes().Get(t.Context(), node.Name, metav1.GetOptions{})
		if err != nil || got.Labels[routerEligibleLabel] != "" {
			t.Fatalf("current Node remains eligible: %v, %v", got, err)
		}
		_, err = client.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) == replacement {
			t.Fatalf("replacement=%v, pod lookup=%v", replacement, err)
		}
		if replacement && observer.decision != routerEligibilityUnknown {
			t.Fatal("retained decision for a replaced Node")
		}
	}
}

func TestWorkerRouterRetriesFailedExclusionWhenCheckIsUnknown(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker", UID: "node-1", Labels: map[string]string{routerEligibleLabel: "true"}}}
	pod := strandedRouter()
	client := fake.NewClientset(node, pod)
	observer := testPlacement(client)
	observer.nodeUID = node.UID
	failed := false
	client.PrependReactor("update", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		if !failed {
			failed = true
			return true, nil, errors.New("API unavailable")
		}
		return false, nil, nil
	})
	if err := observer.reconcile(t.Context()); err == nil {
		t.Fatal("expected failed exclusion")
	}
	observer.check = func(context.Context) (bool, error) { return false, errors.New("CDS unavailable") }
	if err := observer.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("held mismatch was not retried: %v", err)
	}
}

func strandedRouter() *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "c8s-router-pod", Namespace: "c8s-router", UID: "pod-1", ResourceVersion: "10",
			Labels:          map[string]string{"app.kubernetes.io/name": "router", "app.kubernetes.io/instance": "c8s"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "c8s-router-abc", UID: "replicaset-1", Controller: &controller}},
		},
		Spec:   corev1.PodSpec{NodeName: "worker", ServiceAccountName: "c8s-router"},
		Status: corev1.PodStatus{InitContainerStatuses: []corev1.ContainerStatus{{Name: "c8s-cert-wait", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
	}
}
