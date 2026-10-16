package cds

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func node(name, internalIP string) *corev1.Node {
	return &corev1.Node{
		Name: name,
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: internalIP},
		}},
	}
}

func stubInClusterKubeClientset(t *testing.T, cs kubernetes.Interface, err error) {
	t.Helper()
	prev := newInClusterKubeClientset
	t.Cleanup(func() { newInClusterKubeClientset = prev })
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return cs, err }
}

// An explicit --sandbox-inventory-cidr is the static mode: no Kubernetes
// client is consulted at all.
func TestBuildInventoryHostsExplicit(t *testing.T) {
	stubInClusterKubeClientset(t, nil, errors.New("must not be called"))
	hosts, err := buildInventoryHosts(t.Context(), []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !hosts.Contains("10.0.0.7") || hosts.Contains("10.244.1.5") {
		t.Fatal("static CIDR bound misapplied")
	}
}

// With no explicit CIDRs the bound tracks the live node list: present at
// startup, extended on scale-up, shrunk on node removal — without a restart.
func TestWatchNodeInventoryHosts(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(node("a", "10.0.1.4"))
	stubInClusterKubeClientset(t, cs, nil)

	hosts, err := buildInventoryHosts(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hosts.Contains("10.0.1.4") || hosts.Empty() {
		t.Fatal("initial node not in the bound after cache sync")
	}
	if hosts.Contains("10.244.1.5") {
		t.Fatal("pod-range address admitted")
	}

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for range 500 {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}

	if _, err := cs.CoreV1().Nodes().Create(t.Context(), node("b", "10.0.1.5"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor("the added node to become dialable", func() bool { return hosts.Contains("10.0.1.5") })

	if err := cs.CoreV1().Nodes().Delete(t.Context(), "a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor("the removed node to leave the bound", func() bool { return !hosts.Contains("10.0.1.4") })
}

// A node list the ServiceAccount cannot read (the node-reader binding absent
// or pruned) fails startup with a message naming the missing access, rather
// than parking the trust root before it ever binds its listener.
func TestWatchNodeInventoryHostsUnreadable(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("nodes"), "", errors.New("no node-reader binding"))
	})
	stubInClusterKubeClientset(t, cs, nil)
	prev := nodeCacheSyncTimeout
	t.Cleanup(func() { nodeCacheSyncTimeout = prev })
	nodeCacheSyncTimeout = 100 * time.Millisecond

	_, err := buildInventoryHosts(t.Context(), nil)
	if err == nil {
		t.Fatal("an unreadable node list must fail startup, not hang")
	}
	if !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("error does not name the missing access: %v", err)
	}
}

// Outside a cluster (local dev) the lister degrades to the old posture: an
// empty bound that refuses every sandbox token, not a startup failure.
func TestWatchNodeInventoryHostsNoCluster(t *testing.T) {
	stubInClusterKubeClientset(t, nil, errors.New("no in-cluster config"))
	hosts, err := buildInventoryHosts(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hosts.Empty() || hosts.Contains("10.0.1.4") {
		t.Fatal("without a cluster the bound must stay empty and refuse everything")
	}
}
