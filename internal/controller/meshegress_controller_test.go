package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The fake client does not default policyTypes the way the API server does,
// so every fixture sets it explicitly; the reconciler reads the stored field.
func egressPolicy(ns, name string, selector metav1.LabelSelector, policyTypes ...networkingv1.PolicyType) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		Name: name, Namespace: ns, UID: types.UID("uid-" + name),
		Spec: networkingv1.NetworkPolicySpec{PodSelector: selector, PolicyTypes: policyTypes},
	}
}

func meshEgressReconciler(excluded map[string]struct{}, objs ...client.Object) *MeshEgressReconciler {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &MeshEgressReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: events.NewFakeRecorder(8),
		Port:     15001,
		Excluded: excluded,
	}
}

func reconcilePolicy(t *testing.T, r *MeshEgressReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	if err != nil {
		t.Fatalf("Reconcile(%s/%s): %v", ns, name, err)
	}
	return res
}

func getCompanion(t *testing.T, c client.Client, ns, source string) (*networkingv1.NetworkPolicy, bool) {
	t.Helper()
	np := &networkingv1.NetworkPolicy{}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: meshEgressCompanionName(source)}, np)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return np, true
}

func mustCompanion(t *testing.T, c client.Client, ns, source string) *networkingv1.NetworkPolicy {
	t.Helper()
	np, ok := getCompanion(t, c, ns, source)
	if !ok {
		t.Fatalf("companion for %s/%s not created", ns, source)
	}
	return np
}

// A default-deny egress policy gets a companion that selects the same pods
// and allows TCP to the mesh port only, owned by the source.
func TestMeshEgressCreatesCompanionForEgressIsolatingPolicy(t *testing.T) {
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"tier": "web"},
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "role", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"canary"},
		}},
	}
	src := egressPolicy("app", "default-deny", selector, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "default-deny")

	got := mustCompanion(t, r.Client, "app", "default-deny")
	if !metav1.IsControlledBy(got, src) {
		t.Fatalf("companion ownerReferences = %+v, want controlled by the source", got.OwnerReferences)
	}
	if got.Labels[managedByLabel] != managedByValue || got.Labels[meshEgressCompanionLabel] != "true" {
		t.Fatalf("companion labels = %v", got.Labels)
	}
	// Additive: the companion must select exactly what the source selects,
	// including matchExpressions, and nothing else.
	if !equality.Semantic.DeepEqual(got.Spec.PodSelector, selector) {
		t.Fatalf("companion podSelector = %+v, want %+v", got.Spec.PodSelector, selector)
	}
	if len(got.Spec.PolicyTypes) != 1 || got.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("companion policyTypes = %v, want [Egress]", got.Spec.PolicyTypes)
	}
	if len(got.Spec.Ingress) != 0 {
		t.Fatalf("companion must carry no ingress rules; got %+v", got.Spec.Ingress)
	}
	if len(got.Spec.Egress) != 1 || len(got.Spec.Egress[0].To) != 0 || len(got.Spec.Egress[0].Ports) != 1 {
		t.Fatalf("companion egress = %+v, want one peerless rule with one port", got.Spec.Egress)
	}
	p := got.Spec.Egress[0].Ports[0]
	if p.Protocol == nil || *p.Protocol != corev1.ProtocolTCP || p.Port == nil || p.Port.IntValue() != 15001 || p.EndPort != nil {
		t.Fatalf("companion port = %+v, want TCP 15001 exactly", p)
	}
}

// A source that selects every pod yields a companion that selects every pod:
// the selector is copied, never narrowed or widened.
func TestMeshEgressCompanionMirrorsEmptySelector(t *testing.T) {
	src := egressPolicy("app", "deny-all", metav1.LabelSelector{}, networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "deny-all")
	got := mustCompanion(t, r.Client, "app", "deny-all")
	if len(got.Spec.PodSelector.MatchLabels) != 0 || len(got.Spec.PodSelector.MatchExpressions) != 0 {
		t.Fatalf("companion podSelector = %+v, want empty", got.Spec.PodSelector)
	}
}

// A policy that does not isolate egress must not get a companion: the
// companion would itself isolate the selected pods' egress.
func TestMeshEgressIgnoresIngressOnlyPolicy(t *testing.T) {
	src := egressPolicy("app", "ingress-only", metav1.LabelSelector{}, networkingv1.PolicyTypeIngress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "ingress-only")
	if _, ok := getCompanion(t, r.Client, "app", "ingress-only"); ok {
		t.Fatal("companion created for a policy that does not isolate egress")
	}
}

// A source whose own rules already admit TCP to the mesh port for every
// destination needs no companion; one whose rules only look like they do
// (named port, peer present, other protocol, range below the port) does.
func TestMeshEgressSkipsSourcesThatAlreadyAllowThePort(t *testing.T) {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	port := func(p int32) *intstr.IntOrString { v := intstr.FromInt32(p); return &v }
	named := intstr.FromString("mesh")
	end := int32(15001)
	cases := []struct {
		name   string
		egress []networkingv1.NetworkPolicyEgressRule
		allows bool
	}{
		{"allow-all-rule", []networkingv1.NetworkPolicyEgressRule{{}}, true},
		{"all-tcp", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp}}}}, true},
		{"any-protocol-any-port", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{}}}}, true},
		{"exact-port", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: port(15001)}}}}, true},
		{"range-covering", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: port(15000), EndPort: &end}}}}, true},
		{"other-port", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: port(443)}}}}, false},
		{"all-udp", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp}}}}, false},
		{"named-port", []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &named}}}}, false},
		{"with-peer", []networkingv1.NetworkPolicyEgressRule{{
			To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp}},
		}}, false},
		{"no-rules", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := egressPolicy("app", tc.name, metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
			src.Spec.Egress = tc.egress
			r := meshEgressReconciler(nil, src)
			reconcilePolicy(t, r, "app", tc.name)
			_, ok := getCompanion(t, r.Client, "app", tc.name)
			if ok == tc.allows {
				t.Fatalf("companion exists = %v for egress %+v, want %v", ok, tc.egress, !tc.allows)
			}
		})
	}
}

// Dropping Egress from a source's policyTypes removes its companion. Owner GC
// cannot do this: the source still exists.
func TestMeshEgressDeletesCompanionWhenSourceStopsIsolatingEgress(t *testing.T) {
	src := egressPolicy("app", "default-deny", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "default-deny")
	mustCompanion(t, r.Client, "app", "default-deny")

	src.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	if err := r.Update(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	reconcilePolicy(t, r, "app", "default-deny")
	if _, ok := getCompanion(t, r.Client, "app", "default-deny"); ok {
		t.Fatal("companion survived its source dropping egress isolation")
	}
}

// Selector changes on the source propagate to the companion.
func TestMeshEgressUpdatesCompanionSelector(t *testing.T) {
	src := egressPolicy("app", "default-deny", metav1.LabelSelector{MatchLabels: map[string]string{"a": "1"}}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "default-deny")

	src.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"b": "2"}}
	if err := r.Update(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	reconcilePolicy(t, r, "app", "default-deny")
	got := mustCompanion(t, r.Client, "app", "default-deny")
	if got.Spec.PodSelector.MatchLabels["b"] != "2" || len(got.Spec.PodSelector.MatchLabels) != 1 {
		t.Fatalf("companion podSelector = %+v, want the updated source selector", got.Spec.PodSelector)
	}
}

// The mesh does not intercept excluded source namespaces, so no companion is
// needed there; a namespace joining the exclusion list loses its companion.
func TestMeshEgressSkipsExcludedNamespaces(t *testing.T) {
	src := egressPolicy("tenant", "default-deny", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "tenant", "default-deny")
	mustCompanion(t, r.Client, "tenant", "default-deny")

	r.Excluded = map[string]struct{}{"tenant": {}}
	reconcilePolicy(t, r, "tenant", "default-deny")
	if _, ok := getCompanion(t, r.Client, "tenant", "default-deny"); ok {
		t.Fatal("companion survived its namespace joining the mesh exclusion list")
	}
}

// A companion isolates egress too; reconciling it must not spawn a companion
// of a companion.
func TestMeshEgressDoesNotRecurseOnCompanions(t *testing.T) {
	src := egressPolicy("app", "default-deny", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "default-deny")
	companion := meshEgressCompanionName("default-deny")
	reconcilePolicy(t, r, "app", companion)
	if _, ok := getCompanion(t, r.Client, "app", companion); ok {
		t.Fatal("companion created for a companion")
	}
}

// A foreign policy at the companion's name is left alone and the source is
// requeued, mirroring the headless-Service reconciler.
func TestMeshEgressDoesNotAdoptForeignPolicy(t *testing.T) {
	src := egressPolicy("app", "default-deny", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	foreign := egressPolicy("app", meshEgressCompanionName("default-deny"), metav1.LabelSelector{MatchLabels: map[string]string{"theirs": "yes"}}, networkingv1.PolicyTypeIngress)
	r := meshEgressReconciler(nil, src, foreign)
	res := reconcilePolicy(t, r, "app", "default-deny")
	if res.RequeueAfter != collisionRequeue {
		t.Fatalf("RequeueAfter = %v, want %v", res.RequeueAfter, collisionRequeue)
	}
	got := mustCompanion(t, r.Client, "app", "default-deny")
	if got.Spec.PodSelector.MatchLabels["theirs"] != "yes" || len(got.OwnerReferences) != 0 {
		t.Fatalf("foreign policy was modified: %+v", got)
	}
}

// Deleting the companion out from under the operator is repaired on the
// next reconcile.
func TestMeshEgressRecreatesDeletedCompanion(t *testing.T) {
	src := egressPolicy("app", "default-deny", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", "default-deny")
	if err := r.Delete(context.Background(), mustCompanion(t, r.Client, "app", "default-deny")); err != nil {
		t.Fatal(err)
	}
	reconcilePolicy(t, r, "app", "default-deny")
	mustCompanion(t, r.Client, "app", "default-deny")
}

func TestMeshEgressCompanionNameStaysValid(t *testing.T) {
	long := strings.Repeat("a", validation.DNS1123SubdomainMaxLength)
	other := strings.Repeat("a", validation.DNS1123SubdomainMaxLength-1) + "b"
	for _, src := range []string{"default-deny", long, other, strings.Repeat("x", 240) + "-.-"} {
		name := meshEgressCompanionName(src)
		if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
			t.Fatalf("companion name for %q invalid: %v (%q)", src[:20], errs, name)
		}
		if !strings.HasSuffix(name, meshEgressCompanionSuffix) {
			t.Fatalf("companion name %q lacks the suffix", name)
		}
	}
	if meshEgressCompanionName(long) == meshEgressCompanionName(other) {
		t.Fatal("two long source names collide on the same companion name")
	}
	if got := meshEgressCompanionName("default-deny"); got != "default-deny-mesh-egress" {
		t.Fatalf("short name = %q", got)
	}
	// And the reconcile path accepts a maximum-length source end to end.
	src := egressPolicy("app", long, metav1.LabelSelector{}, networkingv1.PolicyTypeEgress)
	r := meshEgressReconciler(nil, src)
	reconcilePolicy(t, r, "app", long)
	mustCompanion(t, r.Client, "app", long)
}

func TestMeshEgressSetupRejectsBadPort(t *testing.T) {
	for _, port := range []int32{0, -1, 65536} {
		r := &MeshEgressReconciler{Port: port}
		if err := r.SetupWithManager(nil); err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("port %d: err = %v, want out of range", port, err)
		}
	}
}
