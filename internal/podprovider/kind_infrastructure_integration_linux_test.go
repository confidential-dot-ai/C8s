//go:build linux && podprovider_integration

package podprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These fixtures use one physical kind node. Infrastructure DaemonSets must not
// consume the virtual node's Pod slots merely because they tolerate every taint.
type kindInfrastructure struct {
	PhysicalNode string               `json:"physicalNode"`
	PhysicalUID  types.UID            `json:"physicalUID"`
	Hostname     string               `json:"hostname"`
	DaemonSets   map[string]types.UID `json:"daemonSets"`
}

func prepareKindInfrastructure(ctx context.Context, kube client.Client) (*kindInfrastructure, error) {
	var nodes corev1.NodeList
	if err := kube.List(ctx, &nodes); err != nil {
		return nil, err
	}
	if len(nodes.Items) != 1 {
		return nil, errors.New("expected one existing physical kind control-plane node")
	}
	physical := &nodes.Items[0]
	_, controlPlane := physical.Labels["node-role.kubernetes.io/control-plane"]
	if !controlPlane || !strings.HasSuffix(physical.Name, "-control-plane") || physical.UID == "" || physical.Labels[corev1.LabelHostname] != physical.Name || physical.Labels[Annotation] == "true" || strings.HasPrefix(physical.Spec.ProviderID, "podcvm://") {
		return nil, errors.New("existing node is not the disposable physical kind control plane")
	}
	placement := &kindInfrastructure{PhysicalNode: physical.Name, PhysicalUID: physical.UID, Hostname: physical.Labels[corev1.LabelHostname], DaemonSets: map[string]types.UID{}}
	for _, name := range []string{"kindnet", "kube-proxy"} {
		ds := &appsv1.DaemonSet{}
		if err := kube.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: name}, ds); err != nil {
			return nil, err
		}
		before := ds.DeepCopy()
		if err := constrainKindDaemonSet(ds, placement.Hostname); err != nil {
			return nil, fmt.Errorf("%s placement: %w", name, err)
		}
		if err := kube.Patch(ctx, ds, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return nil, err
		}
		placement.DaemonSets[name] = ds.UID
	}
	err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		for name, uid := range placement.DaemonSets {
			ds := &appsv1.DaemonSet{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: name}, ds); err != nil {
				return false, err
			}
			if ds.UID != uid {
				return false, errors.New("kind infrastructure identity changed during placement")
			}
			if !kindDaemonSetReady(ds) {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("physical kind infrastructure rollout: %w", err)
	}
	return placement, nil
}

func constrainKindDaemonSet(ds *appsv1.DaemonSet, hostname string) error {
	if hostname == "" {
		return errors.New("physical hostname is required")
	}
	if existing, ok := ds.Spec.Template.Spec.NodeSelector[corev1.LabelHostname]; ok && existing != hostname {
		return errors.New("existing hostname selector conflicts with the physical kind node")
	}
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{}
	}
	ds.Spec.Template.Spec.NodeSelector[corev1.LabelHostname] = hostname
	return nil
}

func kindDaemonSetReady(ds *appsv1.DaemonSet) bool {
	return ds.Status.ObservedGeneration >= ds.Generation && ds.Status.DesiredNumberScheduled == 1 && ds.Status.UpdatedNumberScheduled == 1 && ds.Status.NumberReady == 1 && ds.Status.NumberMisscheduled == 0
}

func (h *providerControlPlane) assertKindInfrastructure(t *testing.T) {
	t.Helper()
	placement := h.infrastructure
	if placement == nil {
		t.Fatal("missing physical infrastructure placement receipt")
	}
	physical, virtual := &corev1.Node{}, &corev1.Node{}
	if err := h.client.Get(h.ctx, client.ObjectKey{Name: placement.PhysicalNode}, physical); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Get(h.ctx, client.ObjectKey{Name: h.cfg.NodeName}, virtual); err != nil {
		t.Fatal(err)
	}
	if physical.UID != placement.PhysicalUID || virtual.Name == physical.Name {
		t.Fatal("physical/virtual node identities changed")
	}
	for name, uid := range placement.DaemonSets {
		ds := &appsv1.DaemonSet{}
		if err := h.client.Get(h.ctx, client.ObjectKey{Namespace: "kube-system", Name: name}, ds); err != nil {
			t.Fatal(err)
		}
		selector := labels.SelectorFromSet(ds.Spec.Template.Spec.NodeSelector)
		if ds.UID != uid || !kindDaemonSetReady(ds) || !selector.Matches(labels.Set(physical.Labels)) || selector.Matches(labels.Set(virtual.Labels)) {
			t.Fatalf("%s does not remain confined to its physical kind node", name)
		}
	}
	var pods corev1.PodList
	if err := h.client.List(h.ctx, &pods, client.MatchingFields{"spec.nodeName": virtual.Name}); err != nil {
		t.Fatal(err)
	}
	for _, pod := range pods.Items {
		for _, owner := range pod.OwnerReferences {
			if owner.Kind == "DaemonSet" {
				t.Fatalf("infrastructure DaemonSet Pod %s/%s reached the virtual node", pod.Namespace, pod.Name)
			}
		}
	}
}

func TestKindInfrastructureSelectorPreservesExistingScheduling(t *testing.T) {
	ds := &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "network"}}, Spec: corev1.PodSpec{
		NodeSelector: map[string]string{corev1.LabelOSStable: "linux"}, PriorityClassName: "system-node-critical", Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
	}}}}
	before := ds.DeepCopy()
	if err := constrainKindDaemonSet(ds, "owned-control-plane"); err != nil {
		t.Fatal(err)
	}
	if ds.Spec.Template.Spec.NodeSelector[corev1.LabelHostname] != "owned-control-plane" {
		t.Fatal("physical-node constraint missing")
	}
	delete(ds.Spec.Template.Spec.NodeSelector, corev1.LabelHostname)
	if !reflect.DeepEqual(before, ds) {
		t.Fatal("placement changed existing scheduling or workload configuration")
	}
	ds.Spec.Template.Spec.NodeSelector[corev1.LabelHostname] = "another-node"
	before = ds.DeepCopy()
	if err := constrainKindDaemonSet(ds, "owned-control-plane"); err == nil || !reflect.DeepEqual(before, ds) {
		t.Fatal("conflicting placement was broadened or changed")
	}
}
