package nriimagepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const routerEligibleLabel = "confidential.ai/router-eligible"

type routerEligibility uint8

const (
	routerEligibilityUnknown routerEligibility = iota
	routerIneligible
	routerEligible
)

type workerRouterPlacement struct {
	mu       sync.Mutex
	nodeName string
	nodeUID  types.UID
	decision routerEligibility
	client   func() (coreclient.CoreV1Interface, error)
	check    func(context.Context) (bool, error)
	logger   *slog.Logger
}

func newWorkerRouterPlacement(
	nodeName string,
	client func() (coreclient.CoreV1Interface, error),
	check func(context.Context) (bool, error),
	logger *slog.Logger,
) *workerRouterPlacement {
	return &workerRouterPlacement{
		nodeName: nodeName,
		client:   client,
		check:    check,
		logger:   logger,
	}
}

func (p *workerRouterPlacement) reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	client, err := p.client()
	if err != nil {
		return err
	}
	node, err := client.Nodes().Get(ctx, p.nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if node.UID == "" || node.UID != p.nodeUID {
		if err := p.resetForNode(ctx, client, node); err != nil {
			return err
		}
	}
	p.refreshLastKnownDecision(ctx)
	node, err = client.Nodes().Get(ctx, p.nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if node.UID == "" || node.UID != p.nodeUID {
		return p.resetForNode(ctx, client, node)
	}
	if _, err := publishRouterEligibility(ctx, client, node, p.decision == routerEligible); err != nil {
		return err
	}
	if p.decision == routerIneligible {
		return p.deleteWorkerRoutersWaitingForCertificate(ctx, client)
	}
	return nil
}

func (p *workerRouterPlacement) resetForNode(ctx context.Context, client coreclient.CoreV1Interface, node *corev1.Node) error {
	p.decision = routerEligibilityUnknown
	if node.UID == "" {
		return fmt.Errorf("worker Node lacks a UID")
	}
	if _, err := publishRouterEligibility(ctx, client, node, false); err != nil {
		return err
	}
	p.nodeUID = node.UID
	return nil
}

func (p *workerRouterPlacement) refreshLastKnownDecision(ctx context.Context) {
	eligible, err := p.check(ctx)
	if err != nil {
		p.logger.Warn("worker router eligibility check failed", "error", err)
		return
	}
	p.decision = routerIneligible
	if eligible {
		p.decision = routerEligible
	}
}

func publishRouterEligibility(
	ctx context.Context,
	client coreclient.CoreV1Interface,
	node *corev1.Node,
	eligible bool,
) (*corev1.Node, error) {
	value, present := node.Labels[routerEligibleLabel]
	if eligible && value == "true" || !eligible && !present {
		return node, nil
	}
	node = node.DeepCopy()
	if eligible {
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		node.Labels[routerEligibleLabel] = "true"
	} else {
		delete(node.Labels, routerEligibleLabel)
	}
	return client.Nodes().Update(ctx, node, metav1.UpdateOptions{})
}

func (p *workerRouterPlacement) deleteWorkerRoutersWaitingForCertificate(ctx context.Context, client coreclient.CoreV1Interface) error {
	pods, err := client.Pods(workloadclaims.RouterNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", p.nodeName).String(),
		LabelSelector: "app.kubernetes.io/name=router,app.kubernetes.io/instance=c8s",
	})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !isWorkerRouterWaitingForCertificate(pod, p.nodeName) {
			continue
		}
		err := client.Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &pod.UID, ResourceVersion: &pod.ResourceVersion},
		})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return err
		}
	}
	return nil
}

func isWorkerRouterWaitingForCertificate(pod *corev1.Pod, nodeName string) bool {
	if !isWorkerRouter(pod) || pod.Spec.NodeName != nodeName || pod.DeletionTimestamp != nil {
		return false
	}
	if pod.UID == "" || pod.ResourceVersion == "" {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return false
		}
	}
	for _, container := range pod.Status.InitContainerStatuses {
		if container.Name == "c8s-cert-wait" && container.State.Running != nil {
			return true
		}
	}
	return false
}

func isWorkerRouter(pod *corev1.Pod) bool {
	if pod.Namespace != workloadclaims.RouterNamespace || pod.Spec.ServiceAccountName != "c8s-router" {
		return false
	}
	if pod.Labels["app.kubernetes.io/name"] != "router" || pod.Labels["app.kubernetes.io/instance"] != "c8s" {
		return false
	}
	owner := metav1.GetControllerOf(pod)
	return owner != nil && owner.APIVersion == "apps/v1" && owner.Kind == "ReplicaSet" && owner.UID != "" && strings.HasPrefix(owner.Name, "c8s-router-")
}
