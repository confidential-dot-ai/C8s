package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// systemExcludedNamespaces are never swept. They mirror the namespaces the
// pod-injector MutatingWebhookConfiguration excludes, so the sweep only
// deletes pods the webhook would actually have injected on recreate. The
// release namespace is added at call time (it is not a compile-time constant).
var systemExcludedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
}

// reinjectSweep deletes pods that opted in to C8s injection
// (confidential.ai/cw) but were admitted while the webhook was unavailable, so
// they never received the get-cert containers. It runs once, on operator
// startup, after the webhook PKI is patched: a pod created during the gap
// cannot self-heal because admission only fires on CREATE.
//
// Only pods with a controller owner are deleted — deleting one lets its
// ReplicaSet/StatefulSet/etc recreate it through admission. Bare pods have no
// recreate path, so deleting them would destroy the workload; they are logged
// and left running.
func reinjectSweep(ctx context.Context, c client.Client, excluded map[string]struct{}) error {
	l := log.FromContext(ctx).WithName("reinject-sweep")

	var pods corev1.PodList
	if err := c.List(ctx, &pods); err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	var deleted, skippedBare int
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !needsReinject(pod, excluded) {
			continue
		}
		if metav1.GetControllerOf(pod) == nil {
			l.Info("un-injected pod has no controller owner; leaving it running",
				"namespace", pod.Namespace, "pod", pod.Name,
				"workload", pod.Annotations[webhook.AnnotationWorkload])
			skippedBare++
			continue
		}
		if err := c.Delete(ctx, pod); err != nil {
			if client.IgnoreNotFound(err) == nil {
				continue
			}
			return fmt.Errorf("delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		l.Info("deleted un-injected pod so its controller recreates it through the webhook",
			"namespace", pod.Namespace, "pod", pod.Name,
			"workload", pod.Annotations[webhook.AnnotationWorkload])
		deleted++
	}

	l.Info("reinject sweep complete", "deleted", deleted, "skipped_bare", skippedBare)
	return nil
}

// needsReinject reports whether pod opted in to injection but never received
// it, in a namespace the webhook covers.
func needsReinject(pod *corev1.Pod, excluded map[string]struct{}) bool {
	if pod.Annotations[webhook.AnnotationWorkload] == "" {
		return false
	}
	if _, ok := pod.Annotations[webhook.AnnotationInjected]; ok {
		return false
	}
	if _, ok := excluded[pod.Namespace]; ok {
		return false
	}
	// A terminating pod is already on its way out; recreation will re-admit it.
	if pod.DeletionTimestamp != nil {
		return false
	}
	return true
}

// excludedNamespaceSet builds the sweep's exclusion set from the release
// namespace, the system namespaces, and the operator's extra exclusions
// (mirroring webhook.extraExcluded so the two stay in sync).
func excludedNamespaceSet(releaseNS string, extra []string) map[string]struct{} {
	out := make(map[string]struct{}, len(systemExcludedNamespaces)+len(extra)+1)
	if releaseNS != "" {
		out[releaseNS] = struct{}{}
	}
	for _, ns := range systemExcludedNamespaces {
		out[ns] = struct{}{}
	}
	for _, ns := range extra {
		if ns = strings.TrimSpace(ns); ns != "" {
			out[ns] = struct{}{}
		}
	}
	return out
}
