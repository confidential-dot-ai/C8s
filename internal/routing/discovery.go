package routing

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// WatchAgents keeps index current from the pods the Kubernetes API reports,
// until ctx ends. The API is the control plane's: what it reports only
// decides where the router dials, never what the dial accepts.
func WatchAgents(ctx context.Context, client kubernetes.Interface, index *AgentIndex, logger *slog.Logger) {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithTransform(slimPod))
	pods := factory.Core().V1().Pods().Informer()
	_, err := pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { updateAgent(index, obj) },
		UpdateFunc: func(_, obj any) { updateAgent(index, obj) },
		DeleteFunc: func(obj any) {
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err == nil {
				index.Delete(key)
			}
		},
	})
	if err != nil {
		logger.Error("agent discovery", "error", err)
		return
	}
	factory.Start(ctx.Done())
	factory.Shutdown()
}

func updateAgent(index *AgentIndex, obj any) {
	if pod, ok := obj.(*corev1.Pod); ok {
		index.Update(pod)
	}
}

// slimPod keeps only what agentOf reads, so the informer's cache stays small
// in a cluster of many pods.
func slimPod(obj any) (any, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	slim := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:              pod.Name,
		Namespace:         pod.Namespace,
		ResourceVersion:   pod.ResourceVersion,
		CreationTimestamp: pod.CreationTimestamp,
		DeletionTimestamp: pod.DeletionTimestamp,
	}}
	for _, name := range []string{workloadclaims.AnnotationClientDocument, workloadclaims.AnnotationPodCVMEndpoints} {
		if v, ok := pod.Annotations[name]; ok {
			if slim.Annotations == nil {
				slim.Annotations = map[string]string{}
			}
			slim.Annotations[name] = v
		}
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			slim.Status.Conditions = []corev1.PodCondition{{Type: c.Type, Status: c.Status}}
		}
	}
	return slim, nil
}
