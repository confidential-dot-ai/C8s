package nriimagepolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/nri/pkg/api"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Where a gke, aks or measured worker node's kubelet keeps its credentials.
const nodeKubeconfig = "/var/lib/kubelet/kubeconfig"

const nodeDeleteTimeout = 30 * time.Second

// The kubeconfig is read per delete: the kubelet rotates the credential it names.
func (p *plugin) deleteNodePod(ctx context.Context, pod *api.PodSandbox) error {
	pods, err := p.cfg.nodePodClient(nodeKubeconfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, nodeDeleteTimeout)
	defer cancel()
	return deletePodInstance(ctx, pods, pod)
}

// The UID precondition holds the delete to the instance the gate refused.
func deletePodInstance(ctx context.Context, pods coreclient.PodsGetter, pod *api.PodSandbox) error {
	uid := types.UID(pod.GetUid())
	return pods.Pods(pod.GetNamespace()).Delete(ctx, pod.GetName(), metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	})
}

// A delete the UID precondition misses means another instance holds the name.
func refusedPodGone(err error) bool {
	return err == nil || apierrors.IsNotFound(err) || apierrors.IsConflict(err)
}

func (c *config) nodePodClient(kubeconfig string) (coreclient.CoreV1Interface, error) {
	nodeAPI, err := c.nodeAPIConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	return coreclient.NewForConfig(nodeAPI)
}

func (c *config) nodeAPIConfig(kubeconfig string) (*rest.Config, error) {
	credentials := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	document, err := credentials.Load()
	if err != nil {
		return nil, fmt.Errorf("read this node's API credentials from %s: %w", kubeconfig, err)
	}
	nodeAPI, err := clientcmd.NewDefaultClientConfig(*document, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("this node's API credentials at %s: %w", kubeconfig, err)
	}
	if c.refusesACredentialHelper() && namesACredentialHelper(nodeAPI) {
		return nil, fmt.Errorf("this node's API credentials at %s name a credential helper to run", kubeconfig)
	}
	return nodeAPI, nil
}

// A measured worker's kubelet writes that kubeconfig itself, naming certificate
// files; a gke kubelet's names a helper the node runs.
func (c *config) refusesACredentialHelper() bool {
	return c.Worker
}

func namesACredentialHelper(cfg *rest.Config) bool {
	return cfg.ExecProvider != nil || cfg.AuthProvider != nil
}
