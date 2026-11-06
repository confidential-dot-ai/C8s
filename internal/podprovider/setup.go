package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Setup adds the Pod reconciler, orphan recovery and a leased virtual node.
// The manager must use leader election; only its elected leader may launch VMs.
func Setup(mgr manager.Manager, cfg *Config) error {
	if cfg == nil || cfg.key == nil {
		return errors.New("provider configuration must be loaded before Setup")
	}
	config := rest.CopyConfig(mgr.GetConfig())
	config.Timeout = cloudTimeout
	direct, err := client.New(config, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return err
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	api := newCloudClient(cfg)
	r := &Reconciler{client: direct, cfg: cfg, cloud: api, guest: readGuest, now: time.Now, recorder: mgr.GetEventRecorder("c8s-pod-cvm-provider")}
	// The provider's pods are the ones bound to its node. Watch them through
	// a cache of its own so the operator caches no other pod for it, and
	// reconcile through the direct client.
	pods, err := cache.New(mgr.GetConfig(), cache.Options{
		Scheme:           mgr.GetScheme(),
		Mapper:           mgr.GetRESTMapper(),
		DefaultTransform: cache.TransformStripManagedFields(),
		ByObject:         map[client.Object]cache.ByObject{&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", cfg.NodeName)}},
	})
	if err != nil {
		return err
	}
	if err := mgr.Add(pods); err != nil {
		return err
	}
	if err := ctrl.NewControllerManagedBy(mgr).Named("pod-cvm").
		WatchesRawSource(source.Kind(pods, &corev1.Pod{}, &handler.TypedEnqueueRequestForObject[*corev1.Pod]{})).Complete(r); err != nil {
		return err
	}
	n := &virtualNode{cfg: cfg, cloud: api, kube: kube, node: nodeObject(cfg)}
	r.ownsNode = n.checkOwnership
	if err := mgr.Add(n); err != nil {
		return err
	}
	if err := mgr.Add(&orphanWorker{reconciler: r}); err != nil {
		return err
	}
	return nil
}

type virtualNode struct {
	cfg   *Config
	cloud cloudAPI
	kube  kubernetes.Interface
	node  *corev1.Node
	guard atomic.Pointer[ownedNodes]
}

func (*virtualNode) NeedLeaderElection() bool { return true }

func (n *virtualNode) Start(ctx context.Context) error {
	for {
		err := n.run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		ctrl.LoggerFrom(ctx).Error(err, "Pod CVM virtual node unavailable")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}
	}
}

func (n *virtualNode) run(ctx context.Context) error {
	guard := n.guard.Load()
	if guard == nil {
		if err := ensureOwnedNode(ctx, n.kube.CoreV1().Nodes(), n.node); err != nil {
			return err
		}
		current, err := n.kube.CoreV1().Nodes().Get(ctx, n.cfg.NodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		guard = &ownedNodes{NodeInterface: n.kube.CoreV1().Nodes(), uid: current.UID, name: n.cfg.NodeName, provider: n.cfg.ProviderID}
		n.guard.Store(guard)
	}
	if _, err := guard.Get(ctx, n.cfg.NodeName, metav1.GetOptions{}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	nc, err := vknode.NewNodeController(n, n.node, guard, vknode.WithNodeEnableLeaseV1(n.kube.CoordinationV1().Leases("kube-node-lease"), 40), vknode.WithNodePingTimeout(10*time.Second))
	if err != nil {
		return err
	}
	return nc.Run(ctx)
}

func (n *virtualNode) Ping(ctx context.Context) error {
	err := n.checkOwnership(ctx)
	if err == nil {
		err = n.cloud.Ping(ctx)
	}
	return err
}

func (n *virtualNode) checkOwnership(ctx context.Context) error {
	g := n.guard.Load()
	if g == nil {
		return errors.New("provider node registration is pending")
	}
	_, err := g.Get(ctx, n.cfg.NodeName, metav1.GetOptions{})
	return err
}

// The SDK reconciles by name. Bind every read and status patch to the node UID
// registered by this process, and never adopt a replacement with the same name.
type ownedNodes struct {
	coreclient.NodeInterface
	uid            types.UID
	name, provider string
}

func (n *ownedNodes) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Node, error) {
	if name != n.name {
		return nil, errors.New("foreign virtual node name")
	}
	obj, err := n.NodeInterface.Get(ctx, name, opts)
	if err != nil {
		return nil, err
	}
	if obj.UID != n.uid || obj.Labels[ownerLabel] != n.provider || obj.Spec.ProviderID != "podcvm://"+n.provider {
		return nil, errors.New("virtual node ownership changed")
	}
	return obj, nil
}
func (*ownedNodes) Create(context.Context, *corev1.Node, metav1.CreateOptions) (*corev1.Node, error) {
	return nil, errors.New("registered virtual node disappeared")
}
func (n *ownedNodes) Patch(ctx context.Context, name string, kind types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*corev1.Node, error) {
	if kind != types.StrategicMergePatchType && kind != types.MergePatchType {
		return nil, errors.New("unexpected virtual node patch type")
	}
	obj, err := n.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var patch map[string]any
	if err := json.Unmarshal(data, &patch); err != nil {
		return nil, err
	}
	metadata, ok := patch["metadata"].(map[string]any)
	if !ok {
		metadata = map[string]any{}
		patch["metadata"] = metadata
	}
	metadata["uid"], metadata["resourceVersion"] = string(n.uid), obj.ResourceVersion
	b, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	return n.NodeInterface.Patch(ctx, name, kind, b, opts, subresources...)
}

// NodeController publishes status and renews the lease only after Ping succeeds.
// Loss of Cloud health stops heartbeats; Kubernetes applies its normal node timeout.
func (*virtualNode) NotifyNodeStatus(context.Context, func(*corev1.Node)) {}

func nodeObject(cfg *Config) *corev1.Node {
	capacity := corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cfg.VCPUs*cfg.MaxPods, resource.DecimalSI), corev1.ResourceMemory: *resource.NewQuantity((cfg.MemoryMiB-cfg.ReservedMemoryMiB)*(1<<20)*cfg.MaxPods, resource.BinarySI), corev1.ResourcePods: *resource.NewQuantity(cfg.MaxPods, resource.DecimalSI)}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: cfg.NodeName, Labels: map[string]string{Annotation: "true", ownerLabel: cfg.ProviderID}},
		Spec:   corev1.NodeSpec{ProviderID: "podcvm://" + cfg.ProviderID, Taints: []corev1.Taint{{Key: Annotation, Value: "true", Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{Capacity: capacity, Allocatable: capacity.DeepCopy(), Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "ProviderReady", LastTransitionTime: metav1.Now()}}},
	}
}

func ensureOwnedNode(ctx context.Context, api coreclient.NodeInterface, want *corev1.Node) error {
	current, err := api.Get(ctx, want.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		starting := want.DeepCopy()
		starting.Status.Conditions[0].Status = corev1.ConditionUnknown
		starting.Status.Conditions[0].Reason = "ProviderStarting"
		_, err = api.Create(ctx, starting, metav1.CreateOptions{})
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		current, err = api.Get(ctx, want.Name, metav1.GetOptions{})
	}
	if err != nil {
		return err
	}
	if current.Labels[ownerLabel] != want.Labels[ownerLabel] || current.Spec.ProviderID != want.Spec.ProviderID {
		return errors.New("refusing to adopt an existing node owned by another provider")
	}
	return nil
}

type orphanWorker struct{ reconciler *Reconciler }

func (*orphanWorker) NeedLeaderElection() bool { return true }
func (w *orphanWorker) Start(ctx context.Context) error {
	for {
		if err := w.reconciler.sweep(ctx); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Pod CVM orphan recovery failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}
	}
}
