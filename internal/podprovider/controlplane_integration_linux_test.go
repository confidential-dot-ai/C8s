//go:build linux && podprovider_integration

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	productionwebhook "github.com/confidential-dot-ai/c8s/internal/webhook"
)

// The API, scheduler, node lifecycle, webhooks, provider and leases are real.
// Only Cloud provisioning and the guest attestation reader are simulated.
func TestPodProviderControlPlane(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxPods = 2
	h := newProviderControlPlane(t, cfg)
	t.Log("Cloud provisioning and guest attestation are explicit test fakes")
	cloud := &controlPlaneCloud{
		client: h.client, cfg: cfg, instances: map[string]*instance{},
		keys: map[string]string{}, requests: map[string][]byte{}, holdDeletion: true,
	}
	var guestMode atomic.Int32
	guest := controlPlaneGuest(&guestMode)
	start := func() {
		h.startManager(t, func(mgr ctrl.Manager, name string) error {
			r := &Reconciler{client: h.client, cfg: cfg, cloud: cloud, guest: guest, now: time.Now}
			if err := ctrl.NewControllerManagedBy(mgr).Named(name).For(&corev1.Pod{}).
				WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
					pod, ok := obj.(*corev1.Pod)
					return ok && pod.Spec.NodeName == cfg.NodeName
				})).Complete(r); err != nil {
				return err
			}
			node := &virtualNode{cfg: cfg, cloud: cloud, kube: h.kube, node: nodeObject(cfg)}
			r.ownsNode = node.checkOwnership
			if err := mgr.Add(node); err != nil {
				return err
			}
			return mgr.Add(&orphanWorker{reconciler: r})
		})
	}
	start()
	h.installWebhooks(t)
	h.waitForVirtualNode(t)
	pod := controlPlanePod("scheduled-workload")
	if err := h.client.Create(h.ctx, pod); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKeyFromObject(pod)
	h.await(t, "normal scheduler binds the opted-in Pod", func() bool {
		p := h.pod(t, key)
		return p != nil && p.Spec.NodeName == cfg.NodeName
	})
	h.await(t, "Cloud running cannot grant readiness", func() bool {
		p := h.pod(t, key)
		return p != nil && p.Status.Reason == "AttestationUnavailable"
	})
	pod = h.pod(t, key)
	if controlPlanePodReady(pod) {
		t.Fatal("Cloud state alone granted readiness")
	}
	if len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("Pod CVM admission injected host sidecars or service account credentials")
	}
	if s := cloud.snapshot(); s.creates != 1 || s.createCalls != 1 {
		t.Fatalf("lost response duplicated creation: %+v", s)
	}
	guestMode.Store(1)
	h.await(t, "verified guest projection grants readiness", func() bool {
		return controlPlanePodReady(h.pod(t, key))
	})
	pod = h.pod(t, key)
	firstUID := pod.UID
	assertControlPlaneProjection(t, pod)
	changed := pod.DeepCopy()
	changed.Spec.Containers[0].Image = "example.invalid/changed@sha256:" + strings.Repeat("d", 64)
	if err := h.client.Update(h.ctx, changed); !apierrors.IsBadRequest(err) || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutable-workload admission refusal, got %v", err)
	}
	guestMode.Store(2)
	h.await(t, "foreign guest identity withdraws readiness and endpoints", func() bool {
		p := h.pod(t, key)
		return p != nil && !controlPlanePodReady(p) && p.Status.Reason == "GuestStatusRefused" && p.Annotations[endpointsAnnotation] == ""
	})
	guestMode.Store(1)
	h.await(t, "valid guest recovers readiness", func() bool {
		return controlPlanePodReady(h.pod(t, key))
	})

	frozen := h.recordBytes(t, firstUID)
	h.manager.stop(t)
	beforeRestart := cloud.snapshot()
	start()
	h.await(t, "restarted provider reads the existing VM", func() bool {
		return cloud.snapshot().gets > beforeRestart.gets && controlPlanePodReady(h.pod(t, key))
	})
	if s := cloud.snapshot(); s.creates != 1 || s.createCalls != 1 || !bytes.Equal(frozen, h.recordBytes(t, firstUID)) {
		t.Fatal("provider restart recreated the VM or changed its frozen signed intent")
	}
	h.waitForVirtualNode(t)

	if err := h.client.Delete(h.ctx, h.pod(t, key), client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	h.await(t, "Cloud deletion remains pending across reconciliations", func() bool {
		return cloud.snapshot().deletes >= 2
	})
	pod = h.pod(t, key)
	if pod == nil || pod.DeletionTimestamp.IsZero() || !slices.Contains(pod.Finalizers, finalizer) {
		t.Fatal("Pod disappeared or released its finalizer before confirmed termination")
	}
	var pending record
	if err := json.Unmarshal(h.recordBytes(t, firstUID), &pending); err != nil {
		t.Fatal(err)
	}
	if !pending.DeleteRequested || pending.Deleted || cloud.snapshot().remaining != 1 {
		t.Fatal("pending Cloud deletion lost its durable cleanup authority")
	}
	cloud.releaseDeletion()
	h.awaitDeleted(t, key, firstUID)

	recreated := controlPlanePod(key.Name)
	if err := h.client.Create(h.ctx, recreated); err != nil {
		t.Fatal(err)
	}
	h.await(t, "same name with a new UID creates another VM", func() bool {
		return controlPlanePodReady(h.pod(t, key))
	})
	pod = h.pod(t, key)
	if s := cloud.snapshot(); pod.UID == firstUID || s.creates != 2 || s.keys != 2 {
		t.Fatalf("replacement did not receive a distinct Pod/VM identity: %+v", s)
	}
	secondUID := pod.UID
	peer := controlPlanePod("capacity-peer")
	if err := h.client.Create(h.ctx, peer); err != nil {
		t.Fatal(err)
	}
	peerKey := client.ObjectKeyFromObject(peer)
	h.await(t, "both Pod slots remain available to opted-in workloads", func() bool {
		return controlPlanePodReady(h.pod(t, key)) && controlPlanePodReady(h.pod(t, peerKey))
	})
	peer = h.pod(t, peerKey)
	if peer.Spec.NodeName != cfg.NodeName || cloud.snapshot().remaining != 2 {
		t.Fatal("two-slot scheduler regression did not place both workloads on the virtual node")
	}
	virtual := &corev1.Node{}
	if err := h.client.Get(h.ctx, client.ObjectKey{Name: cfg.NodeName}, virtual); err != nil {
		t.Fatal(err)
	}
	if virtual.Status.Allocatable.Pods().Value() != 2 {
		t.Fatal("scheduler regression requires exactly two advertised Pod slots")
	}
	h.assertKindInfrastructure(t)
	if err := h.client.Delete(h.ctx, peer, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	h.awaitDeleted(t, peerKey, peer.UID)
	if err := h.client.Delete(h.ctx, pod, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	h.awaitDeleted(t, key, secondUID)
	if cloud.snapshot().remaining != 0 {
		t.Fatal("test left an owned fake Cloud VM behind")
	}
	h.manager.stop(t)
	if t.Failed() {
		return
	}
	h.writeResult(t)
}

type providerControlPlane struct {
	ctx            context.Context
	cfg            *Config
	config         *rest.Config
	scheme         *runtime.Scheme
	client         client.Client
	kube           *kubernetes.Clientset
	webhooks       envtest.WebhookInstallOptions
	manager        *controlPlaneManager
	generation     int
	serverVersion  string
	infrastructure *kindInfrastructure
}

func newProviderControlPlane(t *testing.T, cfg *Config) *providerControlPlane {
	t.Helper()
	return newProviderControlPlaneWithTimeout(t, cfg, 240*time.Second)
}

func newProviderControlPlaneWithTimeout(t *testing.T, cfg *Config, timeout time.Duration) *providerControlPlane {
	t.Helper()
	// Retain fixed assertion receipts instead of object or Secret payload logs.
	ctrl.SetLogger(logr.Discard())
	kubeconfig := os.Getenv("C8S_PODPROVIDER_KUBECONFIG")
	if kubeconfig == "" || !filepath.IsAbs(kubeconfig) {
		t.Fatal("C8S_PODPROVIDER_KUBECONFIG must name the disposable harness kubeconfig; use make test-podprovider-integration")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	direct, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	version, err := kube.Discovery().ServerVersion()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	h := &providerControlPlane{ctx: ctx, cfg: cfg, config: config, scheme: scheme, client: direct, kube: kube, serverVersion: version.GitVersion}
	h.infrastructure, err = prepareKindInfrastructure(ctx, direct)
	if err != nil {
		t.Fatalf("restrict disposable kind infrastructure before registering the virtual node: %v", err)
	}
	for _, namespace := range []string{cfg.Namespace, "tenant", "kube-node-lease"} {
		if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	if err := direct.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "tenant"}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	h.webhooks.LocalServingHost = "127.0.0.1"
	if err := h.webhooks.PrepWithoutInstalling(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.webhooks.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if h.manager != nil {
			h.manager.stop(t)
		}
	})
	t.Logf("real Kubernetes API/scheduler/controller-manager %s", version.GitVersion)
	return h
}

type controlPlaneManager struct {
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	stopped bool
}

func (m *controlPlaneManager) stop(t *testing.T) {
	t.Helper()
	if m.stopped {
		return
	}
	m.stopped = true
	m.cancel()
	select {
	case <-m.done:
		if m.err != nil {
			t.Errorf("provider manager stopped with error: %v", m.err)
		}
	case <-time.After(15 * time.Second):
		t.Error("provider manager did not stop within its cleanup deadline")
	}
}

func (h *providerControlPlane) startManager(t *testing.T, register func(ctrl.Manager, string) error) {
	t.Helper()
	h.generation++
	wh := h.webhooks
	mgr, err := ctrl.NewManager(h.config, ctrl.Options{
		Scheme:  h.scheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
		LeaderElection: true, LeaderElectionID: "podprovider-integration", LeaderElectionNamespace: h.cfg.Namespace,
		LeaderElectionReleaseOnCancel: true,
		LeaseDuration:                 new(5 * time.Second), RenewDeadline: new(3 * time.Second), RetryPeriod: new(time.Second),
		// Tests restart managers in one process; metrics are disabled above.
		Controller:    controllerconfig.Controller{SkipNameValidation: new(true)},
		Cache:         cache.Options{ByObject: map[client.Object]cache.ByObject{&corev1.Secret{}: {Namespaces: map[string]cache.Config{h.cfg.Namespace: {}}}}},
		WebhookServer: webhookserver.NewServer(webhookserver.Options{Host: wh.LocalServingHost, Port: wh.LocalServingPort, CertDir: wh.LocalServingCertDir}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := productionwebhook.Register(mgr, productionwebhook.Config{PodCVMProviderEnabled: true, GetCertImage: "example.invalid/cert@sha256:" + strings.Repeat("b", 64), MeshImage: "example.invalid/mesh@sha256:" + strings.Repeat("c", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := register(mgr, fmt.Sprintf("podprovider-integration-%d", h.generation)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(h.ctx)
	m := &controlPlaneManager{cancel: cancel, done: make(chan struct{})}
	h.manager = m
	go func() {
		m.err = mgr.Start(ctx)
		close(m.done)
	}()
	h.await(t, "provider webhook is serving", func() bool {
		return mgr.GetWebhookServer().StartedChecker()(nil) == nil
	})
}

func (h *providerControlPlane) installWebhooks(t *testing.T) {
	t.Helper()
	wh := h.webhooks
	rules := []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods", "pods/status"}, Scope: new(admissionv1.NamespacedScope)}}}
	url := func(path string) *string {
		return new(fmt.Sprintf("https://%s:%d/%s", wh.LocalServingHost, wh.LocalServingPort, path))
	}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "tenant"}}
	mutator := &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "podprovider-integration"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "mutate.podprovider.integration", AdmissionReviewVersions: []string{"v1"}, SideEffects: new(admissionv1.SideEffectClassNone), FailurePolicy: new(admissionv1.Fail), TimeoutSeconds: new(int32(5)), NamespaceSelector: selector, Rules: rules, ClientConfig: admissionv1.WebhookClientConfig{URL: url("mutate-pods"), CABundle: wh.LocalServingCAData}}}}
	validator := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "podprovider-integration"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "validate.podprovider.integration", AdmissionReviewVersions: []string{"v1"}, SideEffects: new(admissionv1.SideEffectClassNone), FailurePolicy: new(admissionv1.Fail), TimeoutSeconds: new(int32(5)), NamespaceSelector: selector, Rules: rules, ClientConfig: admissionv1.WebhookClientConfig{URL: url("validate-pods"), CABundle: wh.LocalServingCAData}}}}
	if err := h.client.Create(h.ctx, mutator); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Create(h.ctx, validator); err != nil {
		t.Fatal(err)
	}
	h.await(t, "API admission observes the routing webhook", func() bool {
		probe := controlPlanePod("admission-probe")
		return h.client.Create(h.ctx, probe, client.DryRunAll) == nil && probe.Spec.NodeSelector[Annotation] == "true"
	})
}

func (h *providerControlPlane) waitForVirtualNode(t *testing.T) {
	t.Helper()
	h.await(t, "virtual node is ready and the node controller removes its startup taint", func() bool {
		node, err := h.kube.CoreV1().Nodes().Get(h.ctx, h.cfg.NodeName, metav1.GetOptions{})
		return err == nil && slices.ContainsFunc(node.Status.Conditions, func(c corev1.NodeCondition) bool {
			return c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue
		}) && !slices.ContainsFunc(node.Spec.Taints, func(taint corev1.Taint) bool {
			return taint.Key == corev1.TaintNodeNotReady || taint.Key == corev1.TaintNodeUnreachable
		})
	})
	h.await(t, "real virtual-node lease is renewed", func() bool {
		lease, err := h.kube.CoordinationV1().Leases("kube-node-lease").Get(h.ctx, h.cfg.NodeName, metav1.GetOptions{})
		return err == nil && lease.Spec.RenewTime != nil && time.Since(lease.Spec.RenewTime.Time) < 40*time.Second
	})
	h.assertKindInfrastructure(t)
}

func (h *providerControlPlane) await(t *testing.T, description string, condition func() bool) {
	t.Helper()
	h.awaitWithTimeout(t, description, 50*time.Second, condition)
}

func (h *providerControlPlane) awaitWithTimeout(t *testing.T, description string, timeout time.Duration, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			t.Log(description)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
		case <-h.manager.done:
			t.Fatalf("provider manager exited while waiting for %s: %v", description, h.manager.err)
		case <-ticker.C:
		}
	}
}

func (h *providerControlPlane) pod(t *testing.T, key client.ObjectKey) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	if err := h.client.Get(h.ctx, key, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		t.Fatal(err)
	}
	return pod
}

func (h *providerControlPlane) recordBytes(t *testing.T, uid types.UID) []byte {
	t.Helper()
	secret := &corev1.Secret{}
	if err := h.client.Get(h.ctx, client.ObjectKey{Namespace: h.cfg.Namespace, Name: identityKey(h.cfg.ProviderID, string(uid))}, secret); err != nil {
		t.Fatal("could not read the persisted provider record:", err)
	}
	return secret.Data["state.json"]
}

func (h *providerControlPlane) awaitDeleted(t *testing.T, key client.ObjectKey, uid types.UID) {
	t.Helper()
	h.await(t, "confirmed VM termination permits Pod and record deletion", func() bool {
		if h.pod(t, key) != nil {
			return false
		}
		err := h.client.Get(h.ctx, client.ObjectKey{Namespace: h.cfg.Namespace, Name: identityKey(h.cfg.ProviderID, string(uid))}, &corev1.Secret{})
		return apierrors.IsNotFound(err)
	})
}

func (h *providerControlPlane) writeResult(t *testing.T) {
	t.Helper()
	dir := os.Getenv("C8S_PODPROVIDER_ARTIFACTS")
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatal("C8S_PODPROVIDER_ARTIFACTS must name the harness evidence directory")
	}
	result := map[string]any{
		"result": "PASS", "apiServer": h.serverVersion, "scheduler": "real kind control plane", "nodeLifecycle": "real controller-manager",
		"cloud": "explicit fake with durable-intent checks, lost response and delayed deletion", "attestation": "explicit fake guest reader",
		"normalSchedulerBinding": true, "realNodeLease": true, "durableIntentBeforeSideEffect": true, "lostResponseCreatesExactlyOneVM": true,
		"providerRestartRetainsSignedIntent": true, "cloudRunningCannotSetPodReady": true, "foreignGuestWithdrawsReadiness": true,
		"schedulerConditionPreserved": true, "sharedPublicIPNotPodIP": true, "immutableScheduledWorkload": true,
		"finalizerWaitsForConfirmedTermination": true, "sameNameNewUIDCreatesNewVM": true, "ownedFakeVMsRemaining": 0,
		"twoConcurrentPodsAtCapacityTwo": true, "infrastructureDaemonSetsExcluded": true, "infrastructurePlacement": h.infrastructure,
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func controlPlanePod(name string) *corev1.Pod {
	pod := fixturePod()
	pod.Name, pod.UID, pod.ResourceVersion = name, "", ""
	pod.Spec.NodeName = ""
	pod.Spec.NodeSelector = nil
	pod.Spec.Tolerations = nil
	return pod
}

func controlPlanePodReady(pod *corev1.Pod) bool {
	return pod != nil && slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
	})
}

func assertControlPlaneProjection(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	if pod.Status.PodIP != "" || len(pod.Status.PodIPs) != 0 {
		t.Fatal("shared public IP was exposed as Pod IP")
	}
	if !slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == corev1.PodScheduled && c.Status == corev1.ConditionTrue
	}) {
		t.Fatal("guest projection replaced the scheduler-owned condition")
	}
	if len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].Image != pod.Spec.Containers[0].Image {
		t.Fatal("guest image name was not projected from the frozen manifest")
	}
	if pod.Annotations[endpointsAnnotation] == "" {
		t.Fatal("ready Pod has no translated endpoint tuples")
	}
}

func controlPlaneGuest(mode *atomic.Int32) guestReader {
	started := metav1.Now()
	return func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
		if mode.Load() == 0 {
			return podstatus.PodProjection{}, errors.New("test fake attestation unavailable")
		}
		doc, err := rec.document()
		if err != nil {
			return podstatus.PodProjection{}, err
		}
		pod, err := launchconfig.ParsePodManifest([]byte(doc.Pod.Manifest))
		if err != nil {
			return podstatus.PodProjection{}, err
		}
		statuses := make([]corev1.ContainerStatus, 0, len(pod.Spec.Containers))
		for _, container := range pod.Spec.Containers {
			statuses = append(statuses, corev1.ContainerStatus{Name: container.Name, Image: "untrusted-guest-image-name", ImageID: container.Image, Ready: true, Started: new(true), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: started}}})
		}
		uid := string(rec.UID)
		if mode.Load() == 2 {
			uid = "another-pod"
		}
		wire := map[string]any{
			"metadata": map[string]string{"uid": uid, "namespace": rec.Namespace, "name": rec.Name + "-" + doc.Node.Name},
			"status":   corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}, {Type: corev1.ContainersReady, Status: corev1.ConditionTrue}, {Type: corev1.PodScheduled, Status: corev1.ConditionFalse}}},
		}
		data, err := json.Marshal(wire)
		if err != nil {
			return podstatus.PodProjection{}, err
		}
		var projection podstatus.PodProjection
		err = json.Unmarshal(data, &projection)
		return projection, err
	}
}

type controlPlaneCloud struct {
	mu                                  sync.Mutex
	client                              client.Client
	cfg                                 *Config
	instances                           map[string]*instance
	keys                                map[string]string
	requests                            map[string][]byte
	creates, createCalls, deletes, gets int
	lostResponse, holdDeletion          bool
}

func (f *controlPlaneCloud) Create(ctx context.Context, key string, req createRequest) (*instance, error) {
	proposed, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := f.requireDurableIntent(ctx, key, proposed); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	if id, exists := f.keys[key]; exists {
		if !bytes.Equal(f.requests[key], proposed) {
			return nil, errors.New("test fake Cloud: idempotency key reused with changed launch bytes")
		}
		return cloneControlPlaneInstance(f.instances[id]), nil
	}
	f.creates++
	in := instanceFor(req)
	in.ID = fmt.Sprintf("i-controlplane-%d", f.creates)
	in.Compute.VCPUs, in.Compute.MemoryGiB = f.cfg.VCPUs, f.cfg.MemoryMiB/1024
	f.instances[in.ID], f.keys[key], f.requests[key] = in, in.ID, proposed
	if !f.lostResponse {
		f.lostResponse = true
		return nil, errors.New("test fake Cloud: create response lost after VM creation")
	}
	return cloneControlPlaneInstance(in), nil
}

func (f *controlPlaneCloud) requireDurableIntent(ctx context.Context, key string, proposed []byte) error {
	secret := &corev1.Secret{}
	if err := f.client.Get(ctx, client.ObjectKey{Namespace: f.cfg.Namespace, Name: key}, secret); err != nil {
		return errors.New("test fake Cloud: launch has no durable record")
	}
	var rec record
	if err := json.Unmarshal(secret.Data["state.json"], &rec); err != nil || !rec.CreateAttempted || rec.Key != key || secret.Labels[ownerLabel] != f.cfg.ProviderID {
		return errors.New("test fake Cloud: launch record is not an owned attempted intent")
	}
	frozen, err := json.Marshal(rec.Request)
	if err != nil || !bytes.Equal(frozen, proposed) {
		return errors.New("test fake Cloud: launch differs from its frozen request")
	}
	doc, err := rec.document()
	if err != nil {
		return err
	}
	pod := &corev1.Pod{}
	if err := f.client.Get(ctx, client.ObjectKey{Namespace: doc.Pod.Namespace, Name: doc.Pod.Name}, pod); err != nil {
		return err
	}
	if string(pod.UID) != doc.Pod.UID || !slices.Contains(pod.Finalizers, finalizer) {
		return errors.New("test fake Cloud: launch has no matching Pod cleanup finalizer")
	}
	return nil
}

func (f *controlPlaneCloud) Find(_ context.Context, key string) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneControlPlaneInstance(f.instances[f.keys[key]]), nil
}

func (f *controlPlaneCloud) Get(_ context.Context, id string) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.instances[id] == nil {
		return nil, errCloudNotFound
	}
	return cloneControlPlaneInstance(f.instances[id]), nil
}

func (f *controlPlaneCloud) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	if in := f.instances[id]; in != nil {
		if f.holdDeletion {
			in.Status = "terminating"
		} else {
			delete(f.instances, id)
		}
	}
	return nil
}

func (*controlPlaneCloud) Ping(context.Context) error { return nil }

func (f *controlPlaneCloud) releaseDeletion() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holdDeletion = false
}

type controlPlaneCloudCounts struct{ creates, createCalls, deletes, gets, remaining, keys int }

func (f *controlPlaneCloud) snapshot() controlPlaneCloudCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return controlPlaneCloudCounts{f.creates, f.createCalls, f.deletes, f.gets, len(f.instances), len(f.keys)}
}

func cloneControlPlaneInstance(in *instance) *instance {
	if in == nil {
		return nil
	}
	copy := *in
	copy.Labels, copy.Endpoints = maps.Clone(in.Labels), slices.Clone(in.Endpoints)
	return &copy
}
