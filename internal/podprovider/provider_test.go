package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// fixtureConfig exercises the production mounted-file loader. No test-only
// attestation bypass or alternate launch authority is present in production.
func fixtureConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	write("launch.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	write("server.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	write("token", []byte("test-provider-token\n"))
	write("manifest.json", []byte(`{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"`+strings.Repeat("11", 48)+`","rtmr1":"`+strings.Repeat("22", 48)+`","rtmr2":"`+strings.Repeat("33", 48)+`"}}`))
	write("workloads.json", []byte(`{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:`+strings.Repeat("a", 64)+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	cfg := Config{ProviderID: "test-provider", NodeName: "pod-cvm-node", Namespace: "provider-system", CloudURL: "https://cloud.example", CloudTokenFile: "token", Image: "c8s-pod@2026.10.26-1", ImageManifestFile: "manifest.json", LaunchKeyFile: "launch.key", ServerAddress: "198.51.100.2", ServerPublicKeyFile: "server.pub", WorkloadsFile: "workloads.json", ClusterID: "test-cluster", Size: "c1.2x", Location: "eu", VCPUs: 2, MemoryMiB: 8192, ReservedMemoryMiB: 1024, MaxPods: 10, MeshPeers: []string{"203.0.113.2:9443"}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write("config.json", b)
	loaded, err := LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func fixturePod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "11111111-1111-1111-1111-111111111111", Annotations: map[string]string{Annotation: "true"}}, Spec: corev1.PodSpec{NodeName: "pod-cvm-node", AutomountServiceAccountToken: new(false), ServiceAccountName: "default", Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app@sha256:" + strings.Repeat("a", 64), Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionTrue}}}}
}

type fakeCloud struct {
	in          *instance
	createCalls int
	deleteCalls int
	create      func(string, createRequest) (*instance, error)
	find        func(string) (*instance, error)
	ping        func() error
}

func (f *fakeCloud) Create(_ context.Context, key string, req createRequest) (*instance, error) {
	f.createCalls++
	if f.create != nil {
		return f.create(key, req)
	}
	f.in = instanceFor(req)
	return f.in, nil
}
func (f *fakeCloud) Find(_ context.Context, key string) (*instance, error) {
	if f.find != nil {
		return f.find(key)
	}
	return f.in, nil
}
func (f *fakeCloud) Get(_ context.Context, id string) (*instance, error) {
	if f.in == nil || f.in.ID != id {
		return nil, errCloudNotFound
	}
	return f.in, nil
}
func (f *fakeCloud) Delete(_ context.Context, id string) error {
	f.deleteCalls++
	if f.in == nil || f.in.ID != id {
		return errCloudNotFound
	}
	f.in.Status = "terminating"
	return nil
}
func (f *fakeCloud) Ping(context.Context) error {
	if f.ping != nil {
		return f.ping()
	}
	return nil
}

func instanceFor(req createRequest) *instance {
	in := &instance{ID: "i-test-instance", Status: "running", Tee: req.Tee, Labels: maps.Clone(req.Labels)}
	in.Image.Family, in.Image.Version, _ = strings.Cut(req.Image, "@")
	in.Compute.VCPUs, in.Compute.MemoryGiB = 2, 8
	in.Boot.Count = 1
	for i, rule := range req.Network.Ingress {
		port := 30000 + i
		if req.Network.PublicIP == "dedicated" {
			port = rule.Port
		}
		in.Endpoints = append(in.Endpoints, endpoint{Name: rule.Name, Host: "203.0.113.5", Port: port})
	}
	return in
}

func fixtureProjection(rec *record) podstatus.PodProjection {
	return podstatus.PodProjection{Metadata: podstatus.PodMetadata{UID: string(rec.UID), Namespace: rec.Namespace, Name: rec.Name + "-" + rec.Key}, Status: podstatus.PodStatus{Phase: corev1.PodRunning, Conditions: []podstatus.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}, {Type: corev1.ContainersReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []podstatus.ContainerStatus{{Name: "app", Ready: true, State: &podstatus.ContainerState{Running: &podstatus.ContainerRunning{}}}}, InitContainerStatuses: []podstatus.ContainerStatus{{Name: workloadclaims.MeshContainerName, Ready: true, State: &podstatus.ContainerState{Running: &podstatus.ContainerRunning{}}}}}}
}

func fixtureReconciler(t *testing.T, pod *corev1.Pod) (*Reconciler, *fakeCloud) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1.Pod{}).WithObjects(pod).Build()
	f := &fakeCloud{}
	r := &Reconciler{client: c, cfg: fixtureConfig(t), cloud: f, now: time.Now, guest: func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
		return fixtureProjection(rec), nil
	}}
	return r, f
}

func reconcile(t *testing.T, r *Reconciler, pod *corev1.Pod) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	return err
}

func getPod(t *testing.T, r *Reconciler, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	out := &corev1.Pod{}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), out); err != nil {
		t.Fatal(err)
	}
	return out
}

func getRecord(t *testing.T, r *Reconciler, pod *corev1.Pod) *record {
	t.Helper()
	rec, _, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestLaunchIntentPrecedesCloudAndSurvivesLostResponse(t *testing.T) {
	pod := fixturePod()
	pod.Labels = map[string]string{"tenant": "one"}
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}, {Name: "TENANT", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.labels['tenant']"}}}}
	r, cloud := fixtureReconciler(t, pod)
	var frozen []byte
	cloud.create = func(key string, req createRequest) (*instance, error) {
		current := getPod(t, r, pod)
		if !controllerutil.ContainsFinalizer(current, finalizer) {
			t.Fatal("Cloud called before finalizer")
		}
		rec := getRecord(t, r, pod)
		if !rec.CreateAttempted || rec.Key != key || !reflect.DeepEqual(rec.Request, req) {
			t.Fatal("Cloud called before exact request and attempt persisted")
		}
		frozen = append([]byte(nil), req.Trust.InitData.Document...)
		doc, err := rec.document()
		if err != nil {
			t.Fatal(err)
		}
		guest, err := launchconfig.ParsePodManifest([]byte(doc.Pod.Manifest))
		if err != nil {
			t.Fatal(err)
		}
		if doc.Workloads != r.cfg.workloads || guest.Spec.ServiceAccountName != "" || guest.Spec.NodeName != "" || guest.Annotations[Annotation] != "" {
			t.Fatal("launch trust or guest sanitization differs")
		}
		if guest.Spec.Containers[0].Env[0].Value != "app" || guest.Spec.Containers[0].Env[1].Value != "one" {
			t.Fatal("external metadata was not frozen")
		}
		cloud.in = instanceFor(req)
		return nil, errors.New("response lost after committed create")
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("expected lost create response")
	}
	// An operator restart/config image upgrade must recover the old signed
	// request and UID assignment, never produce a second randomized document.
	next := *r.cfg
	next.Image = "c8s-pod@2026.11.01-1"
	restarted := &Reconciler{client: r.client, cfg: &next, cloud: cloud, guest: r.guest, now: r.now}
	if err := reconcile(t, restarted, pod); err != nil {
		t.Fatal(err)
	}
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodRunning || got.Status.PodIP != "" || got.Annotations[endpointsAnnotation] == "" {
		t.Fatalf("incorrect running projection: %+v", got.Status)
	}
	if len(got.Status.InitContainerStatuses) != 0 || got.Status.ContainerStatuses[0].Image != pod.Spec.Containers[0].Image {
		t.Fatal("guest-only container leaked or image was not pinned")
	}
	if cloud.createCalls != 1 || !bytes.Equal(getRecord(t, r, pod).Request.Trust.InitData.Document, frozen) {
		t.Fatal("restart recreated or resigned UID")
	}
	got.Labels["tenant"] = "changed"
	if err := matchesPod(getRecord(t, r, pod), got); err == nil {
		t.Fatal("changed FieldRef dependency accepted")
	}
}

func TestDeletionResolvesUncertainCreateBeforeReleasingFinalizer(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	var first createRequest
	cloud.find = func(string) (*instance, error) { return nil, nil } // uncommitted rows are invisible
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		if cloud.createCalls == 1 {
			first = req
		}
		if !reflect.DeepEqual(first, req) {
			t.Fatal("uncertain create replay changed bytes")
		}
		return nil, errors.New("idempotency_in_flight")
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("expected uncertain create")
	}
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("in-flight deletion must remain unresolved")
	}
	if !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) || getRecord(t, r, pod).Deleted {
		t.Fatal("empty lookup discarded in-flight cleanup")
	}
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		if !reflect.DeepEqual(first, req) {
			t.Fatal("replay changed")
		}
		cloud.in = instanceFor(req)
		return cloud.in, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 || !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) {
		t.Fatal("deletion was not awaited")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Pod finalizer not released: %v", err)
	}
	if _, _, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID))); !apierrors.IsNotFound(err) {
		t.Fatalf("record retained after confirmed delete: %v", err)
	}
}

func TestTerminalOutcomeAndRebootNeverRelaunchUID(t *testing.T) {
	for _, outcome := range []string{"succeeded", "failed-vm", "reboot"} {
		t.Run(outcome, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			want := corev1.PodFailed
			switch outcome {
			case "succeeded":
				want = corev1.PodSucceeded
				r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
					p := fixtureProjection(rec)
					p.Status.Phase = want
					return p, nil
				}
			case "failed-vm":
				cloud.in.Status = "failed"
			case "reboot":
				cloud.in.Boot.Count = 2
			}
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if getRecord(t, r, pod).TerminalStatus == nil || getPod(t, r, pod).Status.Phase != want || cloud.deleteCalls != 1 {
				t.Fatal("terminal outcome not persisted before delete")
			}
			cloud.in.Status = "terminated"
			for range 3 {
				if err := reconcile(t, r, pod); err != nil {
					t.Fatal(err)
				}
			}
			if cloud.createCalls != 1 || getPod(t, r, pod).Status.Phase != want || !getRecord(t, r, pod).Deleted {
				t.Fatal("terminal UID relaunched or outcome lost")
			}
		})
	}
}

func TestOrphanSweepCleansOnlyOriginalUID(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	old := getPod(t, r, pod)
	old.Finalizers = nil
	if err := r.client.Update(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Delete(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	replacement := fixturePod()
	replacement.UID = "22222222-2222-2222-2222-222222222222"
	if err := r.client.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := r.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatal("old UID orphan not deleted")
	}
	cloud.in.Status = "terminated"
	if err := r.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getPod(t, r, replacement); got.UID != replacement.UID || len(got.Finalizers) != 0 {
		t.Fatal("orphan cleanup touched replacement Pod")
	}
	if cloud.createCalls != 1 {
		t.Fatal("orphan recovery launched an instance")
	}
}

func TestUnverifiedStatusWithdrawsReadinessAndEndpoints(t *testing.T) {
	for _, failure := range []string{"attestation", "foreign-uid", "unknown-container", "duplicate-status"} {
		t.Run(failure, func(t *testing.T) {
			pod := fixturePod()
			r, _ := fixtureReconciler(t, pod)
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
				p := fixtureProjection(rec)
				switch failure {
				case "attestation":
					return p, errors.New("attestation failed")
				case "foreign-uid":
					p.Metadata.UID = "foreign"
				case "unknown-container":
					p.Status.ContainerStatuses[0].Name = "foreign"
				case "duplicate-status":
					p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, p.Status.ContainerStatuses[0])
				}
				return p, nil
			}
			if err := reconcile(t, r, pod); err == nil {
				t.Fatal("unverified guest status accepted")
			}
			got := getPod(t, r, pod)
			if got.Annotations[endpointsAnnotation] != "" {
				t.Fatal("unverified endpoint remained published")
			}
			for _, c := range got.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status != corev1.ConditionUnknown {
					t.Fatal("unverified Pod remained Ready")
				}
			}
			if got.Status.ContainerStatuses[0].Ready {
				t.Fatal("unverified container remained Ready")
			}
		})
	}
}

func TestFrozenCredentialsAndOldUncertainIntentFailClosed(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.create = func(string, createRequest) (*instance, error) { return nil, errors.New("timeout") }
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("expected create error")
	}
	r.cfg.token = "different-org-token"
	if _, _, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID))); err == nil {
		t.Fatal("credential change accepted for existing intent")
	}
	r.cfg.token = "test-provider-token"
	r.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("old uncertain deletion should require resolution")
	}
	if cloud.createCalls != 1 || !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) {
		t.Fatal("old intent recreated or discarded")
	}
}

func TestProviderRejectsUnlaunchableWorkloadsBeforeCloud(t *testing.T) {
	for _, kind := range []string{"long-name", "huge-memory", "cpu-total", "tag", "service-account", "secret-env", "provider-fieldref"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			switch kind {
			case "long-name":
				pod.Name = strings.Repeat("a", 206)
			case "huge-memory":
				pod.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("100000000000000000000")}
			case "cpu-total":
				pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: pod.Spec.Containers[0].Image, Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")}}}}
				pod.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}
			case "tag":
				pod.Spec.Containers[0].Image = "busybox:latest"
			case "service-account":
				pod.Spec.AutomountServiceAccountToken = nil
			case "secret-env":
				pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "key"}}}}
			case "provider-fieldref":
				pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "ENDPOINTS", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.annotations['" + endpointsAnnotation + "']"}}}}
			}
			if _, err := r.cfg.launch(pod); err == nil {
				t.Fatal("invalid workload accepted")
			}
			if cloud.createCalls != 0 {
				t.Fatal("invalid workload reached Cloud")
			}
		})
	}
}

func TestDedicatedEndpointsRequireOnePreservedAddress(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	r.cfg.PublicIP = "dedicated"
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	in := instanceFor(rec.Request)
	address, apps, ip, err := endpoints(rec, in)
	if err != nil || address != "203.0.113.5:8443" || len(apps) != 1 || ip != "203.0.113.5" {
		t.Fatalf("dedicated projection: %s %v %s %v", address, apps, ip, err)
	}
	in.Endpoints[1].Port++
	if _, _, _, err := endpoints(rec, in); err == nil {
		t.Fatal("translated dedicated app port accepted")
	}
	in = instanceFor(rec.Request)
	in.Compute.MemoryGiB = 1
	if err := validateInstance(rec, in); err == nil {
		t.Fatal("undersized Cloud instance accepted")
	}
}

func TestLoadConfigStrictness(t *testing.T) {
	cfg := fixtureConfig(t)
	path := filepath.Join(filepath.Dir(cfg.CloudTokenFile), "config.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{append(append([]byte(nil), original...), []byte(" {}")...), []byte(`{"unexpected":true}`), bytes.Repeat([]byte("a"), maxFile+1)} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("ambiguous/oversized configuration accepted")
		}
	}
}

func TestDirectBindingWithoutOptInFailsWithoutCloudEffects(t *testing.T) {
	pod := fixturePod()
	delete(pod.Annotations, Annotation)
	r, cloud := fixtureReconciler(t, pod)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodFailed || got.Status.Reason != "PodCVMOptInRequired" || len(got.Finalizers) != 0 || cloud.createCalls != 0 {
		t.Fatal("unrequested direct binding was launched or left pending")
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if getPod(t, r, pod).ResourceVersion != got.ResourceVersion || cloud.createCalls != 0 {
		t.Fatal("refusal status looped or launched a Cloud instance")
	}
}
