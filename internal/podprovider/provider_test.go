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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
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
	write("launch.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	write("token", []byte("test-provider-token\n"))
	write("cds.json", providerCDSPolicy(t, []byte("schemaVersion: c8s-cds/v1\nclusterID: test-cluster\n")))
	write("manifest.json", []byte(`{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"`+strings.Repeat("11", 48)+`","rtmr1":"`+strings.Repeat("22", 48)+`","rtmr2":"`+strings.Repeat("33", 48)+`"}}`))
	write("workloads.json", []byte(`{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:`+strings.Repeat("a", 64)+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	cfg := Config{ProviderID: "test-provider", NodeName: "pod-cvm-node", Namespace: "provider-system", CloudURL: "https://cloud.example", CloudTokenFile: "token", Image: "c8s-pod@2026.10.26-1", ImageManifestFile: "manifest.json", LaunchKeyFile: "launch.key", CDSAddress: "cds.example.test:8443", CDSImagePolicyFile: "cds.json", WorkloadsFile: "workloads.json", ClusterID: "test-cluster", Size: "c1.2x", Location: "eu", VCPUs: 2, MemoryMiB: 8192, ReservedMemoryMiB: 1024, MaxPods: 10, MeshPeers: []string{"203.0.113.2:9443"}}
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
	list        func() ([]instance, error)
	deleted     []string
	listed      []string
	get         func(string) (*instance, error)
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
func (f *fakeCloud) List(_ context.Context, provider string) ([]instance, error) {
	f.listed = append(f.listed, provider)
	if f.list != nil {
		return f.list()
	}
	if f.in == nil {
		return nil, nil
	}
	return []instance{*f.in}, nil
}
func (f *fakeCloud) Get(_ context.Context, id string) (*instance, error) {
	if f.get != nil {
		return f.get(id)
	}
	if f.in == nil || f.in.ID != id {
		return nil, errCloudNotFound
	}
	return f.in, nil
}
func (f *fakeCloud) Delete(_ context.Context, id string) error {
	f.deleteCalls++
	f.deleted = append(f.deleted, id)
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

// fakeGuest stands in for the pod status service of every instance the
// fixture creates: one serving key, no pod status until an assignment is
// accepted, and the provider's durable intent checked before every send.
type fakeGuest struct {
	t                              *testing.T
	r                              *Reconciler
	key                            *ecdsa.PrivateKey
	assigned                       map[string]bool
	prepares, sends                int
	lostResponse, failBeforeCommit bool
	beforeSend                     func()
}

type fakeSession struct {
	guest *fakeGuest
	rec   *record
}

func (g *fakeGuest) verify(_ context.Context, rec *record, _ string) (assignmentSession, error) {
	if g.assigned[rec.Key] {
		return nil, errors.New("generic measurements are not empty")
	}
	return &fakeSession{g, rec}, nil
}
func (s *fakeSession) ServingKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(&s.guest.key.PublicKey)
	if err != nil {
		s.guest.t.Fatal(err)
	}
	return b
}
func (s *fakeSession) Prepare(_ context.Context, key *ecdsa.PrivateKey, manifest, entries, peers, clientDocument []byte) ([]byte, error) {
	s.guest.prepares++
	nonce := make([]byte, podassign.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req, err := podassign.Sign(key, &s.guest.key.PublicKey, podassign.Request{Nonce: nonce, Manifest: manifest, Entries: entries, MeshPeers: peers, ClientDocument: clientDocument})
	if err != nil {
		return nil, err
	}
	return podassign.Encode(req)
}
func (s *fakeSession) Send(ctx context.Context, body []byte) (string, error) {
	g := s.guest
	stored, _, err := g.r.loadRecord(ctx, s.rec.Key)
	if err != nil {
		g.t.Fatal(err)
	}
	if !bytes.Equal(stored.Assignment, body) || !bytes.Equal(stored.ServingKey, s.ServingKey()) {
		g.t.Fatal("assignment POST preceded exact durable intent")
	}
	g.sends++
	if g.beforeSend != nil {
		g.beforeSend()
	}
	if g.failBeforeCommit {
		return "", errors.New("POST outcome lost before commit")
	}
	if g.assigned[stored.Key] {
		return "", &podstatus.AlreadyAssignedError{HeldUID: string(stored.UID)}
	}
	g.assigned[stored.Key] = true
	if g.lostResponse {
		g.lostResponse = false
		return "", errors.New("committed assignment response lost")
	}
	return string(stored.UID), nil
}
func (*fakeSession) Close() {}
func (g *fakeGuest) read(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
	if !g.assigned[rec.Key] {
		return podstatus.PodProjection{}, errors.New("guest waiting for assignment")
	}
	return fixtureProjection(rec), nil
}

func fixture(t *testing.T, pod *corev1.Pod) (*Reconciler, *fakeCloud, *fakeGuest) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1.Pod{}).WithObjects(pod).Build()
	f := &fakeCloud{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guest := &fakeGuest{t: t, key: key, assigned: map[string]bool{}}
	r := &Reconciler{client: c, cfg: fixtureConfig(t), cloud: f, now: time.Now, guest: guest.read, assignment: guest.verify}
	guest.r = r
	return r, f, guest
}

func fixtureReconciler(t *testing.T, pod *corev1.Pod) (*Reconciler, *fakeCloud) {
	t.Helper()
	r, cloud, _ := fixture(t, pod)
	return r, cloud
}

// restartReconciler is a provider restart: the same durable state and
// configuration, nothing carried in memory.
func restartReconciler(r *Reconciler, guest *fakeGuest) *Reconciler {
	next := &Reconciler{client: r.client, cfg: r.cfg, cloud: r.cloud, guest: r.guest, assignment: r.assignment, now: r.now, ownsNode: r.ownsNode}
	guest.r = next
	return next
}

func reconcile(t *testing.T, r *Reconciler, pod *corev1.Pod) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	return err
}

// runToRunning reconciles until the pod reports verified running status: the
// record, the instance, the assignment and then the status each take a pass.
func runToRunning(t *testing.T, r *Reconciler, pod *corev1.Pod) {
	t.Helper()
	for range 8 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		if getPod(t, r, pod).Status.Phase == corev1.PodRunning {
			return
		}
	}
	t.Fatal("Pod never reached verified running status")
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
	r, cloud, guest := fixture(t, pod)
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
		// The document is generic: the pod, the entries and the peers are
		// frozen in the record for the assignment, and the instance opens the
		// pod's application ports from the start.
		doc, err := podlaunch.Parse(req.Trust.InitData.Document)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Role != podlaunch.Pod || doc.Node.Name != key || doc.CDS != r.cfg.cds {
			t.Fatal("launch document is not the generic document of this pod CVM")
		}
		if rec.Entries != r.cfg.workloads || !reflect.DeepEqual(rec.MeshPeers, r.cfg.MeshPeers) || len(req.Network.Ingress) != 2 || req.Network.Ingress[1].Name != "app-8080" {
			t.Fatal("record did not freeze the assignment inputs or the pod's ingress")
		}
		frozenPod, err := podlaunch.ParsePodManifest(rec.Pod)
		if err != nil {
			t.Fatal(err)
		}
		if frozenPod.Spec.ServiceAccountName != "" || frozenPod.Spec.NodeName != "" || frozenPod.Annotations[Annotation] != "" {
			t.Fatal("guest sanitization differs")
		}
		if frozenPod.Spec.Containers[0].Env[0].Value != "app" || frozenPod.Spec.Containers[0].Env[1].Value != "one" {
			t.Fatal("external metadata was not frozen")
		}
		cloud.in = instanceFor(req)
		return nil, errors.New("response lost after committed create")
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if getPod(t, r, pod).Status.Reason != "CloudUnavailable" {
		t.Fatal("lost create response was not retained as unavailable")
	}
	// An operator restart/config image upgrade must recover the old signed
	// request and UID assignment, never produce a second randomized document.
	next := *r.cfg
	next.Image = "c8s-pod@2026.11.01-1"
	next.CDSAddress = "replacement-cds.example.test:9443"
	next.cds.Address = next.CDSAddress
	restarted := restartReconciler(r, guest)
	restarted.cfg = &next
	runToRunning(t, restarted, pod)
	got := getPod(t, r, pod)
	if got.Status.PodIP != "" || got.Annotations[endpointsAnnotation] == "" {
		t.Fatalf("incorrect running projection: %+v", got.Status)
	}
	if len(got.Status.InitContainerStatuses) != 0 || got.Status.ContainerStatuses[0].Image != pod.Spec.Containers[0].Image {
		t.Fatal("guest-only container leaked or image was not pinned")
	}
	if cloud.createCalls != 1 || guest.prepares != 1 || guest.sends != 1 || !bytes.Equal(getRecord(t, r, pod).Request.Trust.InitData.Document, frozen) {
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
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
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
	for _, failure := range []string{"attestation", "foreign-uid"} {
		t.Run(failure, func(t *testing.T) {
			pod := fixturePod()
			r, _ := fixtureReconciler(t, pod)
			runToRunning(t, r, pod)
			r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
				p := fixtureProjection(rec)
				switch failure {
				case "attestation":
					return p, errors.New("attestation failed")
				case "foreign-uid":
					p.Metadata.UID = "foreign"
				}
				return p, nil
			}
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
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

// A rotated Cloud credential and an old uncertain create both still drain:
// records key on provider ID and pod UID, and the create is replayed under
// its idempotency key however long ago the response was lost.
func TestRotatedCredentialAndOldUncertainIntentStillDrain(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.create = func(string, createRequest) (*instance, error) { return nil, errors.New("timeout") }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	r.cfg.token = "rotated-token"
	if _, _, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID))); err != nil {
		t.Fatalf("rotated credential stranded the record: %v", err)
	}
	r.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	var first createRequest
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		first = req
		cloud.in = instanceFor(req)
		return cloud.in, nil
	}
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.createCalls != 2 || cloud.deleteCalls != 1 || !reflect.DeepEqual(first, getRecord(t, r, pod).Request) {
		t.Fatal("old uncertain create was not replayed unchanged and destroyed")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Pod finalizer not released: %v", err)
	}
}

func TestProviderRejectsUnlaunchableWorkloadsBeforeCloud(t *testing.T) {
	for _, kind := range []string{"huge-memory", "cpu-total", "tag", "service-account", "secret-env", "provider-fieldref"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			switch kind {
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
			if _, _, _, err := r.cfg.launch(pod); err == nil {
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
	address, apps, ip, err := endpoints(rec.Request.Network, in)
	if err != nil || address != "203.0.113.5:8443" || len(apps) != 1 || ip != "203.0.113.5" {
		t.Fatalf("dedicated projection: %s %v %s %v", address, apps, ip, err)
	}
	in.Endpoints[1].Port++
	if _, _, _, err := endpoints(rec.Request.Network, in); err == nil {
		t.Fatal("translated dedicated app port accepted")
	}
	in = instanceFor(rec.Request)
	in.Compute.MemoryGiB = 1
	if err := validateInstance(&rec.instanceIntent, in); err == nil {
		t.Fatal("undersized Cloud instance accepted")
	}
}

// The cloud chooses a shared-mode public port. One on a mesh control port is
// unreachable through a peer's endpoint, which refuses those ports, so the
// provider publishes no such endpoint and the pod keeps no verified status.
func TestEndpointsRefuseAPublicPortOnAMeshControlPort(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{int(workloadclaims.MeshOutboundPort), int(workloadclaims.MeshInboundPort), int(workloadclaims.MeshHealthPort)} {
		in := instanceFor(rec.Request)
		in.Endpoints[1].Port = port
		if _, _, _, err := endpoints(rec.Request.Network, in); err == nil {
			t.Fatalf("public endpoint on mesh control port %d accepted", port)
		}
	}
	if _, apps, _, err := endpoints(rec.Request.Network, instanceFor(rec.Request)); err != nil || len(apps) != 1 {
		t.Fatalf("ordinary public endpoint refused: %v %v", apps, err)
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

// A pod whose opt-in was removed past admission still owns an instance.
// Deletion must destroy it and release the finalizer rather than leave the
// pod failed, held and its instance running.
func TestDeletionOfALaunchedPodWithoutOptInDestroysItsInstance(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.createCalls != 1 {
		t.Fatal("pod was not launched")
	}
	launched := getPod(t, r, pod)
	delete(launched.Annotations, Annotation)
	if err := r.client.Update(context.Background(), launched); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatal("deletion of a launched pod without the opt-in left its instance")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Pod finalizer not released: %v", err)
	}
}

// Removing the opt-in from a launched pod stops and destroys its instance
// rather than leaving it running unverified with its endpoints published.
func TestRemovedOptInStopsTheLaunchedInstance(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	launched := getPod(t, r, pod)
	delete(launched.Annotations, Annotation)
	if err := r.client.Update(context.Background(), launched); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	got := getPod(t, r, pod)
	if cloud.deleteCalls != 1 || getRecord(t, r, pod).TerminalStatus == nil || got.Status.Phase != corev1.PodFailed || got.Status.Reason != optInRequiredReason {
		t.Fatalf("de-opted pod left running: deletes=%d status=%s/%s", cloud.deleteCalls, got.Status.Phase, got.Status.Reason)
	}
	if got.Annotations[endpointsAnnotation] != "" || !controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatal("endpoints stayed published or cleanup authority was released early")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if !getRecord(t, r, pod).Deleted || cloud.createCalls != 1 {
		t.Fatal("instance not confirmed destroyed, or relaunched")
	}
}

// A deleted pod ends with a terminal phase before its finalizer goes, so a
// controller waiting for the pod to fail sees it fail. Another finalizer
// keeps the pod readable after the provider's own is released.
func TestDeletedPodLeavesWithATerminalPhase(t *testing.T) {
	for _, outcome := range []string{"running", "stopped"} {
		t.Run(outcome, func(t *testing.T) {
			pod := fixturePod()
			pod.Finalizers = []string{"example.invalid/hold"}
			r, cloud := fixtureReconciler(t, pod)
			runToRunning(t, r, pod)
			want := instanceDestroyedReason
			if outcome == "stopped" {
				cloud.in.Status = "failed"
				if err := reconcile(t, r, pod); err != nil {
					t.Fatal(err)
				}
				want = "InstanceEnded"
			}
			if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
				t.Fatal(err)
			}
			cloud.in.Status = "terminated"
			for range 2 {
				if err := reconcile(t, r, pod); err != nil {
					t.Fatal(err)
				}
			}
			got := getPod(t, r, pod)
			if controllerutil.ContainsFinalizer(got, finalizer) {
				t.Fatal("finalizer not released")
			}
			if got.Status.Phase != corev1.PodFailed || got.Status.Reason != want {
				t.Fatalf("deleted pod left as %s/%s, want Failed/%s", got.Status.Phase, got.Status.Reason, want)
			}
		})
	}
}

// No kubelet confirms the deletion of a Pod bound to the virtual node, so the
// provider removes the object with a zero grace period once its instance is
// gone. The fake client deletes on finalizer release, which hides this.
func TestDeletionRemovesThePodWithZeroGrace(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	var deleted *client.DeleteOptions
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				deleted = &client.DeleteOptions{}
				deleted.ApplyOptions(opts)
			}
			return c.Delete(ctx, obj, opts...)
		},
	})
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if deleted.GracePeriodSeconds != nil {
		t.Fatal("provider ended the Pod before its instance was gone")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if deleted.GracePeriodSeconds == nil || *deleted.GracePeriodSeconds != 0 {
		t.Fatalf("Pod deleted with grace %v, want 0", deleted.GracePeriodSeconds)
	}
	if deleted.Preconditions == nil || deleted.Preconditions.UID == nil || *deleted.Preconditions.UID != pod.UID {
		t.Fatal("Pod deletion is not guarded by its UID")
	}
}
