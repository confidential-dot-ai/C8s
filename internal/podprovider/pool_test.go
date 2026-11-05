package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

type poolCloud struct {
	mu                             sync.Mutex
	byKey                          map[string]*instance
	requests                       map[string]createRequest
	creates, deletes, ingressCalls int
	loseCreate, holdDeletion       bool
	ingressPending                 bool
	beforeCreate                   func(string, createRequest)
}

func copyPoolInstance(in *instance) *instance {
	if in == nil {
		return nil
	}
	out := *in
	out.Labels = maps.Clone(in.Labels)
	out.Endpoints = slices.Clone(in.Endpoints)
	out.Network.Ingress = slices.Clone(in.Network.Ingress)
	return &out
}
func (f *poolCloud) Create(_ context.Context, key string, req createRequest) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.beforeCreate != nil {
		f.beforeCreate(key, req)
	}
	if found := f.byKey[key]; found != nil {
		return copyPoolInstance(found), nil
	}
	in := instanceFor(req)
	in.ID = fmt.Sprintf("i-pool-%d", len(f.byKey)+1)
	in.Network.Ingress = slices.Clone(req.Network.Ingress)
	f.byKey[key], f.requests[key] = in, req
	if f.loseCreate {
		f.loseCreate = false
		return nil, errors.New("committed create response lost")
	}
	return copyPoolInstance(in), nil
}
func (f *poolCloud) Find(_ context.Context, key string) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return copyPoolInstance(f.byKey[key]), nil
}
func (f *poolCloud) Get(_ context.Context, id string) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, in := range f.byKey {
		if in.ID == id {
			return copyPoolInstance(in), nil
		}
	}
	return nil, errCloudNotFound
}
func (f *poolCloud) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	for _, in := range f.byKey {
		if in.ID == id {
			in.Status = "terminating"
			if !f.holdDeletion {
				in.Status = "terminated"
			}
			return nil
		}
	}
	return errCloudNotFound
}
func (*poolCloud) Ping(context.Context) error { return nil }
func (f *poolCloud) AddIngress(_ context.Context, id, key string, rule ingress) (*instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for launchKey, in := range f.byKey {
		if in.ID != id {
			continue
		}
		if key != identityKey(launchKey, "ingress-"+rule.Name) {
			return nil, errors.New("unstable ingress key")
		}
		for _, old := range in.Network.Ingress {
			if old.Name == rule.Name {
				if old != rule {
					return nil, errors.New("conflicting rule")
				}
				return copyPoolInstance(in), nil
			}
		}
		f.ingressCalls++
		in.Network.Ingress = append(in.Network.Ingress, rule)
		port := 30000 + len(in.Network.Ingress)
		if f.requests[launchKey].Network.PublicIP == "dedicated" {
			port = rule.Port
		}
		in.Endpoints = append(in.Endpoints, endpoint{Name: rule.Name, Host: "203.0.113.5", Port: port})
		in.Network.IngressUpdating = f.ingressPending
		return copyPoolInstance(in), nil
	}
	return nil, errCloudNotFound
}

type poolGuest struct {
	t                                         *testing.T
	r                                         *Reconciler
	key                                       *ecdsa.PrivateKey
	assigned                                  map[string]bool
	prepares, sends                           int
	lostResponse, failBeforeCommit, failReads bool
	beforeSend                                func()
	beforePrepare                             func()
}
type poolSession struct {
	guest *poolGuest
	pool  *poolRecord
}

func (g *poolGuest) verify(_ context.Context, p *poolRecord, _ string) (assignmentSession, error) {
	if g.assigned[p.Key] {
		return nil, errors.New("generic measurements are not empty")
	}
	return &poolSession{g, p}, nil
}
func (s *poolSession) ServingKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(&s.guest.key.PublicKey)
	if err != nil {
		s.guest.t.Fatal(err)
	}
	return b
}
func (s *poolSession) Prepare(_ context.Context, key *ecdsa.PrivateKey, manifest, entries, peers []byte) ([]byte, error) {
	s.guest.prepares++
	if s.guest.beforePrepare != nil {
		s.guest.beforePrepare()
	}
	nonce := make([]byte, podassign.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req, err := podassign.Sign(key, &s.guest.key.PublicKey, podassign.Request{Nonce: nonce, Manifest: manifest, Entries: entries, MeshPeers: peers})
	if err != nil {
		return nil, err
	}
	return podassign.Encode(req)
}
func (s *poolSession) Send(ctx context.Context, body []byte) (string, error) {
	g := s.guest
	stored, secret, err := g.r.loadPool(ctx, slotName(g.r.cfg.ProviderID, s.pool.Slot))
	if err != nil {
		g.t.Fatal(err)
	}
	if !bytes.Equal(stored.Assignment, body) || !bytes.Equal(stored.ServingKey, s.ServingKey()) {
		g.t.Fatal("assignment POST preceded exact durable intent")
	}
	rec, podSecret, err := g.r.poolPod(ctx, stored, secret)
	if err != nil || rec == nil || podSecret.UID != stored.Claim.RecordUID {
		g.t.Fatal("assignment POST has no reciprocal claim")
	}
	g.sends++
	if g.beforeSend != nil {
		g.beforeSend()
	}
	if g.failBeforeCommit {
		return "", errors.New("POST outcome lost before commit")
	}
	if g.assigned[stored.Key] {
		return "", podstatus.ErrAlreadyAssigned
	}
	g.assigned[stored.Key] = true
	if g.lostResponse {
		g.lostResponse = false
		return "", errors.New("committed assignment response lost")
	}
	return string(rec.UID), nil
}
func (*poolSession) Close() {}
func (g *poolGuest) read(ctx context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
	if g.failReads || rec.Pool == nil {
		return podstatus.PodProjection{}, errors.New("no verified Pod")
	}
	p, _, err := g.r.loadPool(ctx, rec.Pool.Name)
	if err != nil || !g.assigned[p.Key] {
		return podstatus.PodProjection{}, errors.New("guest waiting for assignment")
	}
	projection := fixtureProjection(rec)
	projection.Metadata.Name = rec.Name + "-" + p.Key
	return projection, nil
}

func poolFixture(t *testing.T) (*Reconciler, *poolCloud, *poolGuest, *corev1.Pod) {
	t.Helper()
	pod := fixturePod()
	pod.Spec.Containers[0].Ports = append(pod.Spec.Containers[0].Ports, corev1.ContainerPort{Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP})
	r, _ := fixtureReconciler(t, pod)
	r.cfg.WarmTarget, r.cfg.MaxPods = 1, 2
	watching, ok := r.client.(client.WithWatch)
	if !ok {
		t.Fatal("fixture client has no watch")
	}
	var ids atomic.Uint64
	r.client = interceptor.NewClient(watching, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*corev1.Secret); ok && obj.GetUID() == "" {
			obj.SetUID(types.UID(fmt.Sprintf("secret-%d", ids.Add(1))))
		}
		return c.Create(ctx, obj, opts...)
	}})
	cloud := &poolCloud{byKey: map[string]*instance{}, requests: map[string]createRequest{}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guest := &poolGuest{t: t, r: r, key: key, assigned: map[string]bool{}}
	r.cloud, r.guest, r.assignment = cloud, guest.read, guest.verify
	return r, cloud, guest, pod
}

func runToAssigned(t *testing.T, r *Reconciler, pod *corev1.Pod) {
	t.Helper()
	for range 8 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		if getPod(t, r, pod).Status.Phase == corev1.PodRunning {
			return
		}
	}
	t.Fatal("Pod never reached its verified allocated guest")
}

func TestWarmClaimPersistsBeforeIngressAndAssignment(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	cloud.beforeCreate = func(key string, req createRequest) {
		pools, _, err := r.allocations(t.Context())
		if err != nil || len(pools) != 1 || !pools[0].record.CreateAttempted || pools[0].record.Key != key {
			t.Fatal("Cloud create preceded frozen slot intent")
		}
		doc, err := pools[0].record.document()
		if err != nil || doc.Pod != nil || doc.Workloads != "" || len(req.Network.Ingress) != 1 || req.Network.Ingress[0].Name != "pod-status" {
			t.Fatal("idle launch carries workload authority or ports")
		}
	}
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil || len(pools) != 1 || pools[0].record.Claim != nil || pools[0].record.VerificationDeadline != nil {
		t.Fatal("pool did not verify an empty generic guest")
	}
	idleKey := pools[0].record.Key
	guest.beforeSend = func() {
		cloud.mu.Lock()
		defer cloud.mu.Unlock()
		in := cloud.byKey[idleKey]
		if len(in.Network.Ingress) != 3 || in.Network.IngressUpdating {
			t.Fatal("assignment preceded exact applied ingress")
		}
	}
	runToAssigned(t, r, pod)
	rec := getRecord(t, r, pod)
	p, secret, err := r.linkedPool(t.Context(), rec, mustRecordSecret(t, r, rec.Key))
	if err != nil || secret.UID != rec.Pool.UID || p.Key != idleKey || len(p.Request.Network.Ingress) != 1 || rec.Version != 2 {
		t.Fatal("claim lost frozen generic launch or reused desired Pod identity")
	}
	if cloud.creates != 1 || guest.prepares != 1 || guest.sends != 1 || getPod(t, r, pod).Annotations[endpointsAnnotation] == "" {
		t.Fatal("warm guest was not reused exactly once")
	}
}

func mustRecordSecret(t *testing.T, r *Reconciler, key string) *corev1.Secret {
	t.Helper()
	_, secret, err := r.loadRecord(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func restartPoolReconciler(r *Reconciler, g *poolGuest) *Reconciler {
	next := &Reconciler{client: r.client, cfg: r.cfg, cloud: r.cloud, guest: g.read, assignment: g.verify, now: r.now, ownsNode: r.ownsNode}
	g.r = next
	return next
}

func TestWarmLostCreateAndAssignmentResponsesKeepOneVM(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	cloud.loseCreate = true
	guest.lostResponse = true
	for range 8 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		r = restartPoolReconciler(r, guest)
		if getPod(t, r, pod).Status.Phase == corev1.PodRunning {
			break
		}
	}
	if getPod(t, r, pod).Status.Phase != corev1.PodRunning || cloud.creates != 1 || guest.prepares != 1 || guest.sends != 1 || len(cloud.byKey) != 1 {
		t.Fatal("lost responses duplicated or lost the permanent assignment")
	}
}

func TestWarmAmbiguousAssignmentNeverResignsAnotherServingKey(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	guest.failBeforeCommit = true
	runToAssignmentAttempt(t, r, pod, guest)
	rec := getRecord(t, r, pod)
	pool, _, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil {
		t.Fatal(err)
	}
	frozen := slices.Clone(pool.Assignment)
	guest.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r = restartPoolReconciler(r, guest)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current, _, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil || !bytes.Equal(frozen, current.Assignment) || guest.prepares != 1 || guest.sends != 1 || cloud.creates != 1 {
		t.Fatal("ambiguous assignment was re-signed or moved after key rotation")
	}
	now := *rec.VerificationDeadline
	r.now = func() time.Time { return now }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if getPod(t, r, pod).Status.Reason != verificationTimeoutReason || cloud.deletes != 1 {
		t.Fatal("uncertain guest did not fail and clean up at its frozen deadline")
	}
}

func TestWarmRecoversPodAnchorBeforeClaimWithoutDuplicateAllocation(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	rec, podSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	p, secret, err := r.reservePool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rec.Pool = &poolRef{Name: secret.Name, UID: secret.UID}
	if err := r.save(t.Context(), rec, podSecret); err != nil {
		t.Fatal(err)
	}
	r = restartPoolReconciler(r, guest)
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	runToAssigned(t, r, pod)
	linked, _, err := r.linkedPool(t.Context(), getRecord(t, r, pod), mustRecordSecret(t, r, rec.Key))
	if err != nil || linked.Key != p.Key || cloud.creates != 1 || guest.sends != 1 {
		t.Fatal("half-written claim allocated another VM")
	}
}

func TestWarmBudgetRetainsDeletingAndUncertainSlots(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	r.cfg.MaxPods = 1
	cloud.holdDeletion = true
	runToAssigned(t, r, pod)
	rec, secret, err := r.loadRecord(t.Context(), identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil {
		t.Fatal(err)
	}
	done, err := r.removePooledInstance(t.Context(), rec, secret)
	if err != nil || done {
		t.Fatal("deleting allocation was prematurely released")
	}
	if _, _, err := r.reservePool(t.Context()); err == nil {
		t.Fatal("deleting VM did not consume MaxPods")
	}
	r = restartPoolReconciler(r, guest)
	cloud.mu.Lock()
	for _, in := range cloud.byKey {
		in.Status = "terminated"
	}
	cloud.mu.Unlock()
	rec, secret, err = r.loadRecord(t.Context(), rec.Key)
	if err != nil {
		t.Fatal(err)
	}
	done, err = r.removePooledInstance(t.Context(), rec, secret)
	if err != nil || !done {
		t.Fatal("confirmed termination did not complete Pod cleanup")
	}
	r.cfg.WarmTarget = 0
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	p, _, err := r.reservePool(t.Context())
	if err != nil || p.Key == rec.Key {
		t.Fatal("terminated allocation slot was not safely reusable")
	}
}

func TestWarmDefaultsDrainAndLegacyBudget(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	r.cfg.WarmTarget = 0
	rec, _, err := r.ensureRecord(t.Context(), pod)
	if err != nil || rec.Version != 1 {
		t.Fatal("default configuration stopped using static launches")
	}
	r.cfg.WarmTarget, r.cfg.MaxPods = 1, 1
	if _, _, err := r.reservePool(t.Context()); err == nil {
		t.Fatal("legacy intent was omitted from MaxPods")
	}
	r.cfg.MaxPods = 2
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.cfg.WarmTarget = 0
	r.ownsNode = func(context.Context) error { return errors.New("node unavailable") }
	for range 2 {
		if err := r.maintainPools(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil || len(pools) != 0 || cloud.creates != 1 || cloud.deletes == 0 {
		t.Fatal("disabling warm capacity did not drain without replenishment")
	}
}

func TestWarmSlotReplacementNeverRebindsPod(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	rec, podSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	p, secret, err := r.selectPool(t.Context(), rec, podSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.discard(t.Context(), secret); err != nil {
		t.Fatal(err)
	}
	replacement := secret.DeepCopy()
	replacement.ObjectMeta = metav1.ObjectMeta{Name: secret.Name, Namespace: secret.Namespace, Labels: maps.Clone(secret.Labels), UID: "replacement"}
	if err := r.client.Create(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.selectPool(t.Context(), rec, podSecret); err == nil || cloud.creates != 0 {
		t.Fatal("replaced slot was adopted by an old Pod anchor")
	}
	if _, err := r.removePooledInstance(t.Context(), rec, podSecret); err == nil {
		t.Fatal("cleanup followed a replacement slot")
	}
	if p.Claim == nil {
		t.Fatal("fixture did not establish a permanent claim")
	}
}

func TestWarmConcurrentReservationAndClaimsRespectCAS(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	r.cfg.MaxPods = 1
	results := make(chan error, 2)
	for range 2 {
		go func() { _, _, err := r.reservePool(t.Context()); results <- err }()
	}
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil || successes != 1 || len(pools) != 1 || cloud.creates != 0 {
		t.Fatal("concurrent reservations exceeded one allocation slot")
	}
	first, firstSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	other := pod.DeepCopy()
	other.Name = "other"
	other.ResourceVersion = ""
	other.UID = "22222222-2222-2222-2222-222222222222"
	if err := r.client.Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	second, secondSecret, err := r.ensureRecord(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	a, as, err := r.loadPool(t.Context(), pools[0].secret.Name)
	if err != nil {
		t.Fatal(err)
	}
	b, bs, err := r.loadPool(t.Context(), pools[0].secret.Name)
	if err != nil {
		t.Fatal(err)
	}
	go func() { results <- r.claimPool(t.Context(), first, firstSecret, a, as) }()
	go func() { results <- r.claimPool(t.Context(), second, secondSecret, b, bs) }()
	successes = 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	claimed, _, err := r.loadPool(t.Context(), pools[0].secret.Name)
	if err != nil || successes != 1 || claimed.Claim == nil {
		t.Fatal("allocation accepted more than one immutable Pod claim")
	}
	loser, loserSecret := first, firstSecret
	if claimed.Claim.PodUID == first.UID {
		loser, loserSecret = second, secondSecret
	}
	// The losing anchor can be discarded because the explicit foreign claim
	// proves this Pod never acquired authority; it cannot delete the winner.
	if _, _, err := r.selectPool(t.Context(), loser, loserSecret); err == nil {
		t.Fatal("losing claim obtained another VM above MaxPods")
	}
	if _, err := r.removePooledInstance(t.Context(), loser, loserSecret); err != nil {
		t.Fatal(err)
	}
	still, _, err := r.loadPool(t.Context(), pools[0].secret.Name)
	if err != nil || still.Claim.PodUID != claimed.Claim.PodUID || cloud.deletes != 0 {
		t.Fatal("losing claim altered the winner's VM authority")
	}
}

func TestWarmWaitsForAppliedIngressBeforeAssignment(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	cloud.ingressPending = true
	for range 4 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
	}
	if guest.prepares != 0 || guest.sends != 0 || cloud.ingressCalls != 1 {
		t.Fatal("pending ingress allowed assignment or concurrent ingress mutation")
	}
	cloud.mu.Lock()
	cloud.ingressPending = false
	for _, in := range cloud.byKey {
		in.Network.IngressUpdating = false
	}
	cloud.mu.Unlock()
	runToAssigned(t, r, pod)
	if guest.sends != 1 || cloud.ingressCalls != 2 {
		t.Fatal("applied ingress did not unblock the single assignment")
	}
}

func TestWarmCorruptedAssignmentCannotRecoverThroughStatus(t *testing.T) {
	for _, field := range []string{"signature", "serving-key", "manifest"} {
		t.Run(field, func(t *testing.T) {
			r, cloud, guest, pod := poolFixture(t)
			runToAssigned(t, r, pod)
			rec := getRecord(t, r, pod)
			p, secret, err := r.loadPool(t.Context(), rec.Pool.Name)
			if err != nil {
				t.Fatal(err)
			}
			req, err := podassign.Decode(p.Assignment)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "signature":
				req.Signature[0] ^= 1
			case "serving-key":
				p.ServingKey = []byte("different")
			case "manifest":
				req.Manifest = append(req.Manifest, ' ')
			}
			p.Assignment, err = podassign.Encode(req)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.savePool(t.Context(), p, secret); err != nil {
				t.Fatal(err)
			}
			r = restartPoolReconciler(r, guest)
			if _, _, err := r.loadPool(t.Context(), rec.Pool.Name); err == nil {
				t.Fatal("corrupted recovered assignment was accepted")
			}
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if getPod(t, r, pod).Annotations[endpointsAnnotation] != "" || cloud.creates != 1 || guest.prepares != 1 || guest.sends != 1 {
				t.Fatal("status recovery bypassed the stored assignment binding")
			}
		})
	}
}

func TestWarmOrphanCleanupRetainsClaimUntilVMTermination(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	runToAssigned(t, r, pod)
	rec := getRecord(t, r, pod)
	current := getPod(t, r, pod)
	current.Finalizers = nil
	if err := r.client.Update(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Delete(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	r.cfg.WarmTarget = 0
	cloud.holdDeletion = true
	if err := r.sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.loadPool(t.Context(), rec.Pool.Name); err != nil {
		t.Fatal("orphan cleanup lost allocation before termination")
	}
	cloud.mu.Lock()
	for _, in := range cloud.byKey {
		in.Status = "terminated"
	}
	cloud.mu.Unlock()
	if err := r.sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil || len(pools) != 0 || cloud.creates != 1 || cloud.deletes == 0 {
		t.Fatal("orphan cleanup recreated or stranded the allocated VM")
	}
}

func TestWarmConfigurationIsBoundedAndOptIn(t *testing.T) {
	for _, target := range []int64{-1, 0, 1, 10, 11} {
		cfg := fixtureConfig(t)
		cfg.WarmTarget = target
		err := cfg.validate()
		if (err == nil) != (target >= 0 && target <= cfg.MaxPods) {
			t.Fatalf("warmTarget %d: %v", target, err)
		}
	}
}

func TestWarmUncommittedMissingAnchorCanRecoverButStaleWriterCannotClearCommit(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	rec, podSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	_, oldSlot, err := r.reservePool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rec.Pool = &poolRef{Name: oldSlot.Name, UID: oldSlot.UID}
	if err := r.save(t.Context(), rec, podSecret); err != nil {
		t.Fatal(err)
	}
	stale, staleSecret, err := r.loadRecord(t.Context(), rec.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.discard(t.Context(), oldSlot); err != nil {
		t.Fatal(err)
	}
	current, currentSecret, err := r.loadRecord(t.Context(), rec.Key)
	if err != nil {
		t.Fatal(err)
	}
	p, secret, err := r.selectPool(t.Context(), current, currentSecret)
	if err != nil || secret.UID == oldSlot.UID || !current.PoolCommitted || cloud.creates != 0 {
		t.Fatal("unused stale anchor could not recover to a committed replacement")
	}
	if _, _, err := r.selectPool(t.Context(), stale, staleSecret); err == nil {
		t.Fatal("stale false marker cleared a published commitment")
	}
	published := getRecord(t, r, pod)
	if !published.PoolCommitted || published.Pool.UID != secret.UID || published.Pool.Name != secret.Name {
		t.Fatal("stale anchor write changed durable assignment authority")
	}
	if p.Claim == nil {
		t.Fatal("replacement had no reciprocal immutable claim")
	}
}

func TestWarmLostCommitMarkerReplyDoesNotLaunchBeforeReload(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	watching, ok := r.client.(client.WithWatch)
	if !ok {
		t.Fatal("fixture client has no watch")
	}
	lost := false
	r.client = interceptor.NewClient(watching, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		err := c.Update(ctx, obj, opts...)
		if err != nil {
			return err
		}
		if secret, ok := obj.(*corev1.Secret); ok && secret.Labels[slotLabel] != "true" && !lost {
			var rec record
			if err := decode(secret.Data["state.json"], &rec); err != nil {
				t.Fatal(err)
			}
			if rec.PoolCommitted {
				lost = true
				return errors.New("committed marker response lost")
			}
		}
		return nil
	}})
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	rec := getRecord(t, r, pod)
	if !lost || !rec.PoolCommitted || cloud.creates != 0 || guest.sends != 0 {
		t.Fatal("uncertain marker write reached workload side effects")
	}
	r = restartPoolReconciler(r, guest)
	runToAssigned(t, r, pod)
	if cloud.creates != 1 || guest.prepares != 1 || guest.sends != 1 {
		t.Fatal("marker recovery duplicated the permanent allocation")
	}
}

func TestWarmCleanupCanReleaseAnUnusedMissingReservation(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	rec, podSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	_, slot, err := r.reservePool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rec.Pool = &poolRef{Name: slot.Name, UID: slot.UID}
	if err := r.save(t.Context(), rec, podSecret); err != nil {
		t.Fatal(err)
	}
	if err := r.discard(t.Context(), slot); err != nil {
		t.Fatal(err)
	}
	done, err := r.removePooledInstance(t.Context(), rec, podSecret)
	if err != nil || !done || !getRecord(t, r, pod).Deleted || cloud.creates != 0 || cloud.deletes != 0 {
		t.Fatal("unused missing reservation stranded cleanup or touched a foreign VM")
	}
}

func TestWarmLateAssignmentPreparationCannotPost(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	now := time.Now()
	r.now = func() time.Time { return now }
	guest.beforePrepare = func() { now = *getRecord(t, r, pod).VerificationDeadline }
	for range 5 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		if getPod(t, r, pod).Status.Phase == corev1.PodFailed {
			break
		}
	}
	rec := getRecord(t, r, pod)
	p, _, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil || len(p.Assignment) != 0 || guest.prepares != 1 || guest.sends != 0 || cloud.deletes != 1 || getPod(t, r, pod).Status.Reason != verificationTimeoutReason {
		t.Fatal("late preparation posted or survived its persisted verification deadline")
	}
}

func runToAssignmentAttempt(t *testing.T, r *Reconciler, pod *corev1.Pod, guest *poolGuest) {
	t.Helper()
	for range 8 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		if guest.sends > 0 {
			return
		}
	}
	t.Fatal("provider never attempted the frozen assignment")
}

func TestWarmSavedAssignmentSurvivesConfiguredSigningKeyRotation(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	guest.failBeforeCommit = true
	runToAssignmentAttempt(t, r, pod, guest)
	rec := getRecord(t, r, pod)
	p, _, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil {
		t.Fatal(err)
	}
	body := slices.Clone(p.Assignment)
	r.cfg.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&r.cfg.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	guest.failBeforeCommit = false
	r = restartPoolReconciler(r, guest)
	runToAssigned(t, r, pod)
	restored, _, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil || !bytes.Equal(body, restored.Assignment) || restored.Request.Trust.LaunchKey == r.cfg.pub || guest.prepares != 1 || guest.sends != 2 || cloud.creates != 1 {
		t.Fatal("configured key rotation altered or stranded the already signed assignment")
	}
}
