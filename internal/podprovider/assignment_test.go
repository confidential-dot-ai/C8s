package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func runToAssignmentAttempt(t *testing.T, r *Reconciler, pod *corev1.Pod, guest *fakeGuest) {
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

// A lost create response and a lost assignment response, each across a
// provider restart, leave one instance, one signed assignment and one send.
func TestLostCreateAndAssignmentResponsesKeepOneInstance(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in, cloud.create = instanceFor(req), nil
		return nil, errors.New("committed create response lost")
	}
	guest.lostResponse = true
	for range 8 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		r = restartReconciler(r, guest)
		if getPod(t, r, pod).Status.Phase == corev1.PodRunning {
			break
		}
	}
	rec := getRecord(t, r, pod)
	if getPod(t, r, pod).Status.Phase != corev1.PodRunning || cloud.createCalls != 1 || guest.prepares != 1 || guest.sends != 1 || len(rec.Assignment) == 0 || len(rec.ServingKey) == 0 {
		t.Fatal("lost responses duplicated or lost the permanent assignment")
	}
}

// An assignment whose outcome is unknown is never signed again: a guest that
// presents another serving key is refused, and the pod stops at its deadline.
func TestAmbiguousAssignmentNeverResignsAnotherServingKey(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	guest.failBeforeCommit = true
	runToAssignmentAttempt(t, r, pod, guest)
	rec := getRecord(t, r, pod)
	frozen := slices.Clone(rec.Assignment)
	var err error
	guest.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r = restartReconciler(r, guest)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current := getRecord(t, r, pod)
	if !bytes.Equal(frozen, current.Assignment) || guest.prepares != 1 || guest.sends != 1 || cloud.createCalls != 1 {
		t.Fatal("ambiguous assignment was re-signed or sent to another serving key")
	}
	now := *rec.VerificationDeadline
	r.now = func() time.Time { return now }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if getPod(t, r, pod).Status.Reason != verificationTimeoutReason || cloud.deleteCalls != 1 {
		t.Fatal("uncertain guest did not fail and clean up at its frozen deadline")
	}
}

type refusalSession struct {
	assignmentSession
	prepare func(context.Context, *ecdsa.PrivateKey, []byte, []byte, []byte, []byte) ([]byte, error)
	send    func(context.Context, []byte) (string, error)
}

func (s refusalSession) Prepare(ctx context.Context, key *ecdsa.PrivateKey, m, e, p, d []byte) ([]byte, error) {
	if s.prepare != nil {
		return s.prepare(ctx, key, m, e, p, d)
	}
	return s.assignmentSession.Prepare(ctx, key, m, e, p, d)
}
func (s refusalSession) Send(ctx context.Context, b []byte) (string, error) {
	if s.send != nil {
		return s.send(ctx, b)
	}
	return s.assignmentSession.Send(ctx, b)
}

// Every refusal before the send leaves no assignment bytes in the record and
// nothing reaches the guest; a 409 counts as accepted only when it names the
// pod.
func TestAssignmentRefusalsNeverPublishUnauthorizedBytes(t *testing.T) {
	for _, phase := range []string{"rotated-launch-key", "unverified", "canceled-verification", "expired-verification", "nonce-unavailable", "canceled-preparation", "intent-write-failed", "different-ack", "already-assigned", "held-by-another-pod"} {
		t.Run(phase, func(t *testing.T) {
			pod := fixturePod()
			r, _, guest := fixture(t, pod)
			rec, secret, err := r.ensureRecord(t.Context(), pod)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if phase == "rotated-launch-key" {
				r.cfg.pub = "new provider key"
			}
			r.assignment = func(ctx context.Context, rec *record, address string) (assignmentSession, error) {
				if phase == "unverified" {
					return nil, errors.New("empty evidence unavailable")
				}
				base, err := guest.verify(ctx, rec, address)
				if err != nil {
					return nil, err
				}
				if phase == "canceled-verification" {
					cancel()
				}
				if phase == "expired-verification" {
					r.now = func() time.Time { return *rec.VerificationDeadline }
				}
				session := refusalSession{assignmentSession: base}
				session.prepare = func(ctx context.Context, key *ecdsa.PrivateKey, m, e, peers, d []byte) ([]byte, error) {
					if phase == "nonce-unavailable" {
						return nil, errors.New("nonce exhaustion")
					}
					b, err := base.Prepare(ctx, key, m, e, peers, d)
					if err != nil {
						return nil, err
					}
					if phase == "canceled-preparation" {
						cancel()
					}
					return b, nil
				}
				switch phase {
				case "different-ack", "already-assigned", "held-by-another-pod":
					session.send = func(ctx context.Context, b []byte) (string, error) {
						if _, err := base.Send(ctx, b); err != nil {
							return "", err
						}
						switch phase {
						case "already-assigned":
							return "", podstatus.ErrAlreadyAssigned
						case "held-by-another-pod":
							return "", &podstatus.AlreadyAssignedError{HeldUID: "another-pod"}
						}
						return "another-pod", nil
					}
				}
				return session, nil
			}
			if phase == "intent-write-failed" {
				watching := r.client.(client.WithWatch)
				r.client = interceptor.NewClient(watching, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if s, ok := obj.(*corev1.Secret); ok && s.Name == secret.Name {
						return errors.New("assignment intent write unavailable")
					}
					return c.Update(ctx, obj, opts...)
				}})
			}
			err = r.assign(ctx, rec, secret, "unused.invalid")
			if (err == nil) != (phase == "already-assigned") {
				t.Fatalf("assignment refusal outcome: %v", err)
			}
			stored, _, loadErr := r.loadRecord(t.Context(), secret.Name)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			acknowledged := phase == "different-ack" || phase == "already-assigned" || phase == "held-by-another-pod"
			expectedSends := 0
			if acknowledged {
				expectedSends = 1
			}
			if (len(stored.Assignment) > 0) != acknowledged || guest.sends != expectedSends {
				t.Fatal("unverified or unpublished assignment reached the guest")
			}
		})
	}
}

// Matching guest status is not enough. A record without a saved assignment
// has no serving key to read status from, so a guest that already runs the
// pod is never read and never adopted, and the pod fails at its deadline.
func TestStatusCannotInventAnUnpublishedAssignment(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	now := time.Now()
	r.now = func() time.Time { return now }
	runToRunning(t, r, pod)
	rec, secret, err := r.loadRecord(t.Context(), identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil {
		t.Fatal(err)
	}
	rec.Assignment, rec.ServingKey = nil, nil
	if err := r.save(t.Context(), rec, secret); err != nil {
		t.Fatal(err)
	}
	reads := guest.reads
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current := getPod(t, r, pod)
	if current.Status.Reason != "AttestationUnavailable" || cloud.deleteCalls != 0 || guest.sends != 1 || guest.prepares != 1 || guest.reads != reads {
		t.Fatalf("reason %s deletes %d sends %d prepares %d reads %d: matching guest status invented missing assignment authority",
			current.Status.Reason, cloud.deleteCalls, guest.sends, guest.prepares, guest.reads-reads)
	}
	now = *getRecord(t, r, pod).VerificationDeadline
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current = getPod(t, r, pod)
	if current.Status.Phase != corev1.PodFailed || current.Status.Reason != verificationTimeoutReason || cloud.deleteCalls != 1 || guest.reads != reads {
		t.Fatalf("phase %s reason %s deletes %d", current.Status.Phase, current.Status.Reason, cloud.deleteCalls)
	}
}

func TestGuestStatusNeedsTheSavedServingKey(t *testing.T) {
	r := &Reconciler{guest: func(context.Context, *record, string) (podstatus.PodProjection, error) {
		t.Error("a guest was read without a saved serving key")
		return podstatus.PodProjection{}, nil
	}}
	if _, err := r.guestStatus(t.Context(), &record{}, "192.0.2.1"); !errors.Is(err, errNoServingKey) {
		t.Fatalf("got %v", err)
	}
}

// The production verifier refuses a guest without evidence or with invalid
// frozen trust, and leaves no trust material behind.
func TestProductionVerifierRefusesUntrustedEvidenceAndRemovesTrustFiles(t *testing.T) {
	pod := fixturePod()
	r, _, _ := fixture(t, pod)
	rec, _, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	r.assignment = nil
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no evidence", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	originalManifest := bytes.Clone(rec.Manifest)
	for _, corrupt := range []bool{false, true} {
		if corrupt {
			rec.Manifest = []byte("invalid manifest")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		target, err := r.assignmentTarget(ctx, rec, strings.TrimPrefix(srv.URL, "https://"))
		cancel()
		if err == nil || target != nil {
			t.Fatal("production verifier accepted absent evidence or invalid frozen trust")
		}
		files, err := os.ReadDir(temp)
		if err != nil || len(files) != 0 {
			t.Fatal("failed attestation leaked temporary launch trust files")
		}
	}
	rec.Manifest = originalManifest
	// An unusable temporary directory must fail before any outbound request.
	blocked := filepath.Join(temp, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blocked)
	if target, err := r.assignmentTarget(t.Context(), rec, "unused.invalid"); err == nil || target != nil {
		t.Fatal("unavailable private trust storage was ignored")
	}
}

// Every record counts against the pod budget until its instance is confirmed
// destroyed; a pod over the budget gets no record and no instance.
func TestRecordBudgetCountsEveryHeldRecord(t *testing.T) {
	pod := fixturePod()
	r, cloud, _ := fixture(t, pod)
	r.cfg.MaxPods = 1
	other := fixturePod()
	other.Name, other.UID = "other", "22222222-2222-2222-2222-222222222222"
	if err := r.client.Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	runToRunning(t, r, pod)
	if err := reconcile(t, r, other); err == nil {
		t.Fatal("record over the pod budget was written")
	}
	if got := getPod(t, r, other); got.Status.Reason != "CapacityLimit" || cloud.createCalls != 1 {
		t.Fatalf("pod over the budget was not refused: %s %d", got.Status.Reason, cloud.createCalls)
	}
	if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	// Deletion requested but not confirmed: the record still holds the budget.
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, other); err == nil || cloud.createCalls != 1 {
		t.Fatal("an unconfirmed destruction released the pod budget")
	}
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	// The fake cloud knows one instance; the destroyed one is forgotten.
	cloud.in = nil
	runToRunning(t, r, other)
	if cloud.createCalls != 2 {
		t.Fatal("released budget did not admit the waiting pod")
	}
}

// A record of another version is unreadable: it is neither resolved in the
// cloud nor treated as absent, so its pod stays held.
func TestUnreadableRecordVersionHoldsThePod(t *testing.T) {
	pod := fixturePod()
	r, cloud, _ := fixture(t, pod)
	rec, secret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	rec.Version = 2
	if secret.Data["state.json"], err = json.Marshal(rec); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Update(t.Context(), secret); err != nil {
		t.Fatal(err)
	}
	current := getPod(t, r, pod)
	current.Finalizers = []string{finalizer}
	if err := r.client.Update(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("record of another version was accepted")
	}
	if got := getPod(t, r, pod); got.Status.Reason != "ProviderStateUnavailable" || cloud.createCalls != 0 {
		t.Fatalf("unreadable record was resolved or misreported: %s %d", got.Status.Reason, cloud.createCalls)
	}
	if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("deletion treated an unreadable record as absent")
	}
	if !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) || cloud.deleteCalls != 0 {
		t.Fatal("unreadable record released the pod or reached the cloud")
	}
}

// The client document is frozen with the pod, leaves the guest manifest, and
// rides as the signed assignment's own member.
func TestAssignmentCarriesTheFrozenClientDocument(t *testing.T) {
	pod := fixturePod()
	pod.Annotations[workloadclaims.AnnotationClientDocument] = base64.StdEncoding.EncodeToString([]byte("client document"))
	r, _, guest := fixture(t, pod)
	runToAssignmentAttempt(t, r, pod, guest)
	rec := getRecord(t, r, pod)
	if string(rec.ClientDocument) != "client document" {
		t.Fatalf("record froze client document %q", rec.ClientDocument)
	}
	req, err := podassign.Decode(rec.Assignment)
	if err != nil {
		t.Fatal(err)
	}
	if string(req.ClientDocument) != "client document" || bytes.Contains(req.Manifest, []byte(workloadclaims.AnnotationClientDocument)) {
		t.Fatalf("assignment carried document %q and manifest %s", req.ClientDocument, req.Manifest)
	}
	if err := podassign.Verify(&r.cfg.key.PublicKey, &guest.key.PublicKey, req); err != nil {
		t.Fatalf("signature does not cover the client document: %v", err)
	}
}

// The pod read at the start of a reconciliation may be gone or changed by the
// time the guest is verified. Nothing is signed or sent for a pod that is
// being deleted, was edited, or no longer passes the pod rules.
func TestAssignmentRereadsTheLivePodBeforeSigningAndSending(t *testing.T) {
	deletePod := func(t *testing.T, r *Reconciler, pod *corev1.Pod) {
		if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
			t.Fatal(err)
		}
	}
	editSpec := func(t *testing.T, r *Reconciler, pod *corev1.Pod) {
		live := getPod(t, r, pod)
		live.Spec.Containers[0].Args = append(live.Spec.Containers[0].Args, "--changed")
		if err := r.client.Update(t.Context(), live); err != nil {
			t.Fatal(err)
		}
	}
	// An annotation is outside the frozen specification; only the pod rules
	// judge it.
	spoilAnnotation := func(t *testing.T, r *Reconciler, pod *corev1.Pod) {
		live := getPod(t, r, pod)
		live.Annotations[workloadclaims.AnnotationClientDocument] = "not base64!"
		if err := r.client.Update(t.Context(), live); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name          string
		change        func(*testing.T, *Reconciler, *corev1.Pod)
		beforeSigning bool
	}{
		{"deleted before signing", deletePod, true},
		{"edited before signing", editSpec, true},
		{"pod rules broken before signing", spoilAnnotation, true},
		{"deleted before sending", deletePod, false},
		{"edited before sending", editSpec, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := fixturePod()
			r, _, guest := fixture(t, pod)
			changed := false
			hook := func() {
				if !changed {
					changed = true
					tc.change(t, r, pod)
				}
			}
			if tc.beforeSigning {
				guest.onVerify = hook
			} else {
				guest.afterPrepare = hook
			}
			// The pass in which the pod changes may end in a write conflict;
			// what matters is what reached the guest during it.
			for range 8 {
				err := reconcile(t, r, pod)
				if changed {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if !changed {
				t.Fatal("the provider never reached the guest")
			}
			// A change before signing leaves nothing prepared or saved; one
			// after it leaves the saved assignment unsent.
			saved, wantPrepares := len(getRecord(t, r, pod).Assignment) != 0, 1
			if tc.beforeSigning {
				wantPrepares = 0
			}
			if guest.prepares != wantPrepares || guest.sends != 0 || saved == tc.beforeSigning {
				t.Fatalf("prepares %d sends %d saved assignment %t", guest.prepares, guest.sends, saved)
			}
		})
	}
}

// A saved assignment is not replayed to a pod that is being deleted.
func TestReplayRereadsTheLivePod(t *testing.T) {
	pod := fixturePod()
	r, _, guest := fixture(t, pod)
	guest.failBeforeCommit = true
	runToAssignmentAttempt(t, r, pod, guest)
	guest.failBeforeCommit = false
	guest.onVerify = func() {
		if live := getPod(t, r, pod); live.DeletionTimestamp == nil {
			if err := r.client.Delete(t.Context(), live); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = reconcile(t, r, pod) // may end in a write conflict with the deletion
	if guest.sends != 1 || guest.prepares != 1 {
		t.Fatalf("sends %d prepares %d: the assignment was replayed for a pod being deleted", guest.sends, guest.prepares)
	}
}
