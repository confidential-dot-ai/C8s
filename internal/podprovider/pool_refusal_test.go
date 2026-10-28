package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

func TestWarmCorruptSlotNeverGrantsCloudAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*poolRecord, *corev1.Secret)
	}{
		{"foreign-owner", func(_ *poolRecord, s *corev1.Secret) { s.Labels[ownerLabel] = "foreign" }},
		{"missing-slot-label", func(_ *poolRecord, s *corev1.Secret) { delete(s.Labels, slotLabel) }},
		{"different-account", func(p *poolRecord, _ *corev1.Secret) { p.CredentialHash = "foreign-account" }},
		{"invalid-generation", func(p *poolRecord, _ *corev1.Secret) { p.Key = "podcvm-" + strings.Repeat("z", 40) }},
		{"zero-deadline", func(p *poolRecord, _ *corev1.Secret) { p.VerificationDeadline = new(time.Time) }},
		{"unclaimed-assignment", func(p *poolRecord, _ *corev1.Secret) { p.Assignment = []byte("unexpected") }},
		{"incomplete-assignment", func(p *poolRecord, _ *corev1.Secret) { p.Claim = &poolClaim{}; p.ServingKey = []byte("unpaired") }},
		{"invalid-claim", func(p *poolRecord, _ *corev1.Secret) { p.Claim = &poolClaim{PodUID: "foreign"} }},
		{"tampered-launch-signature", func(p *poolRecord, _ *corev1.Secret) {
			p.Request.Trust.InitData.Document = append(p.Request.Trust.InitData.Document, ' ')
		}},
		{"unexpected-idle-ingress", func(p *poolRecord, _ *corev1.Secret) {
			p.Request.Network.Ingress = append(p.Request.Network.Ingress, ingress{Name: "app", Port: 80})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cloud, guest, _ := poolFixture(t)
			p, slot, err := r.reservePool(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(p, slot)
			if err := r.savePool(t.Context(), p, slot); err != nil {
				t.Fatal(err)
			}
			if _, _, err := r.loadPool(t.Context(), slot.Name); err == nil {
				t.Fatal("corrupt allocation was accepted")
			}
			// Direct recovery must refuse before making any network effect.
			if cloud.creates != 0 || cloud.deletes != 0 || guest.prepares != 0 || guest.sends != 0 {
				t.Fatal("corrupt durable state authorized a Cloud or guest operation")
			}
		})
	}
}

func TestWarmProductionVerifierRefusesUntrustedEvidenceAndRemovesTrustFiles(t *testing.T) {
	r, _, _, _ := poolFixture(t)
	p, _, err := r.reservePool(t.Context())
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
	originalManifest := bytes.Clone(p.Manifest)
	for _, corrupt := range []bool{false, true} {
		if corrupt {
			p.Manifest = []byte("invalid manifest")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		target, err := r.assignmentTarget(ctx, p, strings.TrimPrefix(srv.URL, "https://"))
		cancel()
		if err == nil || target != nil {
			t.Fatal("production verifier accepted absent evidence or invalid frozen trust")
		}
		files, err := os.ReadDir(temp)
		if err != nil || len(files) != 0 {
			t.Fatal("failed attestation leaked temporary launch trust files")
		}
	}
	p.Manifest = originalManifest
	// An unusable temporary directory must fail before any outbound request.
	blocked := filepath.Join(temp, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blocked)
	if target, err := r.assignmentTarget(t.Context(), p, "unused.invalid"); err == nil || target != nil {
		t.Fatal("unavailable private trust storage was ignored")
	}
}

type refusalSession struct {
	assignmentSession
	prepare func(context.Context, *ecdsa.PrivateKey, []byte, []byte, []byte) ([]byte, error)
	send    func(context.Context, []byte) (string, error)
}

func (s refusalSession) Prepare(ctx context.Context, key *ecdsa.PrivateKey, m, e, p []byte) ([]byte, error) {
	if s.prepare != nil {
		return s.prepare(ctx, key, m, e, p)
	}
	return s.assignmentSession.Prepare(ctx, key, m, e, p)
}
func (s refusalSession) Send(ctx context.Context, b []byte) (string, error) {
	if s.send != nil {
		return s.send(ctx, b)
	}
	return s.assignmentSession.Send(ctx, b)
}

func TestWarmAssignmentRefusalsNeverPublishUnauthorizedBytes(t *testing.T) {
	for _, phase := range []string{"rotated-launch-key", "unverified", "canceled-verification", "expired-verification", "nonce-unavailable", "canceled-preparation", "malformed-body", "different-payload", "intent-write-failed", "different-ack", "already-assigned"} {
		t.Run(phase, func(t *testing.T) {
			r, _, guest, pod := poolFixture(t)
			rec, podSecret, err := r.ensureRecord(t.Context(), pod)
			if err != nil {
				t.Fatal(err)
			}
			p, slot, err := r.selectPool(t.Context(), rec, podSecret)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if phase == "rotated-launch-key" {
				r.cfg.pub = "new provider key"
			}
			r.assignment = func(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
				if phase == "unverified" {
					return nil, errors.New("empty evidence unavailable")
				}
				base, err := guest.verify(ctx, p, address)
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
				session.prepare = func(ctx context.Context, key *ecdsa.PrivateKey, m, e, peers []byte) ([]byte, error) {
					if phase == "nonce-unavailable" {
						return nil, errors.New("nonce exhaustion")
					}
					b, err := base.Prepare(ctx, key, m, e, peers)
					if err != nil {
						return nil, err
					}
					if phase == "canceled-preparation" {
						cancel()
					}
					if phase == "malformed-body" {
						return []byte("invalid assignment"), nil
					}
					if phase == "different-payload" {
						req, err := podassign.Decode(b)
						if err != nil {
							return nil, err
						}
						req.Manifest = append(bytes.Clone(m), ' ')
						req, err = podassign.Sign(key, &guest.key.PublicKey, req)
						if err != nil {
							return nil, err
						}
						return podassign.Encode(req)
					}
					return b, nil
				}
				if phase == "different-ack" || phase == "already-assigned" {
					session.send = func(ctx context.Context, b []byte) (string, error) {
						if _, err := base.Send(ctx, b); err != nil {
							return "", err
						}
						if phase == "already-assigned" {
							return "", podstatus.ErrAlreadyAssigned
						}
						return "another-pod", nil
					}
				}
				return session, nil
			}
			if phase == "intent-write-failed" {
				watching := r.client.(client.WithWatch)
				r.client = interceptor.NewClient(watching, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if s, ok := obj.(*corev1.Secret); ok && s.Name == slot.Name {
						return errors.New("assignment intent write unavailable")
					}
					return c.Update(ctx, obj, opts...)
				}})
			}
			err = r.assignPool(ctx, rec, p, slot, "unused.invalid")
			if (err == nil) != (phase == "already-assigned") {
				t.Fatalf("assignment refusal outcome: %v", err)
			}
			stored, _, loadErr := r.loadPool(t.Context(), slot.Name)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			acknowledged := phase == "different-ack" || phase == "already-assigned"
			expectedSends := 0
			if acknowledged {
				expectedSends = 1
			}
			if (len(stored.Assignment) > 0) != acknowledged || guest.sends != expectedSends {
				t.Fatal("unverified or unpublished assignment reached the guest")
			}
			if stored.Claim == nil || stored.Claim.PodUID != pod.UID {
				t.Fatal("assignment refusal lost the permanent claim")
			}
		})
	}
}

func TestWarmUnexpectedIngressBlocksAssignmentAndEndpoints(t *testing.T) {
	for _, mode := range []string{"duplicate", "wrong-port", "extra", "missing-adapter"} {
		t.Run(mode, func(t *testing.T) {
			r, cloud, guest, pod := poolFixture(t)
			runToAssigned(t, r, pod)
			rec := getRecord(t, r, pod)
			p, _, err := r.loadPool(t.Context(), rec.Pool.Name)
			if err != nil {
				t.Fatal(err)
			}
			in := cloud.byKey[p.Key]
			switch mode {
			case "duplicate":
				in.Network.Ingress = append(in.Network.Ingress, in.Network.Ingress[0])
			case "wrong-port":
				in.Network.Ingress[0].Port++
			case "extra":
				in.Network.Ingress = append(in.Network.Ingress, ingress{Name: "unexpected", Port: 9999})
			case "missing-adapter":
				r.cloud = struct{ cloudAPI }{cloud}
			}
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			current := getPod(t, r, pod)
			if current.Status.Reason != "EndpointsPending" || current.Annotations[endpointsAnnotation] != "" || guest.sends != 1 || guest.prepares != 1 || cloud.deletes != 0 {
				t.Fatal("invalid ingress preserved readiness or replayed assignment")
			}
		})
	}
}

func TestWarmMalformedSlotCannotEscapeAllocationBudget(t *testing.T) {
	r, cloud, _, _ := poolFixture(t)
	_, slot, err := r.reservePool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	slot.Data["state.json"] = []byte(`{"version":1,"version":2}`)
	if err := r.client.Update(t.Context(), slot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.reservePool(t.Context()); err == nil {
		t.Fatal("malformed outstanding obligation was skipped by capacity accounting")
	}
	if err := r.maintainPools(t.Context()); err == nil {
		t.Fatal("maintenance ignored malformed allocation")
	}
	if cloud.creates != 0 || cloud.deletes != 0 {
		t.Fatal("malformed allocation authorized Cloud effects")
	}
	// Preserve the corrupt bytes for authoritative repair rather than deleting.
	stored := &corev1.Secret{}
	if err := r.client.Get(t.Context(), client.ObjectKeyFromObject(slot), stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Data["state.json"], slot.Data["state.json"]) {
		t.Fatal("recovery destroyed the retained diagnostic obligation")
	}
}

func TestWarmTerminalProjectionRemainsTerminalDuringCleanup(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	cloud.holdDeletion = true
	runToAssigned(t, r, pod)
	r.guest = func(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
		projection, err := guest.read(ctx, rec, address)
		if err != nil {
			return podstatus.PodProjection{}, err
		}
		if len(projection.Status.ContainerStatuses) != 1 {
			t.Fatal("fixture lost its assigned workload status")
		}
		projection.Status.Phase = corev1.PodSucceeded
		projection.Status.Conditions = nil
		projection.Status.ContainerStatuses[0].Ready = false
		projection.Status.ContainerStatuses[0].State = &podstatus.ContainerState{Terminated: &podstatus.ContainerTerminated{ExitCode: 0}}
		return projection, err
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	rec := getRecord(t, r, pod)
	if rec.TerminalStatus == nil || rec.TerminalStatus.Phase != corev1.PodSucceeded || rec.Deleted || cloud.deletes != 1 {
		t.Fatal("attested completion was not frozen before cleanup")
	}
	r = restartPoolReconciler(r, guest)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current := getPod(t, r, pod)
	if current.Status.Phase != corev1.PodSucceeded || current.Annotations[endpointsAnnotation] != "" || guest.sends != 1 || guest.prepares != 1 || cloud.creates != 1 {
		t.Fatal("late running status revived a completed warm workload")
	}
}

func TestWarmStatusCannotInventAnUnpublishedAssignment(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	runToAssigned(t, r, pod)
	rec := getRecord(t, r, pod)
	p, slot, err := r.loadPool(t.Context(), rec.Pool.Name)
	if err != nil {
		t.Fatal(err)
	}
	p.Assignment, p.ServingKey = nil, nil
	if err := r.savePool(t.Context(), p, slot); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	current := getPod(t, r, pod)
	if current.Status.Phase != corev1.PodFailed || current.Status.Reason != "UnexpectedAssignedGuest" || cloud.deletes != 1 || guest.sends != 1 {
		t.Fatal("matching guest status invented missing assignment authority")
	}
}
