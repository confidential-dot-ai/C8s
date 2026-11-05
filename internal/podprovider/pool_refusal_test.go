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
)

func TestWarmCorruptSlotNeverGrantsCloudAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*poolRecord, *corev1.Secret)
	}{
		{"missing-slot-label", func(_ *poolRecord, s *corev1.Secret) { delete(s.Labels, slotLabel) }},
		{"different-account", func(p *poolRecord, _ *corev1.Secret) { p.CredentialHash = "foreign-account" }},
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
	for _, phase := range []string{"rotated-launch-key", "unverified", "canceled-verification", "expired-verification", "nonce-unavailable", "canceled-preparation", "intent-write-failed", "different-ack", "already-assigned"} {
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
