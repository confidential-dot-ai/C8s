package podprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func onlyPool(t *testing.T, r *Reconciler) poolState {
	t.Helper()
	pools, _, err := r.allocations(t.Context())
	if err != nil || len(pools) != 1 {
		t.Fatalf("expected one durable allocation, got %d: %v", len(pools), err)
	}
	return pools[0]
}

func TestWarmIdleDeadlineSurvivesRestartAndRetainsCapacity(t *testing.T) {
	r, cloud, guest, _ := poolFixture(t)
	r.cfg.MaxPods = 1
	cloud.holdDeletion = true
	unavailable := func(context.Context, *poolRecord, string) (assignmentSession, error) {
		return nil, errors.New("unverifiable idle guest")
	}
	r.assignment = unavailable
	if err := r.maintainPools(t.Context()); err == nil {
		t.Fatal("unverifiable idle guest was accepted")
	}
	before := onlyPool(t, r)
	if before.record.VerificationDeadline == nil || before.record.InstanceID == "" {
		t.Fatal("idle verification lost its frozen deadline or VM identity")
	}
	r = restartPoolReconciler(r, guest)
	r.assignment = unavailable
	r.cfg.VerificationTimeoutSeconds = 86400
	r.now = func() time.Time { return *before.record.VerificationDeadline }
	r.ownsNode = func(context.Context) error { return errors.New("node unavailable during cleanup") }
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending := onlyPool(t, r)
	if !pending.record.DeleteRequested || pending.record.Deleted || !pending.record.VerificationDeadline.Equal(*before.record.VerificationDeadline) || cloud.deletes != 1 {
		t.Fatal("expired idle allocation did not preserve cleanup authority")
	}
	if _, _, err := r.reservePool(t.Context()); err == nil {
		t.Fatal("unconfirmed idle termination released capacity")
	}
	cloud.byKey[before.record.Key].Status = "terminated"
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	replacement, _, err := r.reservePool(t.Context())
	if err != nil || replacement.Key == before.record.Key {
		t.Fatalf("confirmed termination did not permit a new allocation generation: %v", err)
	}
	if guest.prepares != 0 || guest.sends != 0 || cloud.creates != 1 {
		t.Fatal("idle cleanup granted workload authority or created another VM")
	}
}

func TestWarmIdleRequiresOwnedLiveEmptyGuest(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		mutate                func(*instance)
		wantDelete, wantError bool
	}{
		{"starting", func(in *instance) { in.Status = "starting" }, false, false},
		{"missing-endpoint", func(in *instance) { in.Endpoints = nil }, false, false},
		{"rebooted", func(in *instance) { in.Boot.Count = 2 }, true, false},
		{"failed", func(in *instance) { in.Status = "failed" }, true, false},
		{"different-image", func(in *instance) { in.Image.Version = "unexpected" }, true, false},
		{"foreign-owner", func(in *instance) { in.Labels["podcvm-provider"] = "other-provider" }, false, true},
		{"changed-instance-id", func(in *instance) { in.ID = "i-replacement" }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cloud, guest, _ := poolFixture(t)
			r.cfg.MaxPods = 1
			cloud.holdDeletion = true
			if err := r.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			initial := onlyPool(t, r)
			tc.mutate(cloud.byKey[initial.record.Key])
			err := r.maintainPools(t.Context())
			if (err != nil) != tc.wantError {
				t.Fatalf("idle inspection error = %v", err)
			}
			current := onlyPool(t, r)
			if current.record.VerificationDeadline == nil || current.record.Key != initial.record.Key || guest.prepares != 0 || guest.sends != 0 {
				t.Fatal("unverified guest became reusable or acquired workload authority")
			}
			if tc.name == "changed-instance-id" {
				if !current.record.Deleted || cloud.deletes != 0 {
					t.Fatal("missing original VM caused deletion of a replacement identity")
				}
			} else if current.record.DeleteRequested != tc.wantDelete || (cloud.deletes > 0) != tc.wantDelete {
				t.Fatal("idle retirement touched a foreign VM or retained an invalid owned guest")
			}
			if _, _, err := r.reservePool(t.Context()); err == nil {
				t.Fatal("unverified or undiscarded slot was omitted from capacity")
			}
		})
	}
}

func TestWarmLateIdleVerificationCannotReturnToReady(t *testing.T) {
	r, cloud, guest, _ := poolFixture(t)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.assignment = func(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
		now = *p.VerificationDeadline
		return guest.verify(ctx, p, address)
	}
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	p := onlyPool(t, r).record
	if p.VerificationDeadline == nil || !p.DeleteRequested || cloud.deletes != 1 || guest.sends != 0 {
		t.Fatal("late idle evidence reset its deadline instead of retiring the guest")
	}
}

func TestWarmOwnershipFailureNeverReservesOrLaunches(t *testing.T) {
	r, cloud, _, _ := poolFixture(t)
	r.ownsNode = func(context.Context) error { return errors.New("provider node registration pending") }
	if err := r.maintainPools(t.Context()); err == nil {
		t.Fatal("warm replenishment ignored missing node ownership")
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil || len(pools) != 0 || cloud.creates != 0 {
		t.Fatal("unowned provider reserved Cloud capacity")
	}
	r.ownsNode = nil
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.ownsNode = func(context.Context) error { return errors.New("node replaced") }
	if err := r.maintainPools(t.Context()); err == nil {
		t.Fatal("idle verification ignored lost node ownership")
	}
	if p := onlyPool(t, r).record; p.VerificationDeadline == nil || p.DeleteRequested || cloud.creates != 1 {
		t.Fatal("ownership failure refreshed readiness or changed VM identity")
	}
}

// Faults affect the Cloud response only; the embedded fake retains the actual
// VM so recovery can demonstrate that ambiguous operations never free quota.
type recoveryCloud struct {
	*poolCloud
	find   func(context.Context, string) (*instance, error)
	create func(context.Context, string, createRequest) (*instance, error)
	delete func(context.Context, string) error
}

func (c *recoveryCloud) Find(ctx context.Context, key string) (*instance, error) {
	if c.find != nil {
		return c.find(ctx, key)
	}
	return c.poolCloud.Find(ctx, key)
}
func (c *recoveryCloud) Create(ctx context.Context, key string, req createRequest) (*instance, error) {
	if c.create != nil {
		return c.create(ctx, key, req)
	}
	return c.poolCloud.Create(ctx, key, req)
}
func (c *recoveryCloud) Delete(ctx context.Context, id string) error {
	if c.delete != nil {
		return c.delete(ctx, id)
	}
	return c.poolCloud.Delete(ctx, id)
}

func TestWarmUncertainCreateCleanupRequiresAuthoritativeResolution(t *testing.T) {
	for _, outcome := range []string{"old", "lookup-unavailable", "replay-unavailable", "replay-empty", "replay-foreign", "replay-owned"} {
		t.Run(outcome, func(t *testing.T) {
			r, cloud, guest, _ := poolFixture(t)
			r.cfg.MaxPods = 1
			cloud.loseCreate, cloud.holdDeletion = true, true
			if err := r.maintainPools(t.Context()); err == nil {
				t.Fatal("fixture did not lose its create response")
			}
			original := onlyPool(t, r)
			if original.record.InstanceID != "" || !original.record.CreateAttempted || cloud.creates != 1 {
				t.Fatal("uncertain create did not retain durable intent")
			}
			r = restartPoolReconciler(r, guest)
			fault := &recoveryCloud{poolCloud: cloud, find: func(context.Context, string) (*instance, error) { return nil, nil }}
			r.cloud = fault
			if outcome == "old" {
				r.now = func() time.Time { return original.record.CreatedAt.Add(25 * time.Hour) }
			}
			if outcome == "lookup-unavailable" {
				fault.find = func(context.Context, string) (*instance, error) { return nil, errors.New("lookup unavailable") }
			}
			if outcome != "old" && outcome != "lookup-unavailable" && outcome != "replay-owned" {
				fault.create = func(context.Context, string, createRequest) (*instance, error) {
					switch outcome {
					case "replay-unavailable":
						return nil, errors.New("replay response lost")
					case "replay-empty":
						return nil, nil
					default:
						in := copyPoolInstance(cloud.byKey[original.record.Key])
						in.Labels["podcvm-provider"] = "other-provider"
						return in, nil
					}
				}
			}
			done, err := r.removePool(t.Context(), original.record, original.secret)
			if done || (err == nil) != (outcome == "replay-owned") {
				t.Fatalf("ambiguous cleanup result = %v, %v", done, err)
			}
			pending := onlyPool(t, r)
			if !pending.record.DeleteRequested || pending.record.Deleted {
				t.Fatal("ambiguous cleanup discarded its durable obligation")
			}
			if _, _, err := r.reservePool(t.Context()); err == nil {
				t.Fatal("uncertain create cleanup released MaxPods")
			}
			if outcome != "replay-owned" && cloud.deletes != 0 {
				t.Fatal("unresolved or foreign create reply authorized deletion")
			}
			if outcome == "old" && cloud.creates != 1 {
				t.Fatal("create replay exceeded Cloud idempotency retention")
			}
			// Restored authoritative lookup resolves even the old intent without a create.
			fault.find, fault.create = nil, nil
			done, err = r.removePool(t.Context(), pending.record, pending.secret)
			if done || err != nil {
				t.Fatalf("owned VM did not enter confirmed cleanup: %v", err)
			}
			cloud.byKey[original.record.Key].Status = "terminated"
			pending = onlyPool(t, r)
			done, err = r.removePool(t.Context(), pending.record, pending.secret)
			if !done || err != nil || !onlyPool(t, r).record.Deleted {
				t.Fatalf("confirmed termination did not release cleanup: %v", err)
			}
			if guest.prepares != 0 || guest.sends != 0 {
				t.Fatal("uncertain idle VM acquired Pod authority")
			}
		})
	}
}

func TestWarmDeleteResponseLossKeepsIdentityAcrossRestart(t *testing.T) {
	r, cloud, guest, _ := poolFixture(t)
	r.cfg.MaxPods = 1
	cloud.holdDeletion = true
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	p := onlyPool(t, r)
	r.cloud = &recoveryCloud{poolCloud: cloud, delete: func(ctx context.Context, id string) error {
		if err := cloud.Delete(ctx, id); err != nil {
			return err
		}
		return errors.New("delete response lost")
	}}
	if done, err := r.removePool(t.Context(), p.record, p.secret); done || err == nil {
		t.Fatal("ambiguous delete appeared complete")
	}
	r = restartPoolReconciler(r, guest)
	if _, _, err := r.reservePool(t.Context()); err == nil {
		t.Fatal("lost delete response freed quota")
	}
	current := onlyPool(t, r)
	if current.record.InstanceID != p.record.InstanceID || !current.record.DeleteRequested {
		t.Fatal("restart lost the deleting VM identity")
	}
	cloud.byKey[p.record.Key].Status = "terminated"
	if done, err := r.removePool(t.Context(), current.record, current.secret); !done || err != nil {
		t.Fatalf("confirmed termination could not recover from lost delete response: %v", err)
	}
	if cloud.creates != 1 || cloud.deletes != 1 {
		t.Fatal("delete recovery recreated or re-deleted a terminated VM")
	}
}

func TestWarmIntentWritesFenceCloudEffects(t *testing.T) {
	for _, phase := range []string{"create-attempt", "instance-identity", "delete-intent", "cleanup-identity"} {
		t.Run(phase, func(t *testing.T) {
			r, cloud, _, _ := poolFixture(t)
			r.cfg.MaxPods = 1
			p, slot, err := r.reservePool(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if phase == "delete-intent" {
				if err := r.inspectIdle(t.Context(), p, slot); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "cleanup-identity" {
				cloud.loseCreate = true
				if err := r.inspectIdle(t.Context(), p, slot); err == nil {
					t.Fatal("fixture did not lose create response")
				}
				p, slot, err = r.loadPool(t.Context(), slot.Name)
				if err != nil {
					t.Fatal(err)
				}
			}
			watching := r.client.(client.WithWatch)
			failed := false
			r.client = interceptor.NewClient(watching, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				secret, ok := obj.(*corev1.Secret)
				if ok && secret.Labels[slotLabel] == "true" {
					var proposed poolRecord
					if err := decode(secret.Data["state.json"], &proposed); err != nil {
						t.Fatal(err)
					}
					reject := phase == "create-attempt" && proposed.CreateAttempted || phase == "instance-identity" && proposed.InstanceID != "" || phase == "delete-intent" && proposed.DeleteRequested || phase == "cleanup-identity" && proposed.DeleteRequested && proposed.InstanceID != ""
					if reject {
						failed = true
						return errors.New("allocation write unavailable")
					}
				}
				return c.Update(ctx, obj, opts...)
			}})
			if phase == "delete-intent" || phase == "cleanup-identity" {
				if done, err := r.removePool(t.Context(), p, slot); done || err == nil {
					t.Fatal("cleanup passed failed intent publication")
				}
			} else if err := r.inspectIdle(t.Context(), p, slot); err == nil {
				t.Fatal("creation passed failed intent publication")
			}
			durable := onlyPool(t, r).record
			if !failed || cloud.deletes != 0 || durable.Deleted {
				t.Fatal("failed state write authorized deletion or discarded capacity")
			}
			if phase == "create-attempt" && (cloud.creates != 0 || durable.CreateAttempted) {
				t.Fatal("VM creation preceded its persisted attempt")
			}
			if phase != "create-attempt" && cloud.creates != 1 {
				t.Fatal("failed persistence duplicated Cloud creation")
			}
			if _, _, err := r.reservePool(t.Context()); err == nil {
				t.Fatal("failed write lost its occupied slot")
			}
		})
	}
}

func TestWarmAssignedGuestFailureCannotCreateReplacement(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*instance)
	}{
		{"missing", "InstanceGone", func(in *instance) { in.ID = "replacement" }},
		{"image-changed", "InstanceIdentityMismatch", func(in *instance) { in.Image.Version = "foreign" }},
		{"rebooted", "GuestRebooted", func(in *instance) { in.Boot.Count = 2 }},
		{"ended", "InstanceEnded", func(in *instance) { in.Status = "failed" }},
		{"starting", "InstanceStarting", func(in *instance) { in.Status = "starting" }},
		{"endpoints-lost", "EndpointsPending", func(in *instance) { in.Endpoints = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cloud, guest, pod := poolFixture(t)
			r.cfg.MaxPods = 1
			cloud.holdDeletion = true
			runToAssigned(t, r, pod)
			rec := getRecord(t, r, pod)
			p, _, err := r.loadPool(t.Context(), rec.Pool.Name)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(cloud.byKey[p.Key])
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			current := getPod(t, r, pod)
			if current.Status.Reason != tc.reason || current.Annotations[endpointsAnnotation] != "" || cloud.creates != 1 || guest.prepares != 1 || guest.sends != 1 {
				t.Fatal("lost assigned guest preserved readiness or created another assignment")
			}
			if _, _, err := r.reservePool(t.Context()); err == nil {
				t.Fatal("failed assigned guest released its permanent allocation")
			}
		})
	}
}

func TestWarmCleanupCompletesHalfPublishedClaim(t *testing.T) {
	r, cloud, guest, pod := poolFixture(t)
	r.cfg.MaxPods = 1
	cloud.holdDeletion = true
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	idle := onlyPool(t, r)
	rec, podSecret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	rec.Pool = &poolRef{Name: idle.secret.Name, UID: idle.secret.UID}
	if err := r.save(t.Context(), rec, podSecret); err != nil {
		t.Fatal(err)
	}
	r = restartPoolReconciler(r, guest)
	done, err := r.removePooledInstance(t.Context(), rec, podSecret)
	if done || err != nil {
		t.Fatalf("half-published claim cleanup: %v", err)
	}
	pending := onlyPool(t, r).record
	if pending.Claim == nil || pending.Claim.RecordUID != podSecret.UID || pending.Claim.PodUID != pod.UID || !pending.DeleteRequested || pending.Deleted || cloud.deletes != 1 || guest.sends != 0 {
		t.Fatal("cleanup did not preserve exclusive authority over the uncommitted guest")
	}
	cloud.byKey[pending.Key].Status = "terminated"
	done, err = r.removePooledInstance(t.Context(), rec, podSecret)
	if !done || err != nil || !getRecord(t, r, pod).Deleted {
		t.Fatalf("terminated half-published claim remained stranded: %v", err)
	}
	// Repeated cleanup remains idempotent and never returns the VM to idle.
	if done, err := r.removePooledInstance(t.Context(), rec, podSecret); !done || err != nil || cloud.deletes != 1 {
		t.Fatal("completed cleanup repeated Cloud effects")
	}
}

func TestWarmMissingClaimRecordRetiresItsGuest(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	runToAssigned(t, r, pod)
	rec := getRecord(t, r, pod)
	if err := r.discard(t.Context(), mustRecordSecret(t, r, rec.Key)); err != nil {
		t.Fatal(err)
	}
	r.cfg.WarmTarget = 0
	cloud.holdDeletion = true
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	p := onlyPool(t, r).record
	if p.Claim == nil || p.Claim.PodUID != pod.UID || !p.DeleteRequested || p.Deleted || cloud.creates != 1 || cloud.deletes != 1 {
		t.Fatal("lost Pod anchor returned a claimed VM to idle or lost its cleanup authority")
	}
}
