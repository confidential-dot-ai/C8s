package podprovider

import (
	"context"
	"errors"
	"testing"
	"time"
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
	if pending.Claim == nil || pending.Claim.RecordName != podSecret.Name || pending.Claim.PodUID != pod.UID || !pending.DeleteRequested || pending.Deleted || cloud.deletes != 1 || guest.sends != 0 {
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

func TestWarmReducedBudgetDrainsOnlyTheExcess(t *testing.T) {
	r, cloud, _, _ := poolFixture(t)
	r.cfg.WarmTarget, r.cfg.MaxPods = 3, 3
	cloud.holdDeletion = true
	for range 3 {
		if err := r.maintainPools(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	r.cfg.MaxPods = 2
	for range 2 {
		if err := r.maintainPools(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	pools, _, err := r.allocations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	draining := 0
	for _, state := range pools {
		if state.record.DeleteRequested {
			draining++
		}
	}
	if len(pools) != 3 || draining != 1 || cloud.creates != 3 {
		t.Fatalf("reduced budget drained %d of %d slots across two sweeps", draining, len(pools))
	}
}

func TestWarmReplacedClaimRecordRetiresItsGuest(t *testing.T) {
	r, cloud, _, pod := poolFixture(t)
	runToAssigned(t, r, pod)
	rec := getRecord(t, r, pod)
	if err := r.discard(t.Context(), mustRecordSecret(t, r, rec.Key)); err != nil {
		t.Fatal(err)
	}
	replacement, _, err := r.ensureRecord(t.Context(), pod)
	if err != nil || replacement.Pool != nil {
		t.Fatalf("replacement record was not written fresh: %v", err)
	}
	r.cfg.WarmTarget = 0
	cloud.holdDeletion = true
	if err := r.maintainPools(t.Context()); err != nil {
		t.Fatal(err)
	}
	p := onlyPool(t, r).record
	if p.Claim == nil || p.Claim.PodUID != pod.UID || !p.DeleteRequested || cloud.deletes != 1 {
		t.Fatal("slot claimed by a replaced Pod record was not destroyed")
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
