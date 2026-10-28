package nriimagepolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// --- F2: a create landing in the deferral window records a LIFETIME denial that
// recovery never clears ----------------------------------------------------
//
// Between NRI registration and RunDeferredCheck, a pre-existing mesh pod is not
// yet on the gate's record. A ValidateContainerAdjustment for one of its
// containers hits gateMesh -> admit -> state() "installed no packet protection",
// which ValidateContainerAdjustment turns into denyContainer -> recordDenial: a
// LIFETIME denial (liftOnAdmit == ""). Recovery later protects the pod but never
// lifts that denial, and only a creation denial (a named liftOnAdmit) can be
// lifted. So the pod asserts no identity for its life even though it is
// recovered -- the PR body claims this window is transient.
//
// This mechanism test needs no network namespace: it inspects the inventory's
// denial record directly, so it runs on every platform.
func TestDeferredWindowCreateDoesNotRefuseAPodForLife(t *testing.T) {
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true}}
	p, _ := newCachedPlugin(cfg, exitsAllowlist(t, ""))
	p.inventory = newAdmissionInventory(t.TempDir())

	pod := meshPod("default", "pod", testNetNS)

	// Not ready: Synchronize defers the pod for recovery.
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	// A container create arrives in the window. SetReady first, so that a fix
	// gated only on !Ready() would not help: readiness is set before
	// RunDeferredCheck runs (main.go), so the pod is still off the record here.
	p.SetReady()
	ctr := makeCtr(pod.Id, "app")
	// The gate must still refuse it (fail-closed: the pod is not yet verified),
	// but transiently — no denial recorded for the pod's life.
	err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{
		Pod:       pod,
		Container: ctr,
	})
	if err == nil {
		t.Fatal("a container of an unverified pod was admitted in the deferral window")
	}
	if d := p.inventory.denied[pod.GetId()]; d.reason != nil && d.liftOnAdmit == "" {
		t.Fatalf("a create in the deferral window recorded a LIFETIME denial (%v); recovery cannot lift it", d.reason)
	}
}

// A pod protect() refused for its life in the deferral window keeps its lifetime
// denial: the transient path is only for a pod recovery has not yet reached, not
// one the gate already refused.
func TestDeferredWindowRefusedPodKeepsItsLifetimeDenial(t *testing.T) {
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true}}
	p, _ := newCachedPlugin(cfg, exitsAllowlist(t, ""))
	p.inventory = newAdmissionInventory(t.TempDir())

	pod := meshPod("default", "pod", testNetNS)
	// Record a lifetime refusal for the sandbox, as protect() does when it cannot
	// establish protection.
	p.mesh.pods[pod.GetId()] = &protectedPod{
		refusal:       errors.New("protect refused this pod for its life"),
		kubeNamespace: pod.GetNamespace(),
	}

	p.SetReady()
	ctr := makeCtr(pod.Id, "app")
	if err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{
		Pod:       pod,
		Container: ctr,
	}); err == nil {
		t.Fatal("a container of a pod refused for its life was admitted")
	}
	if p.inventory.denial(pod.GetId()) == nil {
		t.Fatal("a pod refused for its life recorded no denial; its refusal must stand")
	}
}

// Once recovery has run, a container of a sandbox still off the record is
// genuinely unknown: the refusal holds for its life, as before the fix. The
// transient path must not outlive recovery.
func TestOffRecordCreateAfterRecoveryIsRefusedForLife(t *testing.T) {
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true}}
	p, _ := newCachedPlugin(cfg, exitsAllowlist(t, ""))
	p.inventory = newAdmissionInventory(t.TempDir())

	// Recovery runs with nothing to recover, marking it complete.
	if _, err := p.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	p.SetReady()
	p.RunDeferredCheck(context.Background())
	if !p.mesh.recoveryDone() {
		t.Fatal("recovery did not mark itself done")
	}

	// A fresh, unknown mesh pod's container arrives after recovery.
	pod := meshPod("default", "ghost", testNetNS)
	ctr := makeCtr(pod.Id, "app")
	if err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{
		Pod:       pod,
		Container: ctr,
	}); err == nil {
		t.Fatal("a container of an unknown pod was admitted after recovery")
	}
	if d := p.inventory.denied[pod.GetId()]; d.reason == nil {
		t.Fatal("an unknown pod after recovery recorded no denial; it must be refused for its life")
	}
}
