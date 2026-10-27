//go:build linux && podprovider_integration

package podprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These scenarios share the existing disposable control plane and webhook
// registration. Cloud and guest attestation remain explicit test fakes.
func (h *providerControlPlane) runLifecycleScenarios(t *testing.T) {
	t.Helper()
	h.runVerificationTimeoutScenario(t)
	h.runWarmAssignmentScenario(t)
	if t.Failed() {
		return
	}
	dir := os.Getenv("C8S_PODPROVIDER_ARTIFACTS")
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatal("lifecycle receipt requires the harness evidence directory")
	}
	receipt := map[string]any{
		"result": "PASS", "apiServer": h.serverVersion, "scheduler": "real kind control plane",
		"cloud": "explicit fake", "attestation": "explicit fake assignment and projection",
		"verificationDeadlineSurvivesManagerRestart": true, "lateStatusCannotReviveFailedPod": true,
		"terminalCleanupWaitsForTermination": true, "genericIdleBootHasNoPodAuthority": true,
		"twoScheduledPodsClaimDistinctSlots": true, "assignmentIntentPrecedesPOST": true,
		"lostAssignmentReplySurvivesManagerRestart": true, "staleClaimWriteRejectedByAPI": true,
		"forcedPodDeletionRetainsAllocationBudget": true, "newPodUIDGetsNewAllocationGeneration": true,
		"poolDisabledAndDrained": true, "ownedFakeVMsRemaining": 0,
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lifecycle-result.json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func newControlPlaneCloud(h *providerControlPlane) *controlPlaneCloud {
	return &controlPlaneCloud{client: h.client, cfg: h.cfg, instances: map[string]*instance{}, keys: map[string]string{}, requests: map[string][]byte{}, holdDeletion: true}
}

func (h *providerControlPlane) persistedRecord(t *testing.T, pod *corev1.Pod) record {
	t.Helper()
	var rec record
	if err := json.Unmarshal(h.recordBytes(t, pod.UID), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func (h *providerControlPlane) runVerificationTimeoutScenario(t *testing.T) {
	t.Helper()
	original := h.cfg.VerificationTimeoutSeconds
	h.cfg.VerificationTimeoutSeconds = 30
	cloud := newControlPlaneCloud(h)
	var mode atomic.Int32
	guest := controlPlaneGuest(&mode)
	h.startProvider(t, cloud, guest, nil)
	h.waitForVirtualNode(t)
	pod := controlPlanePod("verification-deadline")
	if err := h.client.Create(h.ctx, pod); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKeyFromObject(pod)
	h.await(t, "unverifiable scheduled guest has a persisted deadline", func() bool {
		current := h.pod(t, key)
		return current != nil && current.Spec.NodeName == h.cfg.NodeName && current.Status.Reason == "AttestationUnavailable"
	})
	pod = h.pod(t, key)
	before := h.persistedRecord(t, pod)
	if before.VerificationDeadline == nil || before.VerificationTimeoutSeconds != 30 || !before.VerificationDeadline.Equal(before.CreatedAt.Add(30*time.Second)) {
		t.Fatal("initial verification budget was not frozen with launch intent")
	}
	h.manager.stop(t)
	h.cfg.VerificationTimeoutSeconds = 600
	h.startProvider(t, cloud, guest, nil)
	h.await(t, "restarted manager fails the guest within the frozen window", func() bool {
		current := h.pod(t, key)
		return current != nil && current.Status.Phase == corev1.PodFailed && current.Status.Reason == verificationTimeoutReason
	})
	failed := h.persistedRecord(t, pod)
	if failed.TerminalStatus == nil || failed.VerificationDeadline == nil || !failed.VerificationDeadline.Equal(*before.VerificationDeadline) || failed.VerificationTimeoutSeconds != 30 {
		t.Fatal("manager restart changed the frozen verification decision")
	}
	current := h.pod(t, key)
	if controlPlanePodReady(current) || current.Annotations[endpointsAnnotation] != "" || !slices.Contains(current.Finalizers, finalizer) {
		t.Fatal("expired guest retained readiness/endpoints or lost cleanup finalizer")
	}
	mode.Store(1)
	h.await(t, "terminal cleanup continues after a late valid guest response", func() bool { return cloud.snapshot().deletes >= 2 })
	current = h.pod(t, key)
	if current.Status.Phase != corev1.PodFailed || current.Status.Reason != verificationTimeoutReason || cloud.snapshot().creates != 1 {
		t.Fatal("late verified status revived the failed Pod or created another VM")
	}
	if err := h.client.Delete(h.ctx, current, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	h.await(t, "expired Pod retains cleanup authority while Cloud deletion is pending", func() bool {
		current := h.pod(t, key)
		return current != nil && !current.DeletionTimestamp.IsZero() && slices.Contains(current.Finalizers, finalizer)
	})
	pending := h.persistedRecord(t, pod)
	if !pending.DeleteRequested || pending.Deleted || cloud.snapshot().remaining != 1 {
		t.Fatal("pending termination released cleanup authority")
	}
	cloud.releaseDeletion()
	h.awaitDeleted(t, key, pod.UID)
	if cloud.snapshot().remaining != 0 {
		t.Fatal("timeout scenario leaked a fake VM")
	}
	h.manager.stop(t)
	h.cfg.VerificationTimeoutSeconds = original
}

func (h *providerControlPlane) runWarmAssignmentScenario(t *testing.T) {
	t.Helper()
	h.cfg.WarmTarget = 1
	cloud := newControlPlaneCloud(h)
	reader := &Reconciler{client: h.client, cfg: h.cfg}
	guest := newControlPlaneAssignment(reader)
	h.startProvider(t, cloud, guest.read, guest.verify)
	h.waitForVirtualNode(t)
	h.await(t, "one empty generic guest is ready before a Pod is scheduled", func() bool {
		pools, legacy, err := reader.allocations(h.ctx)
		return err == nil && legacy == 0 && len(pools) == 1 && pools[0].record.Claim == nil && pools[0].record.InstanceID != "" && pools[0].record.VerificationDeadline == nil
	})
	pools, _, err := reader.allocations(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	generic, err := pools[0].record.document()
	if err != nil || generic.Pod != nil || generic.Workloads != "" || len(pools[0].record.Request.Network.Ingress) != 1 {
		t.Fatal("idle VM received Pod authority or speculative workload ingress")
	}
	pods := []*corev1.Pod{controlPlanePod("warm-workload"), controlPlanePod("warm-peer")}
	for _, pod := range pods {
		if err := h.client.Create(h.ctx, pod); err != nil {
			t.Fatal(err)
		}
	}
	h.await(t, "both scheduled Pods record their assignment before losing its response", func() bool {
		prepared, sent, accepted := guest.snapshot()
		return prepared == 2 && sent == 2 && accepted == 2
	})
	h.manager.stop(t)
	frozen := make([]poolState, 0, 2)
	for i, pod := range pods {
		pods[i] = h.pod(t, client.ObjectKeyFromObject(pod))
		if pods[i] == nil || pods[i].Spec.NodeName != h.cfg.NodeName || pods[i].UID == "" || controlPlanePodReady(pods[i]) {
			t.Fatal("warm claim bypassed scheduling or trusted a lost reply")
		}
		rec, secret, err := reader.loadRecord(h.ctx, identityKey(h.cfg.ProviderID, string(pods[i].UID)))
		if err != nil {
			t.Fatal(err)
		}
		p, slot, err := reader.linkedPool(h.ctx, rec, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !rec.PoolCommitted || secret.UID == "" || slot.UID == "" || p.Claim.RecordUID != secret.UID || p.Claim.PodUID != pods[i].UID || len(p.Assignment) == 0 {
			t.Fatal("claim lacks real API UID fencing")
		}
		frozen = append(frozen, poolState{p, slot})
	}
	if frozen[0].secret.UID == frozen[1].secret.UID || cloud.snapshot().creates != 2 || cloud.snapshot().remaining != 2 {
		t.Fatal("two Pods shared an allocation or exceeded MaxPods")
	}
	// Model an old leader holding an earlier resourceVersion. A real API update
	// must fence its attempted claim overwrite, even after leader handover.
	stale := frozen[0].secret.DeepCopy()
	newer := stale.DeepCopy()
	if newer.Annotations == nil {
		newer.Annotations = map[string]string{}
	}
	newer.Annotations["podprovider.integration/claim-fence"] = "advanced"
	if err := h.client.Update(h.ctx, newer); err != nil {
		t.Fatal(err)
	}
	wrong := *frozen[0].record
	wrong.Claim = frozen[1].record.Claim
	if err := reader.savePool(h.ctx, &wrong, stale); !apierrors.IsConflict(err) {
		t.Fatalf("stale allocation writer escaped the API fence: %v", err)
	}
	current, _, err := reader.loadPool(h.ctx, frozen[0].secret.Name)
	if err != nil || !reflect.DeepEqual(current.Claim, frozen[0].record.Claim) {
		t.Fatal("stale claim changed allocation ownership")
	}
	guest.allowReads()
	h.startProvider(t, cloud, guest.read, guest.verify)
	h.await(t, "new leader recovers accepted assignments without another POST", func() bool {
		return controlPlanePodReady(h.pod(t, client.ObjectKeyFromObject(pods[0]))) && controlPlanePodReady(h.pod(t, client.ObjectKeyFromObject(pods[1])))
	})
	for i, pod := range pods {
		current, slot, err := reader.loadPool(h.ctx, frozen[i].secret.Name)
		if err != nil || slot.UID != frozen[i].secret.UID || current.Key != frozen[i].record.Key || !reflect.DeepEqual(current.Claim, frozen[i].record.Claim) || !bytes.Equal(current.Assignment, frozen[i].record.Assignment) || !bytes.Equal(current.ServingKey, frozen[i].record.ServingKey) {
			t.Fatal("manager restart changed immutable assignment authority")
		}
		assertControlPlaneProjection(t, h.pod(t, client.ObjectKeyFromObject(pod)))
	}
	prepared, sent, accepted := guest.snapshot()
	if prepared != 2 || sent != 2 || accepted != 2 || cloud.snapshot().creates != 2 {
		t.Fatal("restart duplicated an assignment or VM")
	}
	oldPod := pods[0]
	h.forceDeletePod(t, client.ObjectKeyFromObject(oldPod), oldPod.UID)
	h.await(t, "orphan recovery retains its claimed VM while termination is pending", func() bool {
		return h.pod(t, client.ObjectKeyFromObject(oldPod)) == nil && cloud.snapshot().deletes > 0
	})
	orphan := h.persistedRecord(t, oldPod)
	if !orphan.DeleteRequested || orphan.Deleted || cloud.snapshot().remaining != 2 {
		t.Fatal("forced Pod deletion lost its VM obligation")
	}
	replacement := controlPlanePod(oldPod.Name)
	if err := h.client.Create(h.ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacementKey := client.ObjectKeyFromObject(replacement)
	h.await(t, "new Pod waits for allocation capacity retained by the orphan", func() bool {
		p := h.pod(t, replacementKey)
		return p != nil && p.Spec.NodeName == h.cfg.NodeName && p.Status.Reason == "AllocationPending"
	})
	if cloud.snapshot().creates != 2 || cloud.snapshot().remaining != 2 {
		t.Fatal("uncertain termination released allocation capacity")
	}
	cloud.releaseDeletion()
	h.awaitWithTimeout(t, "confirmed termination permits a new generation for the replacement Pod", 90*time.Second, func() bool { return controlPlanePodReady(h.pod(t, replacementKey)) })
	replacement = h.pod(t, replacementKey)
	rec, secret, err := reader.loadRecord(h.ctx, identityKey(h.cfg.ProviderID, string(replacement.UID)))
	if err != nil {
		t.Fatal(err)
	}
	replacementPool, replacementSlot, err := reader.linkedPool(h.ctx, rec, secret)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.UID == oldPod.UID || replacementSlot.UID == frozen[0].secret.UID || replacementPool.Key == frozen[0].record.Key || cloud.snapshot().creates != 3 {
		t.Fatal("replacement reused an old Pod or VM allocation identity")
	}
	// Disable refill before deleting the last Pods. Existing v2 claims must still
	// recover and clean up with warmTarget zero.
	h.manager.stop(t)
	h.cfg.WarmTarget = 0
	h.startProvider(t, cloud, guest.read, guest.verify)
	for _, pod := range []*corev1.Pod{pods[1], replacement} {
		key := client.ObjectKeyFromObject(pod)
		if err := h.client.Delete(h.ctx, h.pod(t, key), client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		h.awaitDeleted(t, key, pod.UID)
	}
	h.await(t, "disabled pool drains all remaining allocation records", func() bool {
		pools, legacy, err := reader.allocations(h.ctx)
		return err == nil && len(pools) == 0 && legacy == 0 && cloud.snapshot().remaining == 0
	})
	h.assertKindInfrastructure(t)
	h.manager.stop(t)
}

func (h *providerControlPlane) forceDeletePod(t *testing.T, key client.ObjectKey, uid types.UID) {
	t.Helper()
	pod := h.pod(t, key)
	if pod == nil || pod.UID != uid {
		t.Fatal("force-deletion target changed")
	}
	if err := h.client.Delete(h.ctx, pod, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &corev1.Pod{}
		if err := h.client.Get(h.ctx, key, current); err != nil {
			return err
		}
		if current.UID != uid {
			return errors.New("force-deletion target UID changed")
		}
		before := current.DeepCopy()
		current.Finalizers = nil
		return h.client.Patch(h.ctx, current, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	}); err != nil {
		t.Fatal(err)
	}
}
