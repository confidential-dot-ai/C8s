//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
)

func cloudWarmWait(ctx context.Context, h *providerControlPlane, budget time.Duration, observe func(context.Context) (bool, error)) error {
	until, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		if err := until.Err(); err != nil {
			return err
		}
		select {
		case <-h.manager.done:
			return errors.New("provider stopped during warm acceptance")
		default:
		}
		done, err := observe(until)
		if err != nil || done {
			return err
		}
		if err = cloudPause(until, 2*time.Second); err != nil {
			return err
		}
	}
}

func (r *cloudRun) waitCloudIdle(ctx context.Context, h *providerControlPlane, reader *Reconciler, excluded string) (poolState, error) {
	var found poolState
	err := cloudWarmWait(ctx, h, 20*time.Minute, func(ctx context.Context) (bool, error) {
		pools, legacy, err := reader.allocations(ctx)
		if err != nil {
			return false, err
		}
		if legacy != 0 || len(pools) > 2 {
			return false, errors.New("warm acceptance exceeded its allocation budget")
		}
		for _, state := range pools {
			p := state.record
			if p.Key == excluded || p.Claim != nil || p.InstanceID == "" || p.VerificationDeadline != nil {
				continue
			}
			if p.DeleteRequested || p.Deleted || len(p.Assignment) != 0 || len(p.ServingKey) != 0 {
				return false, errors.New("idle guest retained assignment or deletion authority")
			}
			doc, err := p.document()
			if err != nil || doc.Pod != nil || doc.Workloads != "" {
				return false, errors.New("idle generic launch contains Pod authority")
			}
			in, err := r.getOwned(ctx, p.Key)
			if err != nil {
				return false, err
			}
			if in == nil || in.ID != p.InstanceID || in.Status != "running" || in.Boot.Count != 1 || !reflect.DeepEqual(in.Network.Ingress, []ingress{{Name: "pod-status", Port: 8443}}) || in.Network.IngressUpdating {
				return false, errors.New("idle generic VM changed its frozen boot or ingress")
			}
			ep, err := cloudEndpoint(in, "pod-status")
			if err != nil {
				return false, err
			}
			target, err := verifyAssignmentTarget(ctx, p, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)))
			if err != nil {
				return false, err
			}
			serving := target.ServingKey()
			target.Close()
			if len(serving) == 0 {
				return false, errors.New("verified idle guest has no serving identity")
			}
			if err = cloudWrite(filepath.Join(r.dir, "idle-"+p.Key+".json"), map[string]any{"allocation": state.secret, "emptyFreshAttestation": true, "servingKey": serving, "bootCount": in.Boot.Count}); err != nil {
				return false, err
			}
			found = state
			return true, nil
		}
		return false, nil
	})
	return found, err
}

type cloudWarmSnapshot struct {
	record  *record
	pool    *poolRecord
	slotUID string
	leaf    *podcvmtest.Leaf
	starts  map[string]string
}

func (r *cloudRun) warmSnapshot(ctx context.Context, h *providerControlPlane, cfg *Config, guest *cloudGuest) (*cloudWarmSnapshot, error) {
	rec, err := r.snapshot(ctx, h, cfg, "a")
	if err != nil {
		return nil, err
	}
	if rec.Pool == nil {
		return nil, errors.New("warm Pod lost its allocation reference")
	}
	reader := &Reconciler{client: h.client, cfg: cfg}
	p, slot, err := reader.loadPool(ctx, rec.Pool.Name)
	if err != nil {
		return nil, err
	}
	if rec.InstanceID != guest.rec.InstanceID || p.InstanceID != rec.InstanceID || p.DeleteRequested || p.Deleted || assignmentMatches(rec, p) != nil {
		return nil, errors.New("assigned warm guest lost its immutable intent")
	}
	pod, err := r.bootPod(ctx, h, cfg, "a")
	if err != nil {
		return nil, err
	}
	if !controlPlanePodReady(pod) || pod.Annotations[endpointsAnnotation] == "" {
		return nil, errors.New("warm Pod has no authenticated provider readiness")
	}
	raw, state, err := r.readStatus(ctx, guest)
	if err != nil || !state.Ready || !state.Running {
		return nil, errors.New("warm guest is not independently authenticated and ready")
	}
	if err = cloudWriteBytes(filepath.Join(r.dir, "warm-status.json"), raw); err != nil {
		return nil, err
	}
	leaf, err := r.leaf(ctx, guest, "certless")
	if err != nil {
		return nil, err
	}
	if leaf.Workload != "cloud-a" || !leaf.Denied || leaf.SandboxID == "" || leaf.Serial == "" || leaf.SPKI == "" {
		return nil, errors.New("warm mesh certificate lacks its named denied-peer identity")
	}
	in, err := r.getOwned(ctx, "a")
	if err != nil {
		return nil, err
	}
	if in == nil || in.ID != rec.InstanceID || in.Status != "running" || in.Boot.Count != guest.boot {
		return nil, errors.New("warm guest rebooted or changed Cloud identity")
	}
	return &cloudWarmSnapshot{record: rec, pool: p, slotUID: string(slot.UID), leaf: leaf, starts: state.Starts}, nil
}

func sameWarmSnapshot(a, b *cloudWarmSnapshot) bool {
	return a.record.UID == b.record.UID && a.record.InstanceID == b.record.InstanceID && a.slotUID == b.slotUID &&
		a.pool.Key == b.pool.Key && reflect.DeepEqual(a.record.Request, b.record.Request) && reflect.DeepEqual(a.pool.Request, b.pool.Request) &&
		reflect.DeepEqual(a.pool.Claim, b.pool.Claim) && bytes.Equal(a.pool.Assignment, b.pool.Assignment) && bytes.Equal(a.pool.ServingKey, b.pool.ServingKey) &&
		a.leaf.SandboxID == b.leaf.SandboxID && a.leaf.SPKI == b.leaf.SPKI && a.leaf.Workload == b.leaf.Workload && podcvmtest.SameStarts(a.starts, b.starts)
}

func (r *cloudRun) checkWarmTermination(p *poolRecord, uid string) error {
	raw, err := cloudPrivateRead(filepath.Join(r.dir, "termination-"+p.Key+".json"), 1<<20)
	if err != nil {
		return err
	}
	var receipt struct {
		InstanceID    string `json:"instanceID"`
		AllocationUID string `json:"allocationUID"`
		Before        bool   `json:"terminationBeforeRelease"`
	}
	if err = decode(raw, &receipt); err != nil {
		return err
	}
	if receipt.InstanceID != p.InstanceID || receipt.AllocationUID != uid || !receipt.Before {
		return errors.New("missing exact termination-before-release observation")
	}
	return nil
}

func (r *cloudRun) warmAssignment(ctx context.Context, t *testing.T, h *providerControlPlane, cfg *Config, pod *corev1.Pod) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Minute)
	defer cancel()
	stage := "generic-idle"
	evidence := map[string]any{"passed": false, "scope": "real Cloud and fresh TDX verification with durable observer wrappers"}
	defer func() {
		evidence["stage"] = stage
		if resultErr != nil {
			resultErr = fmt.Errorf("warm assignment %s: %w", stage, resultErr)
		}
		resultErr = errors.Join(resultErr, cloudWrite(filepath.Join(r.dir, "warm-assignment.json"), evidence))
	}()
	reader := &Reconciler{client: h.client, cfg: cfg}
	tracked := &cloudTrackedAPI{run: r, reader: reader}
	observed := &cloudAssignmentObserver{run: r, reader: reader}
	start := func(next *Config) {
		h.cfg = next
		reader.cfg = next
		h.startProvider(t, tracked, observed.read, observed.target)
		h.waitForVirtualNode(t)
	}
	stop := func() error {
		h.manager.stop(t)
		select {
		case <-h.manager.done:
			return h.manager.err
		default:
			return errors.New("provider has not stopped")
		}
	}
	start(cfg)
	h.installWebhooks(t)
	idle, err := r.waitCloudIdle(ctx, h, reader, "")
	if err != nil {
		return err
	}
	evidence["initialAllocation"] = idle.record.Key
	stage = "scheduled-assignment"
	if err = r.submit(ctx, h, pod, cfg, "a"); err != nil {
		return err
	}
	guest, err := r.waitBoot(ctx, h, cfg, "a")
	if err != nil {
		return err
	}
	if guest.rec.Pool == nil || guest.rec.Pool.UID != idle.secret.UID {
		return errors.New("scheduler did not claim the pre-existing generic allocation")
	}
	if err = cloudWarmWait(ctx, h, 3*time.Minute, func(ctx context.Context) (bool, error) {
		p, err := r.bootPod(ctx, h, cfg, "a")
		return err == nil && controlPlanePodReady(p), err
	}); err != nil {
		return err
	}
	before, err := r.warmSnapshot(ctx, h, cfg, guest)
	if err != nil {
		return err
	}
	accepted, err := cloudPrivateRead(filepath.Join(r.dir, "assignment-accepted-"+before.pool.Key+".json"), 2<<20)
	if err != nil {
		return err
	}
	var proof struct {
		PodUID           string `json:"podUID"`
		AllocationUID    string `json:"allocationUID"`
		AssignmentSHA256 string `json:"assignmentSHA256"`
		ServingKeySHA256 string `json:"servingKeySHA256"`
		Conflict         []byte `json:"conflictingAssignment"`
		Rejected         bool   `json:"conflictingAssignmentRejected"`
		Fenced           bool   `json:"uidFencedClaim"`
		Persisted        bool   `json:"assignmentBeforePOST"`
	}
	if err = decode(accepted, &proof); err != nil {
		return err
	}
	if proof.PodUID != string(before.record.UID) || proof.AllocationUID != before.slotUID || proof.AssignmentSHA256 != cloudHash(before.pool.Assignment) || proof.ServingKeySHA256 != cloudHash(before.pool.ServingKey) || !proof.Rejected || !proof.Fenced || !proof.Persisted || len(proof.Conflict) == 0 {
		return errors.New("assignment proof differs from the accepted durable intent")
	}
	evidence["assignment"] = json.RawMessage(accepted)
	stage = "refill-and-restart"
	refill, err := r.waitCloudIdle(ctx, h, reader, before.pool.Key)
	if err != nil {
		return err
	}
	if refill.secret.UID == idle.secret.UID || refill.record.InstanceID == before.pool.InstanceID {
		return errors.New("refill reused claimed allocation identity")
	}
	if err = stop(); err != nil {
		return err
	}
	// Only the restarted manager may advance this stopped-generation baseline.
	reads, posts := observed.counts()
	if posts != 1 {
		return errors.New("acceptance requires one primary assignment POST")
	}
	start(cfg)
	if err = cloudWarmWait(ctx, h, 3*time.Minute, func(ctx context.Context) (bool, error) { current, _ := observed.counts(); return current > reads, nil }); err != nil {
		return err
	}
	after, err := r.warmSnapshot(ctx, h, cfg, guest)
	if err != nil {
		return err
	}
	if !sameWarmSnapshot(before, after) {
		return errors.New("provider restart changed assignment, workload starts or certificate identity")
	}
	_, posts = observed.counts()
	if posts != 1 {
		return errors.New("provider restart repeated assignment POST")
	}
	evidence["beforeCertificate"] = json.RawMessage(before.leaf.Raw)
	evidence["afterCertificate"] = json.RawMessage(after.leaf.Raw)
	evidence["refillAllocation"] = refill.record.Key
	stage = "disable-and-drain"
	if err = stop(); err != nil {
		return err
	}
	next := *cfg
	next.WarmTarget = 0
	start(&next)
	if err = cloudWarmWait(ctx, h, 8*time.Minute, func(ctx context.Context) (bool, error) {
		_, _, err := reader.loadPool(ctx, refill.secret.Name)
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		if err == nil {
			return false, nil
		}
		in, err := r.getOwned(ctx, refill.record.Key)
		return err == nil && in != nil && in.Status == "terminated", err
	}); err != nil {
		return err
	}
	if err = r.checkWarmTermination(refill.record, string(refill.secret.UID)); err != nil {
		return err
	}
	if err = r.markTerminated(refill.record.Key); err != nil {
		return err
	}
	after, err = r.warmSnapshot(ctx, h, &next, guest)
	if err != nil {
		return err
	}
	if !sameWarmSnapshot(before, after) {
		return errors.New("pool disable disturbed the claimed Pod")
	}
	stage = "claimed-deletion"
	if err = r.deleteThroughProvider(ctx, h, &next); err != nil {
		return err
	}
	if err = cloudWarmWait(ctx, h, 3*time.Minute, func(ctx context.Context) (bool, error) {
		pools, legacy, err := reader.allocations(ctx)
		return err == nil && len(pools) == 0 && legacy == 0, err
	}); err != nil {
		return err
	}
	if err = r.checkWarmTermination(before.pool, before.slotUID); err != nil {
		return err
	}
	if len(r.ownedHandles()) != 3 {
		return errors.New("warm scenario created an unexplained allocation generation")
	}
	h.assertKindInfrastructure(t)
	if t.Failed() {
		return errors.New("warm provider infrastructure check failed")
	}
	if err = stop(); err != nil {
		return err
	}
	_, posts = observed.counts()
	if posts != 1 {
		return errors.New("warm lifecycle repeated the primary assignment POST")
	}
	evidence["passed"] = true
	evidence["assignmentSHA256"] = cloudHash(before.pool.Assignment)
	evidence["genericLaunchSHA256"] = cloudHash(before.pool.Request.Trust.InitData.Document)
	evidence["terminationBeforeRelease"] = true
	evidence["primaryAssignmentPOSTs"] = posts
	t.Log("real generic assignment, provider restart, idle refill drain and claimed VM deletion passed")
	return nil
}
