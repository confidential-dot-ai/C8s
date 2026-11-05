//go:build linux && pod_cloud_integration

package acceptance

import (
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
)

func cloudWarmWait(ctx context.Context, budget time.Duration, observe func(context.Context) (bool, error)) error {
	until, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		if err := until.Err(); err != nil {
			return err
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

// waitGenericIdle waits for the generic guest to run on its first boot with
// only its status ingress, and proves it attests empty with a serving key.
func (r *cloudRun) waitGenericIdle(ctx context.Context, generic *record) (*instance, endpoint, error) {
	var idle *instance
	var status endpoint
	err := cloudWarmWait(ctx, 20*time.Minute, func(ctx context.Context) (bool, error) {
		in, err := r.getOwned(ctx, "generic")
		if err != nil {
			return false, err
		}
		if in == nil || in.Status != "running" {
			return false, nil
		}
		if err = validateInstance(generic, in); err != nil {
			return false, err
		}
		if in.Boot.Count != 1 || !reflect.DeepEqual(in.Network.Ingress, []ingress{{Name: "pod-status", Port: 8443}}) || in.Network.IngressUpdating {
			return false, errors.New("idle generic VM changed its frozen boot or ingress")
		}
		ep, err := cloudEndpoint(in, "pod-status")
		if err != nil {
			return false, nil
		}
		target, err := verifyAssignmentTarget(ctx, generic, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)))
		if err != nil {
			return false, nil
		}
		serving := target.ServingKey()
		target.Close()
		if len(serving) == 0 {
			return false, errors.New("verified idle guest has no serving identity")
		}
		if err = cloudWrite(filepath.Join(r.dir, "idle-"+generic.Key+".json"), map[string]any{"instance": in, "emptyFreshAttestation": true, "servingKey": serving, "bootCount": in.Boot.Count}); err != nil {
			return false, err
		}
		idle, status = in, ep
		return true, nil
	})
	return idle, status, err
}

type cloudWarmSnapshot struct {
	record, generic *record
	leaf            *Leaf
	starts          map[string]string
	instance        string
	boot            int64
}

func (r *cloudRun) warmSnapshot(ctx context.Context, guest *cloudGuest) (*cloudWarmSnapshot, error) {
	rec, err := r.snapshot("a")
	if err != nil {
		return nil, err
	}
	generic, err := r.snapshot("generic")
	if err != nil {
		return nil, err
	}
	if rec.InstanceID != guest.rec.InstanceID || generic.InstanceID != rec.InstanceID || assignmentMatches(rec, generic) != nil {
		return nil, errors.New("assigned warm guest lost its immutable intent")
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
	if err = leaf.Accepted("cloud-a", acceptanceTenant); err != nil {
		return nil, err
	}
	in, err := r.getOwned(ctx, "a")
	if err != nil {
		return nil, err
	}
	if in == nil || in.ID != rec.InstanceID || in.Status != "running" || in.Boot.Count != guest.boot {
		return nil, errors.New("warm guest rebooted or changed Cloud identity")
	}
	return &cloudWarmSnapshot{record: rec, generic: generic, leaf: leaf, starts: state.Starts, instance: in.ID, boot: in.Boot.Count}, nil
}

func sameWarmSnapshot(a, b *cloudWarmSnapshot) bool {
	return a.record.UID == b.record.UID && a.instance == b.instance && a.boot == b.boot &&
		reflect.DeepEqual(a.record.Request, b.record.Request) && reflect.DeepEqual(a.generic.Request, b.generic.Request) &&
		reflect.DeepEqual(a.generic.Assignment, b.generic.Assignment) && reflect.DeepEqual(a.generic.ServingKey, b.generic.ServingKey) &&
		a.leaf.SandboxID == b.leaf.SandboxID && a.leaf.SPKI == b.leaf.SPKI && a.leaf.Workload == b.leaf.Workload && a.leaf.AssignedWorkloadID == b.leaf.AssignedWorkloadID && SameStarts(a.starts, b.starts)
}

// warmAssignment launches a generic guest, assigns the Pod to it through the
// guest status service, opens its workload ingress and proves the assigned
// workload runs and keeps its identity until the guest is deleted.
func (r *cloudRun) warmAssignment(ctx context.Context, t *testing.T, cfg *Config, pod *corev1.Pod) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Minute)
	defer cancel()
	stage := "generic-idle"
	evidence := map[string]any{"passed": false, "scope": "real Cloud TDX generic boot and fresh empty attestation; signed assignment through the guest status service with durable intent before the POST"}
	defer func() {
		evidence["stage"] = stage
		if resultErr != nil {
			resultErr = fmt.Errorf("warm assignment %s: %w", stage, resultErr)
		}
		resultErr = errors.Join(resultErr, cloudWrite(filepath.Join(r.dir, "warm-assignment.json"), evidence))
	}()
	generic, err := r.launchGeneric(ctx, cfg)
	if err != nil {
		return err
	}
	idle, status, err := r.waitGenericIdle(ctx, generic)
	if err != nil {
		return err
	}
	evidence["genericLaunch"] = generic.Key
	stage = "assignment"
	rec, err := r.preparePod(cfg, pod, "a")
	if err != nil {
		return err
	}
	observer := &cloudAssignmentObserver{run: r}
	target, err := verifyAssignmentTarget(ctx, generic, net.JoinHostPort(status.Host, strconv.Itoa(status.Port)))
	if err != nil {
		return err
	}
	defer target.Close()
	session := observer.target(target, "generic")
	manifest, entries, peers, err := assignmentPayload(rec)
	if err != nil {
		return err
	}
	body, err := session.Prepare(ctx, cfg.key, manifest, entries, peers)
	if err != nil {
		return err
	}
	// The exact bytes and the verified serving identity are durable before the
	// guest can see them; a recovered run compares them before any retry.
	generic.Assignment, generic.ServingKey = body, session.ServingKey()
	if err = r.saveRecord(generic, "generic"); err != nil {
		return err
	}
	if _, err = session.Send(ctx, body); err != nil {
		return err
	}
	if err = observer.freezePosts(); err != nil {
		return err
	}
	accepted, err := cloudPrivateRead(filepath.Join(r.dir, "assignment-accepted-"+generic.Key+".json"), 2<<20)
	if err != nil {
		return err
	}
	evidence["assignment"] = json.RawMessage(accepted)
	stage = "ingress"
	for _, rule := range rec.Request.Network.Ingress {
		if rule.Name == "pod-status" {
			continue
		}
		if _, err = r.api.AddIngress(ctx, idle.ID, identityKey(generic.Key, "ingress-"+rule.Name), rule); err != nil {
			return err
		}
	}
	var app endpoint
	if err = cloudWarmWait(ctx, 5*time.Minute, func(ctx context.Context) (bool, error) {
		in, err := r.getOwned(ctx, "a")
		if err != nil {
			return false, err
		}
		if in == nil || in.ID != idle.ID || in.Status != "running" || in.Boot.Count != 1 {
			return false, errors.New("assigned guest stopped or rebooted while its ingress opened")
		}
		if in.Network.IngressUpdating || !reflect.DeepEqual(in.Network.Ingress, rec.Request.Network.Ingress) {
			return false, nil
		}
		app, err = cloudEndpoint(in, "app-8080")
		return err == nil, nil
	}); err != nil {
		return err
	}
	stage = "readiness"
	rec, err = r.snapshot("a")
	if err != nil {
		return err
	}
	guest := &cloudGuest{rec: rec, status: status, app: app, boot: 1}
	if err = cloudWarmWait(ctx, 5*time.Minute, func(ctx context.Context) (bool, error) {
		raw, state, err := r.readStatus(ctx, guest)
		if writeErr := r.observation("warmup-a", raw, nil, err == nil); writeErr != nil {
			return false, writeErr
		}
		return err == nil && state.Ready && state.Running, nil
	}); err != nil {
		return err
	}
	if err = r.exactAttestation(ctx, guest); err != nil {
		return err
	}
	before, err := r.warmSnapshot(ctx, guest)
	if err != nil {
		return err
	}
	if err = cloudPause(ctx, 2*time.Minute); err != nil {
		return err
	}
	after, err := r.warmSnapshot(ctx, guest)
	if err != nil {
		return err
	}
	if !sameWarmSnapshot(before, after) {
		return errors.New("assigned guest changed assignment, workload starts or certificate identity")
	}
	evidence["beforeCertificate"] = json.RawMessage(before.leaf.Raw)
	evidence["afterCertificate"] = json.RawMessage(after.leaf.Raw)
	stage = "deletion"
	if err = r.deleteOwned(ctx); err != nil {
		return err
	}
	if err = observer.checkFrozenPosts(1); err != nil {
		return err
	}
	evidence["passed"] = true
	evidence["assignmentSHA256"] = cloudHash(before.generic.Assignment)
	evidence["genericLaunchSHA256"] = cloudHash(before.generic.Request.Trust.InitData.Document)
	evidence["primaryAssignmentPOSTs"] = int64(1)
	evidence["acceptedAssignments"] = 1
	t.Log("real generic boot, authenticated one-time assignment, workload ingress and deletion passed")
	return nil
}
