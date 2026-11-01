package podprovider

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *Reconciler) poolMode(ctx context.Context) (bool, error) {
	if r.cfg.WarmTarget > 0 {
		return true, nil
	}
	pools, _, err := r.allocations(ctx)
	return len(pools) > 0, err
}

// selectPool resumes a published reservation before considering another slot.
// Only an uncommitted anchor can be reselected after a losing claim or missing
// slot. A committed Pod never adopts a replacement allocation.
func (r *Reconciler) selectPool(ctx context.Context, rec *record, podSecret *corev1.Secret) (*poolRecord, *corev1.Secret, error) {
	if rec.Pool != nil {
		p, secret, err := r.loadPool(ctx, rec.Pool.Name)
		missing := apierrors.IsNotFound(err) || (err == nil && secret.UID != rec.Pool.UID)
		if missing {
			if rec.PoolCommitted {
				return nil, nil, errors.New("committed allocation disappeared or was replaced")
			}
			rec.Pool = nil
			// CAS refuses a stale false marker if another reconciler committed it.
			if err := r.save(ctx, rec, podSecret); err != nil {
				return nil, nil, err
			}
		} else if err != nil {
			return nil, nil, err
		} else if p.Claim != nil && (p.Claim.PodUID != rec.UID || p.Claim.RecordUID != podSecret.UID) {
			if rec.PoolCommitted {
				return nil, nil, errors.New("committed allocation belongs to another Pod")
			}
			rec.Pool = nil
			if err := r.save(ctx, rec, podSecret); err != nil {
				return nil, nil, err
			}
		} else {
			if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
				return nil, nil, err
			}
			return p, secret, r.checkPoolBinding(rec, p)
		}
	}
	pools, _, err := r.allocations(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, state := range pools {
		p, secret := state.record, state.secret
		if p.Claim != nil || p.DeleteRequested || p.Deleted || !r.compatiblePool(p) {
			continue
		}
		// An unclaimed slot might already have a published Pod anchor after a
		// process crash. Complete that reservation before offering it elsewhere.
		reserved, reservedSecret, err := r.poolPod(ctx, p, secret)
		if err != nil {
			return nil, nil, err
		}
		if reserved != nil && reservedSecret.UID != podSecret.UID {
			continue
		}
		if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
			return nil, nil, err
		}
		return p, secret, r.checkPoolBinding(rec, p)
	}
	p, secret, err := r.reservePool(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
		return nil, nil, err
	}
	return p, secret, r.checkPoolBinding(rec, p)
}

func (r *Reconciler) poolPod(ctx context.Context, p *poolRecord, secret *corev1.Secret) (*record, *corev1.Secret, error) {
	if p.Claim != nil {
		rec, podSecret, err := r.loadRecord(ctx, p.Claim.RecordName)
		if apierrors.IsNotFound(err) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if podSecret.UID != p.Claim.RecordUID || rec.UID != p.Claim.PodUID {
			return nil, nil, nil
		}
		if rec.Pool == nil || rec.Pool.Name != secret.Name || rec.Pool.UID != secret.UID || p.Claim.DesiredDigest != desiredDigest(rec) {
			return nil, nil, errors.New("claimed allocation lost its reciprocal Pod anchor")
		}
		return rec, podSecret, nil
	}
	list := &corev1.SecretList{}
	if err := r.client.List(ctx, list, client.InNamespace(r.cfg.Namespace), client.MatchingLabels{ownerLabel: r.cfg.ProviderID}); err != nil {
		return nil, nil, err
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	for _, entry := range list.Items {
		if entry.Labels[slotLabel] == "true" {
			continue
		}
		rec, podSecret, err := r.loadRecord(ctx, entry.Name)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if rec.Pool != nil && rec.Pool.Name == secret.Name && rec.Pool.UID == secret.UID && !rec.Deleted {
			return rec, podSecret, nil
		}
	}
	return nil, nil, nil
}

func (r *Reconciler) removePool(ctx context.Context, p *poolRecord, secret *corev1.Secret) (bool, error) {
	return removeCloudInstance(ctx, r.cloud, &p.instanceIntent, r.now(), func() error { return r.savePool(ctx, p, secret) })
}

func (r *Reconciler) removePooledInstance(ctx context.Context, rec *record, podSecret *corev1.Secret) (bool, error) {
	if rec.Deleted {
		return true, nil
	}
	if !rec.DeleteRequested {
		rec.DeleteRequested = true
		if err := r.save(ctx, rec, podSecret); err != nil {
			return false, err
		}
	}
	if rec.Pool == nil {
		rec.Deleted = true
		return true, r.save(ctx, rec, podSecret)
	}
	p, secret, err := r.loadPool(ctx, rec.Pool.Name)
	missing := apierrors.IsNotFound(err) || (err == nil && secret.UID != rec.Pool.UID)
	if missing {
		if rec.PoolCommitted {
			return false, errors.New("refusing cleanup of a missing or replaced committed allocation")
		}
		rec.Pool = nil
		rec.Deleted = true
		return true, r.save(ctx, rec, podSecret)
	}
	if err != nil {
		return false, err
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name, RecordUID: podSecret.UID, DesiredDigest: desiredDigest(rec)}
	if p.Claim != nil && !reflect.DeepEqual(p.Claim, want) {
		if rec.PoolCommitted {
			return false, errors.New("refusing cleanup of a foreign committed allocation")
		}
		// Losing a reservation CAS never authorized this Pod to touch the VM.
		rec.Deleted = true
		return true, r.save(ctx, rec, podSecret)
	}
	if p.Claim == nil {
		p.Claim = want
		if err := r.savePool(ctx, p, secret); err != nil {
			return false, err
		}
	}
	done, err := r.removePool(ctx, p, secret)
	if err != nil || !done {
		return done, err
	}
	rec.Deleted = true
	return true, r.save(ctx, rec, podSecret)
}

// maintainPools runs under the same leader/mutex as Pod reconciliation. Cleanup
// is independent of node availability; only replenishment needs node ownership.
func (r *Reconciler) maintainPools(ctx context.Context) error {
	pools, legacy, err := r.allocations(ctx)
	if err != nil {
		return err
	}
	var pending int64
	for _, state := range pools {
		p := state.record
		if p.Claim == nil && !p.DeleteRequested && !p.Deleted && p.Slot < r.cfg.MaxPods && r.compatiblePool(p) {
			pending++
		}
	}
	total := legacy + int64(len(pools))
	if pending < r.cfg.WarmTarget && total < r.cfg.MaxPods {
		if r.ownsNode != nil {
			if err := r.ownsNode(ctx); err != nil {
				return err
			}
		}
		p, secret, err := r.reservePool(ctx)
		if err != nil {
			return err
		}
		return r.inspectIdle(ctx, p, secret)
	}
	if len(pools) == 0 {
		return nil
	}
	// Process one allocation per sweep. Network calls under the reconciliation
	// mutex must not grow with warmTarget and starve Pod verification deadlines.
	// The cursor is only a fairness hint; all cleanup/claim authority is durable.
	chosen := 0
	for i, state := range pools {
		if state.record.Slot >= r.poolCursor {
			chosen = i
			break
		}
	}
	p, secret := pools[chosen].record, pools[chosen].secret
	r.poolCursor = p.Slot + 1
	rec, podSecret, err := r.poolPod(ctx, p, secret)
	if err != nil {
		return err
	}
	if rec != nil && p.Claim == nil {
		if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
			return err
		}
	}
	if p.Claim != nil {
		if rec != nil && !rec.Deleted {
			return nil
		}
		done, err := r.removePool(ctx, p, secret)
		if err == nil && done {
			err = r.discard(ctx, secret)
		}
		return err
	}
	var earlier int64
	for _, state := range pools[:chosen] {
		other := state.record
		if other.Claim == nil && !other.DeleteRequested && !other.Deleted && other.Slot < r.cfg.MaxPods && r.compatiblePool(other) {
			earlier++
		}
	}
	drain := p.DeleteRequested || p.Deleted || !r.compatiblePool(p) || p.Slot >= r.cfg.MaxPods || earlier >= r.cfg.WarmTarget || total > r.cfg.MaxPods
	if drain {
		done, err := r.removePool(ctx, p, secret)
		if err == nil && done {
			err = r.discard(ctx, secret)
		}
		return err
	}
	return r.inspectIdle(ctx, p, secret)
}

func (r *Reconciler) inspectIdle(ctx context.Context, p *poolRecord, secret *corev1.Secret) error {
	if p.VerificationDeadline == nil {
		deadline := r.now().Add(time.Duration(p.VerificationTimeoutSeconds) * time.Second)
		p.VerificationDeadline = &deadline
		if err := r.savePool(ctx, p, secret); err != nil {
			return err
		}
	}
	if !r.now().Before(*p.VerificationDeadline) {
		_, err := r.removePool(ctx, p, secret)
		return err
	}
	if r.ownsNode != nil {
		if err := r.ownsNode(ctx); err != nil {
			return err
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, p.VerificationDeadline.Sub(r.now()))
	defer cancel()
	in, err := ensureCloudInstance(callCtx, r.cloud, &p.instanceIntent, r.now(), func() error { return r.savePool(callCtx, p, secret) })
	if err != nil {
		return err
	}
	if in == nil || validateInstance(p.instanceRecord(), in) != nil || in.Boot.Count > 1 || in.Status == "failed" || in.Status == "terminated" || in.Status == "terminating" || in.Status == "stopped" {
		_, err := r.removePool(ctx, p, secret)
		return err
	}
	if in.Status != "running" {
		return nil
	}
	address, _, _, err := endpoints(p.instanceRecord(), in)
	if err != nil {
		return nil
	}
	target, err := r.assignmentTarget(callCtx, p, address)
	if err != nil {
		return err
	}
	defer target.Close()
	if !r.now().Before(*p.VerificationDeadline) {
		_, err := r.removePool(ctx, p, secret)
		return err
	}
	p.VerificationDeadline = nil
	return r.savePool(ctx, p, secret)
}
