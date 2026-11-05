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

// selectPool resolves the slot a Pod claimed, or claims one: an unclaimed
// compatible slot nobody else has anchored, else a fresh reservation. A Pod
// that named a slot follows that binding and never adopts a replacement.
func (r *Reconciler) selectPool(ctx context.Context, rec *record, podSecret *corev1.Secret) (*poolRecord, *corev1.Secret, error) {
	if rec.Pool != nil {
		p, secret, err := r.loadPool(ctx, rec.Pool.Name)
		if apierrors.IsNotFound(err) || (err == nil && secret.UID != rec.Pool.UID) {
			return nil, nil, errors.New("claimed allocation disappeared or was replaced")
		}
		if err != nil {
			return nil, nil, err
		}
		if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
			return nil, nil, err
		}
		return p, secret, nil
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
		// An unclaimed slot might already have a Pod anchor after a crash
		// between the two claim writes. Complete that claim before offering
		// the slot elsewhere.
		reserved, _, err := r.poolPod(ctx, p, secret)
		if err != nil {
			return nil, nil, err
		}
		if reserved != nil && reserved.UID != rec.UID {
			continue
		}
		if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
			return nil, nil, err
		}
		return p, secret, nil
	}
	p, secret, err := r.reservePool(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
		return nil, nil, err
	}
	return p, secret, nil
}

// poolPod finds the Pod record bound to a slot: the one its claim names, or
// an anchor written before the claim.
func (r *Reconciler) poolPod(ctx context.Context, p *poolRecord, secret *corev1.Secret) (*record, *corev1.Secret, error) {
	if p.Claim != nil {
		rec, podSecret, err := r.loadRecord(ctx, p.Claim.RecordName)
		if apierrors.IsNotFound(err) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		// The pod record names the slot before the slot is marked claimed, so a
		// record that does not name this slot is a replacement: the claimed
		// slot's pod is gone and the slot is destroyed.
		if rec.UID != p.Claim.PodUID || rec.Pool == nil || rec.Pool.Name != secret.Name || rec.Pool.UID != secret.UID {
			return nil, nil, nil
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

// removePooledInstance destroys the instance through the slot the Pod claimed.
// A slot that disappeared or was replaced is never released: its instance may
// still run. A slot another Pod claimed was never this Pod's to destroy.
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
	if apierrors.IsNotFound(err) || (err == nil && secret.UID != rec.Pool.UID) {
		return false, errors.New("refusing cleanup of a missing or replaced claimed allocation")
	}
	if err != nil {
		return false, err
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name}
	if p.Claim != nil && !reflect.DeepEqual(p.Claim, want) {
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
	pools, direct, err := r.allocations(ctx)
	if err != nil {
		return err
	}
	var pending int64
	for _, state := range pools {
		p := state.record
		if p.Claim == nil && !p.DeleteRequested && !p.Deleted && r.compatiblePool(p) {
			pending++
		}
	}
	total := direct + int64(len(pools))
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
	// Every slot is inspected on every sweep. Claimed slots are retained and
	// count against the pod budget until destruction is confirmed; a claimed
	// slot whose Pod is gone is destroyed. Unclaimed slots are kept up to the
	// warm target and the capacity remaining under the budget, and drained
	// when incompatible or in excess. An unclaimed slot already draining
	// occupies the budget for reservation but not for the drain threshold,
	// or every sweep until its deletion confirms would drain one more.
	retained := direct
	var unclaimed []poolState
	var errs []error
	for _, state := range pools {
		p, secret := state.record, state.secret
		rec, podSecret, err := r.poolPod(ctx, p, secret)
		if err != nil {
			errs = append(errs, err)
			retained++
			continue
		}
		if rec != nil && p.Claim == nil {
			if err := r.claimPool(ctx, rec, podSecret, p, secret); err != nil {
				errs = append(errs, err)
				retained++
				continue
			}
		}
		if p.Claim == nil && !p.DeleteRequested && !p.Deleted {
			unclaimed = append(unclaimed, state)
			continue
		}
		if p.Claim != nil {
			retained++
			if rec != nil && !rec.Deleted {
				continue
			}
		}
		done, err := r.removePool(ctx, p, secret)
		if err == nil && done {
			err = r.discard(ctx, secret)
		}
		errs = append(errs, err)
	}
	var kept int64
	for _, state := range unclaimed {
		p, secret := state.record, state.secret
		if !r.compatiblePool(p) || kept >= r.cfg.WarmTarget || retained+kept >= r.cfg.MaxPods {
			retained++
			done, err := r.removePool(ctx, p, secret)
			if err == nil && done {
				err = r.discard(ctx, secret)
			}
			errs = append(errs, err)
			continue
		}
		kept++
		errs = append(errs, r.inspectIdle(ctx, p, secret))
	}
	return errors.Join(errs...)
}

// inspectIdle verifies an unclaimed slot like an assignment target. The
// deadline is set when a slot is reserved or first fails and cleared by a
// successful verification, so a slot that stops verifying is destroyed one
// verification deadline after its first failure.
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
	if in == nil || validateInstance(&p.instanceIntent, in) != nil || in.Boot.Count > 1 || in.Status == "failed" || in.Status == "terminated" || in.Status == "terminating" || in.Status == "stopped" {
		_, err := r.removePool(ctx, p, secret)
		return err
	}
	if in.Status != "running" {
		return nil
	}
	address, _, _, err := endpoints(p.Request.Network, in)
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
