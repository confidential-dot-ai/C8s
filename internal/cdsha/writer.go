package cdsha

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"
)

// writerTick runs while this replica holds the Lease: apply a Genesis
// decree when the cluster has no key, otherwise publish our state and apply
// pending decrees.
func (r *Replica) writerTick(ctx context.Context, term uint64, peers []string) {
	st, serving := r.snapshot()
	pending, err := r.store.PendingDecrees(ctx)
	if err != nil {
		r.log.Warn("list decrees failed", "err", err)
		return
	}
	if len(st.Chain) == 0 {
		for _, p := range pending {
			if p.Err == nil && p.Decree.Decree.Kind == Genesis && r.stillWriter(term) {
				r.genesis(ctx, term, peers, p)
			}
		}
		return
	}
	if !serving || term < st.Chain.Tail().Term {
		return // a candidate writes nothing (L4); a stale term never writes (E1)
	}
	r.publish(ctx, st, false)
	for _, p := range pending {
		if !r.stillWriter(term) {
			return // W4
		}
		r.applyDecree(ctx, term, peers, p)
	}
}

// genesis mints the first mesh CA key under an operator Genesis decree. It
// never runs while any attested peer reports a key: the writer only reaches
// it with an empty chain, and an empty chain syncs from any joined peer
// first (compare). What remains is the honest race in R1.
func (r *Replica) genesis(ctx context.Context, term uint64, peers []string, p PendingDecree) {
	if err := CheckDecree(p.Decree, PreGenesis(r.cfg.ClusterID, r.cfg.OperatorPubKey), time.Now()); err != nil {
		r.event("DecreeRejected", "decree", p.Name, "why", err.Error())
		r.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: err.Error()})
		return
	}
	ca, err := r.newMeshCA()
	if err != nil {
		r.log.Error("genesis: mint mesh CA", "err", err)
		return
	}
	rec := Record{
		ClusterID:      r.cfg.ClusterID,
		Term:           term,
		RootCert:       ca.Cert.Raw,
		Measurements:   normalizePins(r.cfg.BakedPins),
		OperatorPubKey: r.cfg.OperatorPubKey,
		AppliedDecrees: []string{p.Decree.Decree.IntentID},
		Decree:         &p.Decree,
	}
	signed, err := SignRecord(rec, ca.Key)
	if err != nil {
		r.log.Error("genesis: sign epoch 0", "err", err)
		return
	}
	if !r.stillWriter(term) {
		return
	}
	if err := r.accept(State{Chain: Chain{signed}, Key: ca.Key}, "genesis"); err != nil {
		r.log.Error("genesis: accept", "err", err)
		return
	}
	r.mu.Lock()
	r.minted++
	r.mu.Unlock()
	r.event("GenesisMinted", "term", term, "decree", p.Name)
	r.updateServing()
	st, _ := r.snapshot()
	r.awaitAcks(ctx, peers, st.Chain.Tuple())
	r.publish(ctx, st, true)
	epoch := uint64(0)
	r.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &epoch})
}

// publish writes our tail to CDSEpoch when the stored record is absent,
// unparsable, older, or not part of our history. It never writes a lower
// tuple over a genuine higher one, which would defeat E6, except for a fresh
// genesis (overwrite, O4).
func (r *Replica) publish(ctx context.Context, st State, overwrite bool) {
	stored, v, err := r.store.GetEpoch(ctx)
	if err != nil && !v.Exists {
		r.log.Warn("read CDSEpoch failed", "err", err)
		return
	}
	if stored != nil && !overwrite && !r.replaceStored(st.Chain, *stored) {
		return
	}
	if err := r.store.PutEpoch(ctx, st.Chain[len(st.Chain)-1], v); err != nil {
		r.log.Warn("write CDSEpoch failed", "err", err)
	}
}

// replaceStored reports whether the writer should overwrite the stored
// record: it is older than our tail, or it claims an epoch at or just past
// our tail without being our record there or a verified extension of our
// chain (a corrupted or forged record would otherwise stay published, and
// hide real rotations from replicas that learn them through CDSEpoch). A
// record further ahead cannot be checked here and is left alone.
func (r *Replica) replaceStored(chain Chain, stored SignedRecord) bool {
	tail := chain.Tail()
	storedT := Tuple{Epoch: stored.Record.Epoch, Term: stored.Record.Term, Hash: stored.Hash()}
	switch {
	case storedT.Less(chain.Tuple()):
		return true
	case stored.Record.Epoch <= tail.Epoch:
		if bytes.Equal(stored.Hash(), chain[stored.Record.Epoch].Hash()) {
			return false
		}
	case stored.Record.Epoch == tail.Epoch+1:
		cand := append(slices.Clone(chain), stored)
		if cand.Verify(r.cfg.ClusterID) == nil {
			return false
		}
	default:
		return false
	}
	r.event("StoredEpochReplaced", "stored_epoch", stored.Record.Epoch, "local_epoch", tail.Epoch)
	return true
}

// applyDecree validates and applies one decree (D3, D5).
func (r *Replica) applyDecree(ctx context.Context, term uint64, peers []string, p PendingDecree) {
	st, _ := r.snapshot()
	tail := st.Chain.Tail()
	if p.Err == nil {
		if epoch, ok := appliedAt(st.Chain, p.Decree.Decree.IntentID); ok {
			// Applied by a writer that stopped before writing the status.
			r.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &epoch})
			return
		}
	}
	err := p.Err
	if err == nil {
		err = CheckDecree(p.Decree, tail, time.Now())
	}
	if d := p.Decree.Decree; err == nil && d.Kind == RotateKey && len(d.Measurements) > 0 && !slices.Contains(d.Measurements, r.measurement) {
		// The writer would mint a key for a set that excludes it (Q3).
		err = errors.New("bundled pin set excludes the writer; apply UpdateMeasurements first (D13)")
	}
	if err != nil {
		r.event("DecreeRejected", "decree", p.Name, "why", err.Error())
		r.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: err.Error()})
		return
	}
	next, err := r.nextState(st, term, p.Decree)
	if err != nil {
		r.log.Error("build next epoch", "decree", p.Name, "err", err)
		return
	}
	if !r.stillWriter(term) {
		return // W4: the Lease may have lapsed while we built the epoch
	}
	// An epoch that unpins the writer is still handed over by it: it keeps
	// the (unchanged) key until peers have synced, then retires.
	if err := r.acceptAs(next, "decree "+p.Name, false); err != nil {
		r.log.Error("accept own epoch", "decree", p.Name, "err", err)
		return
	}
	// Publish before waiting for acks (D5 reordered): CDSEpoch is how a
	// replica cut off from its peers learns of a rotation and stops serving
	// the old key; waiting for ack_timeout first kept it serving that long.
	r.publish(ctx, next, false)
	r.awaitAcks(ctx, peers, next.Chain.Tuple())
	epoch := next.Chain.Tail().Epoch
	r.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &epoch})
	r.event("DecreeApplied", "decree", p.Name, "kind", p.Decree.Decree.Kind, "epoch", epoch)
	r.mu.Lock()
	r.retireLocked()
	r.mu.Unlock()
}

// nextState builds epoch n+1, signed by the key of epoch n (O3) and bound
// to the decree that justifies it (checkTransition).
func (r *Replica) nextState(st State, term uint64, sd SignedDecree) (State, error) {
	prev := st.Chain[len(st.Chain)-1]
	d := sd.Decree
	rec := prev.Record
	rec.Epoch++
	rec.Term = term
	rec.PrevEpochHash = prev.Hash()
	rec.AppliedDecrees = append(slices.Clone(rec.AppliedDecrees), d.IntentID)
	rec.Decree = &sd
	if len(d.Measurements) > 0 {
		rec.Measurements = d.Measurements // D6 full set; D14 bundled set
	}
	key := st.Key
	if d.Kind == RotateKey {
		ca, err := r.newMeshCA() // D12
		if err != nil {
			return State{}, err
		}
		rec.RootCert, key = ca.Cert.Raw, ca.Key
		if len(d.Measurements) == 0 {
			r.log.Warn("RotateKey without a new pin set: the new key goes to the same measurements (D14)")
		}
	}
	if !overlaps(prev.Record.Measurements, rec.Measurements) {
		r.log.Warn("new pin set has no overlap with the current one (D9)")
	}
	signed, err := SignRecord(rec, st.Key)
	if err != nil {
		return State{}, err
	}
	return State{Chain: append(slices.Clone(st.Chain), signed), Key: key}, nil
}

func overlaps(a, b []string) bool {
	return slices.ContainsFunc(a, func(s string) bool { return slices.Contains(b, s) })
}

// awaitAcks is D5 steps 1-2 and 4 without a push: followers pull on their
// own heartbeat (H2); the writer watches their heartbeats until each reports
// the new tuple or ack_timeout passes. Peers excluded by the new pins never
// ack; that is expected.
func (r *Replica) awaitAcks(ctx context.Context, peers []string, want Tuple) {
	deadline := time.Now().Add(r.cfg.Timing.AckTimeout)
	pending := slices.Clone(peers)
	for len(pending) > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
		pending = slices.DeleteFunc(pending, func(p string) bool {
			hb, err := r.client.heartbeat(ctx, p)
			return err == nil && !hb.Tuple().Less(want)
		})
		if len(pending) > 0 {
			time.Sleep(r.cfg.Timing.Heartbeat / 4)
		}
	}
	for _, p := range pending {
		r.event("MissingAck", "peer", p, "epoch", want.Epoch)
	}
}

func (r *Replica) setStatus(ctx context.Context, name string, st DecreeStatus) {
	if err := r.store.SetDecreeStatus(ctx, name, st); err != nil {
		r.log.Warn("write decree status failed", "decree", name, "err", err)
	}
}

// appliedAt finds the epoch whose record first lists intentID.
func appliedAt(c Chain, intentID string) (uint64, bool) {
	for _, s := range c {
		if slices.Contains(s.Record.AppliedDecrees, intentID) {
			return s.Record.Epoch, true
		}
	}
	return 0, false
}
