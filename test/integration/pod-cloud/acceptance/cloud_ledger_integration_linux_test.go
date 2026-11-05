//go:build linux && pod_cloud_integration

package acceptance

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"sort"
)

// Every ledger mutation is durable before its caller gains authority; callers
// never hold this lock over network I/O.
func (r *cloudRun) updateLedger(change func(*cloudLedger) error) error {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	raw, err := json.Marshal(r.ledger)
	if err != nil {
		return err
	}
	var next cloudLedger
	if err = json.Unmarshal(raw, &next); err != nil {
		return err
	}
	if err = change(&next); err != nil {
		return err
	}
	if next.Version != r.ledger.Version || next.Run != r.ledger.Run || next.Config != r.ledger.Config || next.CredentialHash != r.ledger.CredentialHash || !reflect.DeepEqual(next.Before, r.ledger.Before) {
		return errors.New("ledger update changed immutable cleanup authority")
	}
	if err = r.saveLocked(next); err != nil {
		return err
	}
	// Keep immutable fields at their original addresses for concurrent readers.
	// A failed write never publishes tentative create/deletion authority in memory.
	r.ledger.Owned, r.ledger.Pods, r.ledger.Complete = next.Owned, next.Pods, next.Complete
	return nil
}

// submittedPod is the durable Pod intent of one side: its own owned launch,
// or, in the warm scenario, a pointer at the generic launch it was assigned to.
func (r *cloudRun) submittedPod(side string) (cloudPodIntent, bool) {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if p, ok := r.ledger.Pods[side]; ok {
		return p, true
	}
	if o := r.ledger.Owned[side]; o != nil && o.UID != "" {
		return cloudPodIntent{UID: o.UID, Key: o.Key}, true
	}
	return cloudPodIntent{}, false
}

// ownedSnapshot copies the owned Cloud intent a side resolves to, and names the
// ledger handle that holds it.
func (r *cloudRun) ownedSnapshot(side string) (*cloudOwned, string, error) {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if p, ok := r.ledger.Pods[side]; ok {
		side = p.Allocation
	}
	o := r.ledger.Owned[side]
	if o == nil {
		return nil, "", errors.New("missing exact owned Cloud intent")
	}
	copy := *o
	copy.Labels = maps.Clone(o.Labels)
	if o.Receipt != nil {
		receipt := *o.Receipt
		receipt.Labels = maps.Clone(o.Receipt.Labels)
		copy.Receipt = &receipt
	}
	return &copy, side, nil
}

// ownedHandles lists owned launches newest side first with the CDS last, so
// cleanup ends the guests that depend on the CDS before the CDS itself.
func (r *cloudRun) ownedHandles() []string {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	out := make([]string, 0, len(r.ledger.Owned))
	for key := range r.ledger.Owned {
		if key != "cds" {
			out = append(out, key)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	if r.ledger.Owned["cds"] != nil {
		out = append(out, "cds")
	}
	return out
}
