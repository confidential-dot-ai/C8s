// Forwarded writes: a client write a replica takes becomes an entry the
// leader commits.
//
// Only the leader appends to the log, so a replica hands the write to it and
// answers its client once it has applied the entry itself. The leader decodes
// the entry again, refuses every kind that is its own, stamps the cluster's
// clock on it, judges it against the admission cap and commits what it
// encoded: nothing a replica forwards reaches the log in the words it sent.

package cdsha

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// forward hands an entry to the cluster's leader and returns once this
// replica has applied it too, so the client's next read sees its own write.
// The leader's commit and this replica's apply share Timing.Apply.
func (n *Node) forward(entry []byte) (Result, error) {
	_, leader := n.raft.LeaderWithID()
	if leader == "" {
		return Result{}, errors.New("cds-ha: this cluster has no leader (fewer than a majority of its voters answer)")
	}
	held, reached := n.peers.knownAt(string(leader))
	if !reached {
		return Result{}, fmt.Errorf("cds-ha: this replica has not reached the leader, member %s", leader)
	}
	deadline := time.Now().Add(n.cfg.Timing.Apply)
	write := controlRequest{
		Op:    opWrite,
		Entry: entry,
	}
	answer, err := held.control.exchange(write, time.Until(deadline))
	if err != nil {
		return Result{}, err
	}
	if answer.Err != "" {
		return Result{}, refusedByLeader(answer)
	}
	// A committed index holds the same entry on every replica of the cluster,
	// so this replica waits for its own state machine to reach it.
	if !n.awaitApplied(answer.Index, time.Until(deadline)) {
		return Result{}, fmt.Errorf("cds-ha: the write is committed at index %d, and this replica has not applied it", answer.Index)
	}
	var res Result
	return res, decodeStrict(answer.Result, &res)
}

// refusedByLeader is the leader's refusal as the forwarding replica's own
// error, a capacity refusal included.
func refusedByLeader(answer controlAnswer) error {
	if answer.Full {
		return fmt.Errorf("%w: the leader refused the write: %s", ErrCapacity, answer.Err)
	}
	return errors.New("cds-ha: the leader refused the write: " + answer.Err)
}

// answerWrite commits a write another replica took, under this leader's own
// judgement and clock. Every admitted peer may forward one.
func (n *Node) answerWrite(forwarded json.RawMessage, answer controlAnswer) controlAnswer {
	if !n.leading() {
		return n.redirectToLeader(answer)
	}
	entry, err := forwardedWrite(forwarded)
	if err != nil {
		answer.Err = err.Error()
		return answer
	}
	stamped, err := json.Marshal(underLeaderClock(entry))
	if err != nil {
		answer.Err = err.Error()
		return answer
	}
	// The forwarding replica judged the cap against its own copy of the
	// state; the leader judges the bytes it is about to commit.
	if err := n.proposable(entry, stamped); err != nil {
		answer.Err = err.Error()
		answer.Full = errors.Is(err, ErrCapacity)
		return answer
	}
	return n.commitForwarded(stamped, answer)
}

func (n *Node) commitForwarded(stamped []byte, answer controlAnswer) controlAnswer {
	res, index, err := n.commit(stamped)
	if err != nil {
		answer.Err = err.Error()
		return answer
	}
	result, err := json.Marshal(res)
	if err != nil {
		slog.Error("cds-ha: this leader committed a forwarded write and could not report what it produced", "index", index, "error", err)
		answer.Err = "the write is committed and this leader cannot report what it produced"
		return answer
	}
	answer.Index = index
	answer.Result = result
	return answer
}

// forwardedWrite is the entry a replica may forward: one client write of one
// store. An entry the state machine cannot read would stop every replica
// once committed.
func forwardedWrite(forwarded json.RawMessage) (Entry, error) {
	var entry Entry
	if err := decodeStrict(forwarded, &entry); err != nil {
		return Entry{}, fmt.Errorf("cds-ha: a forwarded entry: %w", err)
	}
	if !clientWrite(entry) {
		return Entry{}, fmt.Errorf("cds-ha: a forwarded entry is one allowlist, secret or binding command, and this one is of kind %q", entry.Kind)
	}
	return entry, nil
}

// clientWrite carries exactly the one store command its kind names, and
// nothing that is the leader's own.
func clientWrite(entry Entry) bool {
	if leadersOwn(entry) {
		return false
	}
	switch entry.Kind {
	case KindAllowlist:
		return entry.Allowlist != nil && entry.Secret == nil && entry.Binding == nil
	case KindSecret:
		return entry.Secret != nil && entry.Allowlist == nil && entry.Binding == nil
	case KindBinding:
		return entry.Binding != nil && entry.Allowlist == nil && entry.Secret == nil
	}
	return false
}

// leadersOwn is an entry only the cluster's leader writes.
func leadersOwn(entry Entry) bool {
	return entry.Format != 0 || entry.SetFormat != 0 || entry.Decree != nil || entry.Doubt != nil
}

// underLeaderClock stamps the entry with the cluster's one clock: a binding's
// expiry and an allowlist write's journal time.
func underLeaderClock(entry Entry) Entry {
	now := time.Now().UnixMilli()
	switch entry.Kind {
	case KindBinding:
		entry.Binding.AtMS = now
	case KindAllowlist:
		entry.Allowlist.AtMS = now
	}
	return entry
}
