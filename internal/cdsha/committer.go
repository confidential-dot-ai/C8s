package cdsha

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// committer writes one store of this replica through the cluster's log.
type committer[C, R any] struct {
	node        *Node
	entry       func(C) Entry
	answer      func(Result) *R
	uncommitted func(error) error
}

func (c committer[C, R]) Commit(cmd C) (R, error) {
	var none R
	entry := c.entry(cmd)
	res, err := c.node.propose(entry)
	if err != nil {
		return none, c.uncommitted(err)
	}
	answer := c.answer(res)
	if answer == nil {
		return none, answeredNothing(entry.Kind)
	}
	return *answer, nil
}

// storeErrors are the errors one store reports for a write the cluster did
// not take: unavailable is retryable, full clears as the replicated state
// shrinks.
type storeErrors struct {
	unavailable error
	full        error
}

func (e storeErrors) uncommitted(err error) error {
	if errors.Is(err, ErrCapacity) {
		return fmt.Errorf("%w: %w", e.full, err)
	}
	return fmt.Errorf("%w: %w", e.unavailable, err)
}

var allowlistErrors = storeErrors{
	unavailable: allowlist.ErrUnavailable,
	full:        allowlist.ErrCapacity,
}

var secretsErrors = storeErrors{
	unavailable: secrets.ErrUnavailable,
	full:        secrets.ErrCapacity,
}

// unchanged is the uncommitted error of a store with no error of its own.
func unchanged(err error) error {
	return err
}

func allowlistWrites(n *Node) committer[allowlist.Command, allowlist.Result] {
	return committer[allowlist.Command, allowlist.Result]{
		node: n,
		entry: func(cmd allowlist.Command) Entry {
			return Entry{
				Kind:      KindAllowlist,
				Allowlist: &cmd,
			}
		},
		answer: func(res Result) *allowlist.Result {
			return res.Allowlist
		},
		uncommitted: allowlistErrors.uncommitted,
	}
}

func secretWrites(n *Node) committer[secrets.Command, secrets.Result] {
	return committer[secrets.Command, secrets.Result]{
		node: n,
		entry: func(cmd secrets.Command) Entry {
			return Entry{
				Kind:   KindSecret,
				Secret: &cmd,
			}
		},
		answer: func(res Result) *secrets.Result {
			return res.Secret
		},
		uncommitted: secretsErrors.uncommitted,
	}
}

// ledgerCommitter is the sandbox ledger's committer, whose lookups catch up
// with the cluster.
type ledgerCommitter struct {
	committer[sandboxledger.Command, sandboxledger.Held]
}

func bindingWrites(n *Node) ledgerCommitter {
	return ledgerCommitter{
		committer[sandboxledger.Command, sandboxledger.Held]{
			node: n,
			entry: func(cmd sandboxledger.Command) Entry {
				return Entry{
					Kind:    KindBinding,
					Binding: &cmd,
				}
			},
			answer: func(res Result) *sandboxledger.Held {
				return res.Binding
			},
			uncommitted: unchanged,
		},
	}
}

// CatchUp applies what this replica knows the cluster has committed. A
// replica that does not get there answers from the bindings it holds, which
// fails closed.
func (c ledgerCommitter) CatchUp() {
	if !c.node.appliedKnownCommitted(c.node.cfg.Timing.Apply) {
		slog.Warn("cds-ha: a sandbox lookup did not catch up with the cluster's log; it answers from the bindings this replica holds")
	}
}

// answeredNothing: the entry is applied, so no writer may send it again.
func answeredNothing(kind EntryKind) error {
	return fmt.Errorf("cds-ha: the committed %s entry answered nothing", kind)
}
