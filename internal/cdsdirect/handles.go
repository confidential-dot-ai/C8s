package cdsdirect

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type policyReader struct{ n *Node }

func (r policyReader) open() (*allowlist.Store, error) {
	s, err := r.n.readyState()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.n.ctx, timeout)
	defer cancel()
	return s.ReadPolicy(ctx)
}
func (r policyReader) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	s, err := r.open()
	if err != nil {
		return nil, "", err
	}
	defer s.Close()
	return s.LoadAll()
}
func (r policyReader) Version() (string, error) {
	s, err := r.open()
	if err != nil {
		return "", err
	}
	defer s.Close()
	return s.Version()
}
func (r policyReader) History() ([]allowlist.HistoryEntry, error) {
	s, err := r.open()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.History()
}
func (r policyReader) Object(digest string) ([]byte, bool, error) {
	s, err := r.open()
	if err != nil {
		return nil, false, err
	}
	defer s.Close()
	return s.Object(digest)
}
func (r policyReader) Signature(digest string) (string, bool, error) {
	s, err := r.open()
	if err != nil {
		return "", false, err
	}
	defer s.Close()
	return s.Signature(digest)
}
func (r policyReader) LoadRoutes() (routes.Envelope, error) {
	s, err := r.open()
	if err != nil {
		return routes.Envelope{}, err
	}
	defer s.Close()
	return s.LoadRoutes()
}
func (r policyReader) Contains(d types.Digest) (bool, error) {
	s, err := r.open()
	if err != nil {
		return false, err
	}
	defer s.Close()
	return s.Contains(d)
}
func (policyReader) Generation() uint64 { return 0 } // Handle disables local-generation caching.

type allowlistWriter struct{ n *Node }

func (w allowlistWriter) Commit(c allowlist.Command) (allowlist.Result, error) {
	// Authorized PUTs must use WriteOperator, so token and mutation cannot be
	// split by an accidental use of a legacy handle. Startup/maintenance only.
	if c.Op != allowlist.OpSeed && c.Op != allowlist.OpStartJournal && c.Op != allowlist.OpPruneHistory {
		return allowlist.Result{}, errors.New("direct state: signed atomic operator request required")
	}
	s, err := w.n.readyState()
	if err != nil {
		return allowlist.Result{}, err
	}
	ctx, cancel := context.WithTimeout(w.n.ctx, timeout)
	defer cancel()
	r, err := s.ApplyControl(ctx, cdsha.Entry{Kind: cdsha.KindAllowlist, Allowlist: &c})
	if err != nil {
		return allowlist.Result{}, err
	}
	if r.Allowlist == nil {
		return allowlist.Result{}, errors.New("direct state: missing allowlist result")
	}
	return *r.Allowlist, nil
}

type secretReader struct{ n *Node }

func (r secretReader) Get(ctx context.Context, path string) ([]byte, error) {
	s, err := r.n.readyState()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.Secret(ctx, path)
}
func (r secretReader) Len() int {
	s, err := r.n.readyState()
	if err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(r.n.ctx, timeout)
	defer cancel()
	v, err := s.store.Read(ctx, countKey)
	if err != nil {
		return 0
	}
	defer v.Clear()
	n, _ := count(v, countKey, s.policy.SecretsMaxPaths)
	return n
}

// Holder enumeration is diagnostic only and requires a separate bounded
// index. Do not reconstruct every secret merely to report a metric.
func (secretReader) TopHolders(int) []secrets.HolderPaths { return nil }

type secretWriter struct{ n *Node }

func (w secretWriter) Commit(c secrets.Command) (secrets.Result, error) {
	s, err := w.n.readyState()
	if err != nil {
		return secrets.Result{}, err
	}
	ctx, cancel := context.WithTimeout(w.n.ctx, timeout)
	defer cancel()
	return s.WriteSecret(ctx, c)
}

type bindingWriter struct{ n *Node }

func (bindingWriter) CatchUp() {} // Each lookup below reads current state.
func (w bindingWriter) Commit(c sandboxledger.Command) (sandboxledger.Held, error) {
	s, err := w.n.readyState()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(w.n.ctx, timeout)
	defer cancel()
	answer, err := s.store.Update(ctx, ledgerKey, []string{coreKey, ledgerKey}, func(v *directstate.View) (map[string][]byte, any, error) {
		if _, _, err := s.core(v); err != nil {
			return nil, nil, err
		}
		l, err := s.ledger(v)
		if err != nil {
			return nil, nil, err
		}
		before := l.Digest()
		held := l.Apply(c)
		if l.Digest() == before {
			return nil, held, nil
		}
		b, err := json.Marshal(l.Dump())
		return map[string][]byte{ledgerKey: b}, held, err
	})
	if err != nil {
		return false, err
	}
	return answer.(sandboxledger.Held), nil
}

// The first pilot retains one bounded binding record to preserve exact expiry
// reclamation and the cluster-wide cap. Worker-join contention is measured
// explicitly; this is not a claim of independently sharded sandbox bindings.
func (s *State) ledger(v *directstate.View) (*sandboxledger.Ledger, error) {
	l := sandboxledger.New(time.Duration(s.policy.LedgerTTLNS), s.policy.LedgerMax)
	if b, exists := v.Get(ledgerKey); exists {
		var bindings []sandboxledger.Binding
		if decode(b, &bindings) != nil || len(bindings) > s.policy.LedgerMax {
			return nil, objectwal.ErrCorrupt
		}
		l.Restore(bindings)
	}
	return l, nil
}

func (n *Node) lookupBinding(id string) (string, bool) {
	s, err := n.readyState()
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	v, err := s.store.Read(ctx, coreKey, ledgerKey)
	if err != nil {
		return "", false
	}
	defer v.Clear()
	if _, _, err := s.core(v); err != nil {
		return "", false
	}
	l, err := s.ledger(v)
	if err != nil {
		return "", false
	}
	return l.Local().Lookup(id)
}
