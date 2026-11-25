package taha

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
)

// Run reads the store every T/2, so an idle replica still writes it forward
// and notices another chain in it, and checks its own build.
func (r *Replica) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Gossip / 2)
	defer ticker.Stop()
	for {
		_, _ = r.refresh(ctx)
		r.checkBuild(ctx)
		r.findChain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkBuild holds this replica's own attestation to each accepted build
// not judged yet. A check that gets no answer is retried and evicts nothing.
// SelfCheck asks the attestation API, which may take its whole request
// timeout, far longer than T: it runs without r.mu (Replica.mu), so reads and
// gossip answers never wait for it.
func (r *Replica) checkBuild(ctx context.Context) {
	for _, m := range r.unjudged() {
		ok, err := r.cfg.SelfCheck(ctx, m)
		if err != nil {
			slog.Warn("Trust Authority replica cannot check its own build yet", "error", err)
			continue
		}
		r.judge(m, ok)
	}
}

// unjudged is the measurements of every accepted build this replica has
// not held its own attestation to yet.
func (r *Replica) unjudged() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return nil
	}
	var todo []string
	for _, b := range r.state.Accepted {
		if _, judged := r.own[b.Measurements]; !judged {
			todo = append(todo, b.Measurements)
		}
	}
	return todo
}

// judge records whether this replica's own attestation passes measurements.
func (r *Replica) judge(measurements string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.own[measurements] = ok
}

// Pending is what a replica that holds no chain publishes: its member key
// and the CA key a genesis would name.
type Pending struct {
	Cluster   string   `json:"cluster"`
	Endpoints []string `json:"endpoints"`
	CAKey     string   `json:"ca_key"`
	Member    string   `json:"member"`
}

// findChain records whether the store of a replica that holds no chain
// already holds one: it then waits for a giver and is no genesis.
func (r *Replica) findChain(ctx context.Context) {
	r.mu.Lock()
	st, pending := r.store, r.state == nil
	r.mu.Unlock()
	if !pending || st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
	defer cancel()
	head, err := st.GetHead(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil && head != nil && r.state == nil {
		r.joining = true
	}
}

// Pending is nil once the replica holds a chain, or (genesis) found one in
// the store.
func (r *Replica) Pending(genesis bool) (*Pending, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != nil || (genesis && r.joining) {
		return nil, nil
	}
	ca, err := cdschain.PublicKeyPEM(r.cfg.Mesh.Current().CA.Key.Public())
	return &Pending{
		Cluster:   r.cfg.Cluster,
		Endpoints: r.cfg.Endpoints,
		CAKey:     ca,
		Member:    r.memberPEM,
	}, err
}

// Handoff is the chain a pending replica starts from.
type Handoff struct {
	Entries []cdschain.Entry `json:"entries"`
}

// round asks the other members for their heads. This replica does not
// gossip yet, so none answers and a write is done only in a set of one.
func (r *Replica) round(context.Context) map[int]cdschain.Head { return nil }

// Start makes a pending replica a member by a genesis, which its own CA must
// be the one of. The chain must start at a genesis signed by a launch
// operator key, for this cluster and endpoints, and name this replica's
// member key at its slot.
func (r *Replica) Start(h Handoff) error {
	if r.slot() < 0 {
		return fmt.Errorf("%w: this replica has not learnt its slot yet", ErrUnavailable)
	}
	state, err := cdschain.Verify(h.Entries)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	switch {
	case h.Entries[0].VerifySignature(r.cfg.OperatorKeys) != nil:
		return fmt.Errorf("%w: the genesis is not signed by a launch operator key", ErrInvalid)
	case state.Cluster != r.cfg.Cluster || !slices.Equal(state.Endpoints, r.cfg.Endpoints):
		return fmt.Errorf("%w: the chain is of another cluster or endpoint list", ErrInvalid)
	case state.Members[r.slot()] != r.memberPEM:
		return fmt.Errorf("%w: the chain does not name this replica the member of slot %d", ErrInvalid, r.slot())
	case !state.CAKey.Equal(r.cfg.Mesh.Current().CA.Key.Public()):
		return fmt.Errorf("%w: the genesis names another CA key", ErrInvalid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != nil || r.joining {
		return ErrNotPending
	}
	r.chain, r.state = h.Entries, state
	r.adoptedLocked()
	slog.Info("Trust Authority replica holds the chain", "audit", true, "head", state.Head.Seq, "genesis", state.Genesis)
	return nil
}

// ErrNotPending is a genesis or handoff to a replica that holds a chain.
var ErrNotPending = errors.New("the replica already holds a chain")

// SetCredential installs the Kubernetes store credential.
func (r *Replica) SetCredential(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setCredentialLocked(data)
}

func (r *Replica) setCredentialLocked(data []byte) error {
	store, err := OpenKube(data, r.cfg.Cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.store, r.credential = store, bytes.Clone(data)
	return nil
}
