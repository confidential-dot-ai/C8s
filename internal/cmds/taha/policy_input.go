package taha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

type policyTarget struct {
	cluster string
	genesis cdschain.Hash
	head    cdschain.Head
}

func (p policyTarget) check(state *cdschain.State) error {
	switch {
	case state.Cluster != p.cluster:
		return fmt.Errorf("the replica serves cluster %q, not --cluster %q", state.Cluster, p.cluster)
	case state.Genesis != p.genesis:
		return fmt.Errorf("the replica's genesis %s does not match --genesis %s", state.Genesis, p.genesis)
	case state.Head.Seq != p.head.Seq || state.Head.Hash != p.head.Hash:
		return fmt.Errorf("the replica's head %d:%s does not match --expect-head %d:%s", state.Head.Seq, state.Head.Hash, p.head.Seq, p.head.Hash)
	}
	return nil
}

// maxPolicyBytes bounds the reviewed policy input before entry encoding.
const maxPolicyBytes = 1 << 20

func readPreparedPolicy(path, digest string) ([]byte, error) {
	expected, err := cdschain.ParseHash(digest)
	if err != nil {
		return nil, fmt.Errorf("--policy-sha256: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy exceeds %d bytes", maxPolicyBytes)
	}
	if cdschain.Hash(sha256.Sum256(data)) != expected {
		return nil, errors.New("policy file does not match --policy-sha256")
	}
	doc, err := allowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("policy file: %w", err)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("policy file is not canonical; review canonical bytes and their SHA-256 before preparing")
	}
	return data, nil
}

func readSubmittedPolicy(path string, target policyTarget) ([]byte, cdschain.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cdschain.Entry{}, err
	}
	defer f.Close()
	encoded, err := io.ReadAll(io.LimitReader(f, cdschain.MaxEntryBytes+1))
	if err != nil {
		return nil, cdschain.Entry{}, err
	}
	entry, err := cdschain.ParseEntry(encoded)
	if err != nil {
		return nil, cdschain.Entry{}, err
	}
	body, err := entry.Decode()
	if err != nil {
		return nil, cdschain.Entry{}, err
	}
	if body.Type != cdschain.TypePolicy || body.Seq == 0 {
		return nil, cdschain.Entry{}, errors.New("--file must contain a policy entry after genesis")
	}
	if body.Cluster != target.cluster || body.Seq-1 != target.head.Seq || body.Prev != target.head.Hash {
		return nil, cdschain.Entry{}, errors.New("the artifact does not match --cluster and --expect-head")
	}
	return encoded, entry, nil
}

type policyHistory struct {
	state   *cdschain.State
	entries []cdschain.Entry
	entry   cdschain.Head
}

// readPolicy replays history; today's keys cannot authorize an old entry.
func (w *writer) readPolicy(ctx context.Context, target policyTarget, entry cdschain.Entry) (*policyHistory, error) {
	records, err := w.o.records()
	if err != nil {
		return nil, err
	}
	entries, err := haapi.ReadChain(ctx, w.client, w.url, 0)
	if err != nil {
		return nil, fmt.Errorf("reading the replica's chain: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("the replica serves no chain")
	}
	state, err := cdschain.VerifyGenesis(entries[0])
	if err != nil {
		return nil, err
	}
	predecessor := state
	for _, e := range entries[1:] {
		if state, err = state.Apply(e); err != nil {
			return nil, err
		}
		if state.Head.Seq <= target.head.Seq {
			predecessor = state
		}
	}
	if err := target.check(predecessor); err != nil {
		return nil, err
	}
	if rec := records[target.cluster]; rec != nil {
		if rec.Genesis != target.genesis {
			return nil, fmt.Errorf("--genesis is %s, recorded %s; after a re-root, remove the record", target.genesis, rec.Genesis)
		}
		if rec.Acknowledged.Seq >= uint64(len(entries)) || entries[rec.Acknowledged.Seq].Hash() != rec.Acknowledged.Hash {
			return nil, fmt.Errorf("the replica serves a chain without head %d, which was acknowledged before this read: the chain was rolled back, or the replica is behind", rec.Acknowledged.Seq)
		}
	}
	candidate, err := predecessor.Apply(entry)
	if err != nil {
		return nil, fmt.Errorf("the entry does not verify against its predecessor: %w", err)
	}
	if candidate.Head.Seq < uint64(len(entries)) {
		held := entries[candidate.Head.Seq]
		if !bytes.Equal(held.Body, entry.Body) || held.Sig != entry.Sig {
			return nil, fmt.Errorf("the replica holds different bytes at the artifact's position: %w", errHeadMoved)
		}
	}
	return &policyHistory{
		state:   state,
		entries: entries,
		entry:   candidate.Head,
	}, nil
}
