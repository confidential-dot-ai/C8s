// Package cdsdirect adapts CDS's rules to encrypted current-state transactions.
// It is a separate experimental backend, with no Raft or object-WAL instance.
package cdsdirect

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

const (
	coreKey   = "identity"
	policyKey = "policy"
	ledgerKey = "bindings"
	countKey  = "secret-count"
)

type State struct {
	store  *directstate.Store
	launch cdsha.Launch
	policy cdsha.Policy
}

func NewState(store *directstate.Store, launch cdsha.Launch, policy cdsha.Policy) *State {
	return &State{store: store, launch: launch, policy: policy}
}

type policyRecord struct {
	Encoding string   `json:"encoding,omitempty"`
	Image    []byte   `json:"image"`
	Digest   [32]byte `json:"digest"`
}

// Bound decompression independently of the ciphertext/read budget. Existing
// uncompressed pilot records remain readable; unknown encodings fail closed.
func (p policyRecord) open() ([]byte, error) {
	if p.Encoding == "" {
		if len(p.Image) > directstate.MaxValueBytes {
			return nil, objectwal.ErrCorrupt
		}
		return bytes.Clone(p.Image), nil
	}
	if p.Encoding != "gzip" {
		return nil, objectwal.ErrCorrupt
	}
	r, err := gzip.NewReader(bytes.NewReader(p.Image))
	if err != nil {
		return nil, objectwal.ErrCorrupt
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, directstate.MaxValueBytes+1))
	if err != nil || len(out) > directstate.MaxValueBytes {
		clear(out)
		return nil, objectwal.ErrCorrupt
	}
	return out, nil
}

func decode(b []byte, value any) error {
	if strictjson.Validate(b) != nil {
		return objectwal.ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return objectwal.ErrCorrupt
	}
	return nil
}

func (s *State) core(v *directstate.View) (cdsha.CurrentCore, *issuer.CA, error) {
	b, exists := v.Get(coreKey)
	if !exists {
		return cdsha.CurrentCore{}, nil, errors.New("direct state: waiting for signed Genesis")
	}
	var core cdsha.CurrentCore
	if err := decode(b, &core); err != nil {
		return core, nil, err
	}
	ca, err := core.Open(s.launch, s.policy)
	clear(core.MeshCAKey)
	core.MeshCAKey = nil
	return core, ca, err
}

func (s *State) Core(ctx context.Context) (cdsha.CurrentCore, *issuer.CA, error) {
	v, err := s.store.Read(ctx, coreKey)
	if err != nil {
		return cdsha.CurrentCore{}, nil, err
	}
	defer v.Clear()
	return s.core(v)
}

func (s *State) machine(v *directstate.View) (*cdsha.FSM, *allowlist.Store, *sandboxledger.Ledger, error) {
	al, err := allowlist.OpenInMemory()
	if err != nil {
		return nil, nil, nil, err
	}
	failed := func(err error) (*cdsha.FSM, *allowlist.Store, *sandboxledger.Ledger, error) {
		al.Close()
		return nil, nil, nil, err
	}
	if b, ok := v.Get(policyKey); ok {
		var p policyRecord
		if err := decode(b, &p); err != nil {
			return failed(err)
		}
		defer clear(p.Image)
		image, err := p.open()
		if err != nil {
			return failed(err)
		}
		defer clear(image)
		if err := al.Restore(image, p.Digest); err != nil {
			return failed(err)
		}
	}
	led := sandboxledger.New(time.Duration(s.policy.LedgerTTLNS), s.policy.LedgerMax)
	sec := secrets.NewMemoryStore(s.policy.SecretsMaxPaths, s.policy.SecretsMaxPerHolder, s.policy.SecretsMaxValue)
	f := cdsha.NewFSM(s.launch, al, sec, led)
	if b, ok := v.Get(coreKey); ok {
		var core cdsha.CurrentCore
		if err := decode(b, &core); err != nil {
			return failed(err)
		}
		defer clear(core.MeshCAKey)
		if err := f.RestoreCurrentCore(core); err != nil {
			return failed(err)
		}
	} else if _, exists := v.Get(policyKey); exists {
		return failed(objectwal.ErrCorrupt)
	}
	return f, al, led, nil
}

func policyBytes(al *allowlist.Store) ([]byte, error) {
	image, err := al.Dump()
	if err != nil {
		return nil, err
	}
	defer clear(image)
	if len(image) > directstate.MaxValueBytes {
		return nil, errors.New("direct state: policy image exceeds decoded size bound")
	}
	// SQLite's sparse pages and repeated schema/history need not make a small
	// policy a large object. Compress policy data only, never secret values or
	// the CA private-key record. Encryption still happens in directstate.
	var compressed bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if _, err := writer.Write(image); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	defer clear(compressed.Bytes())
	return json.Marshal(policyRecord{Encoding: "gzip", Image: compressed.Bytes(), Digest: al.Digest()})
}

func coreBytes(f *cdsha.FSM) ([]byte, error) {
	core, err := f.CurrentCore()
	if err != nil {
		return nil, err
	}
	defer clear(core.MeshCAKey)
	return json.Marshal(core)
}

// ApplyControl evaluates the existing FSM rules in a private disposable
// machine, then publishes ONLY the affected current records. It never writes
// commands to durable storage or reconstructs state by replaying them.
func (s *State) ApplyControl(ctx context.Context, e cdsha.Entry) (cdsha.Result, error) {
	if e.Kind != cdsha.KindDecree && e.Kind != cdsha.KindRenewCA && e.Kind != cdsha.KindAllowlist {
		return cdsha.Result{}, errors.New("direct state: unsupported control transition")
	}
	answer, err := s.store.Update(ctx, policyKey, []string{coreKey, policyKey}, func(v *directstate.View) (map[string][]byte, any, error) {
		f, al, _, err := s.machine(v)
		if err != nil {
			return nil, nil, err
		}
		defer al.Close()
		before := al.Digest()
		body, err := json.Marshal(e)
		if err != nil {
			return nil, nil, err
		}
		defer clear(body)
		r := f.Apply(1, body)
		if r.Stop != nil {
			return nil, nil, r.Stop
		}
		writes := map[string][]byte{}
		if e.Kind == cdsha.KindDecree || e.Kind == cdsha.KindRenewCA {
			if r.Decree == nil || r.Decree.Refused == "" {
				b, err := coreBytes(f)
				if err != nil {
					return nil, nil, err
				}
				writes[coreKey] = b
			}
		}
		if al.Digest() != before {
			b, err := policyBytes(al)
			if err != nil {
				for _, b := range writes {
					clear(b)
				}
				return nil, nil, err
			}
			writes[policyKey] = b
		}
		return writes, r, nil
	})
	if err != nil {
		return cdsha.Result{}, err
	}
	return answer.(cdsha.Result), nil
}

func (s *State) ReadPolicy(ctx context.Context) (*allowlist.Store, error) {
	v, err := s.store.Read(ctx, coreKey, policyKey)
	if err != nil {
		return nil, err
	}
	defer v.Clear()
	if _, _, err := s.core(v); err != nil {
		return nil, err
	}
	_, al, _, err := s.machine(v)
	return al, err // Caller closes its private SQLite view after use.
}
