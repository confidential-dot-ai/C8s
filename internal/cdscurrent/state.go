package cdscurrent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

type snapshot struct {
	Format       int                     `json:"format"`
	CACert       []byte                  `json:"ca_cert"`
	CAKey        []byte                  `json:"ca_key"`
	Policy       []byte                  `json:"policy"`
	PolicyDigest [32]byte                `json:"policy_digest"`
	Secrets      []secrets.SnapshotEntry `json:"secrets"`
	Bindings     []sandboxledger.Binding `json:"bindings"`
	Challenges   map[string]int64        `json:"secret_challenges"`
}

func (s *snapshot) clear() {
	clear(s.CAKey)
	clear(s.Policy)
	for _, entry := range s.Secrets {
		clear(entry.Value)
	}
}

type view struct {
	state   snapshot
	al      *allowlist.Store
	secrets *secrets.MemoryStore
	ledger  *sandboxledger.Ledger
	ca      *issuer.CA
}

func (v *view) close() {
	_ = v.al.Close()
	v.state.clear()
}

func (r *Replica) emptyPolicy() (*allowlist.Store, error) {
	al, err := allowlist.OpenInMemory()
	if err == nil {
		al.SetNodeDelay(r.policy.NodeDelay)
	}
	return al, err
}

func (r *Replica) seal(s snapshot) ([]byte, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain)+r.aead.NonceSize()+r.aead.Overhead() > maxStateBytes {
		return nil, ErrCapacity
	}
	nonce := make(
		[]byte,
		r.aead.NonceSize(),
	)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return r.aead.Seal(
		nonce,
		nonce,
		plain,
		r.domain,
	), nil
}

func (r *Replica) open(encrypted []byte) (*view, error) {
	if len(encrypted) == 0 {
		return nil, ErrUninitialized
	}
	if len(encrypted) > maxStateBytes || len(encrypted) < r.aead.NonceSize()+r.aead.Overhead() {
		return nil, errors.New("current CDS: invalid encrypted state size")
	}
	plain, err := r.aead.Open(
		nil,
		encrypted[:r.aead.NonceSize()],
		encrypted[r.aead.NonceSize():],
		r.domain,
	)
	if err != nil {
		return nil, errors.New("current CDS: state authentication failed")
	}
	defer clear(plain)
	var s snapshot
	transferred := false
	defer func() {
		if !transferred {
			s.clear()
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&s); err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("current CDS: trailing state data")
	}
	if s.Format != 1 || len(s.Secrets) > r.policy.MaxPaths || len(s.Bindings) > maxBindings || len(s.Challenges) > maxChallenges {
		return nil, errors.New("current CDS: unsupported state or exceeded limits")
	}
	for _, entry := range s.Secrets {
		if len(entry.Value) > r.policy.MaxSecretValueBytes {
			return nil, ErrCapacity
		}
	}
	cert, err := x509.ParseCertificate(s.CACert)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(s.CAKey)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("current CDS: CA key is not ECDSA")
	}
	ca, err := issuer.WrapCA(
		cert,
		key,
	)
	if err != nil {
		return nil, err
	}
	al, err := r.emptyPolicy()
	if err != nil {
		return nil, err
	}
	if err = al.Restore(
		s.Policy,
		s.PolicyDigest,
	); err != nil {
		_ = al.Close()
		return nil, err
	}
	sec := secrets.NewMemoryStore(
		r.policy.MaxPaths,
		r.policy.MaxPerHolder,
		r.policy.MaxSecretValueBytes,
	)
	sec.Restore(s.Secrets)
	ledger := sandboxledger.New(
		r.policy.LedgerTTL,
		maxBindings,
	)
	ledger.Restore(s.Bindings)
	if s.Challenges == nil {
		s.Challenges = make(map[string]int64)
	}
	transferred = true
	return &view{
		state:   s,
		al:      al,
		secrets: sec,
		ledger:  ledger,
		ca:      ca,
	}, nil
}

func (r *Replica) capture(v *view) ([]byte, error) {
	image, err := v.al.Dump()
	if err != nil {
		return nil, err
	}
	defer clear(image)
	entries := v.secrets.Dump()
	defer func() {
		for _, entry := range entries {
			clear(entry.Value)
		}
	}()
	s := v.state
	s.Policy, s.PolicyDigest = image, v.al.Digest()
	s.Secrets, s.Bindings = entries, v.ledger.Dump()
	return r.seal(s)
}

func (r *Replica) read(ctx context.Context) (*view, error) {
	encrypted, err := r.register.Read(ctx)
	if err != nil {
		return nil, err
	}
	return r.open(encrypted)
}

func (r *Replica) update(
	ctx context.Context,
	apply func(*view) error,
) ([]byte, error) {
	return r.register.Update(
		ctx,
		func(encrypted []byte) ([]byte, error) {
			v, err := r.open(encrypted)
			if err != nil {
				return nil, err
			}
			defer v.close()
			if err := apply(v); err != nil {
				return nil, err
			}
			return r.capture(v)
		},
	)
}
