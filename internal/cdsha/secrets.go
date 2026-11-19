package cdsha

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A replica set keeps operator secrets: a secret entry names the hash of a
// value sealed under a key derived from the set's CA key, which every replica
// holds, and the store keeps the sealed value as an entry under that hash.
const (
	secretKeyLabel = "c8s-cds-secrets/v1/"
	secretDomain   = "c8s-cds-secret-v1\x00"
)

func sealedHash(sealed []byte) cdschain.Hash {
	return sha256.Sum256(append([]byte(secretDomain), sealed...))
}

// secretKey is AES-256-GCM under the key derived from the set's CA key.
func (r *Replica) secretKey() (cipher.AEAD, error) {
	ca, err := r.cfg.Mesh.Current().CA.Key.ECDH()
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, ca.Bytes(), nil, secretKeyLabel+r.cfg.Cluster, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal seals value for path and keeps it in the store. Nothing releases it
// until a secret entry names the hash it returns.
func (r *Replica) Seal(ctx context.Context, path string, value []byte) (string, error) {
	aead, err := r.secretKey()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	st := r.store
	r.mu.Unlock()
	if st == nil {
		return "", fmt.Errorf("%w: the store is unreachable: no store credential yet", ErrUnavailable)
	}
	sealed := aead.Seal(nil, nil, value, []byte(path))
	h := sealedHash(sealed)
	ctx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
	defer cancel()
	return h.String(), st.PutEntry(ctx, h, sealed)
}

// Secrets is the secret store of a replica set: it releases the value the
// newest secret entry of a path names, and generates none.
func (r *Replica) Secrets() secrets.Store { return setSecrets{r} }

type setSecrets struct{ r *Replica }

// Get releases a value only if the store's bytes hash to the one the served
// chain names for path and open under the set's key.
func (s setSecrets) Get(ctx context.Context, path string) ([]byte, error) {
	state, err := s.r.Current(ctx)
	if err != nil {
		return nil, err
	}
	h, ok := state.Secrets[path]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	s.r.mu.Lock()
	st := s.r.store
	s.r.mu.Unlock()
	sctx, cancel := context.WithTimeout(ctx, s.r.cfg.StoreTimeout)
	defer cancel()
	sealed, err := st.GetEntry(sctx, h)
	if err != nil {
		return nil, err
	}
	if sealedHash(sealed) != h {
		return nil, fmt.Errorf("the store does not hold the value the chain names for %s", path)
	}
	aead, err := s.r.secretKey()
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, sealed, []byte(path))
}

// PutIfAbsent generates nothing: a path the operator wrote is held, any
// other is refused.
func (s setSecrets) PutIfAbsent(ctx context.Context, path string, _ []byte, _ secrets.Holder) ([]byte, secrets.Held, error) {
	_, err := s.Get(ctx, path)
	if errors.Is(err, secrets.ErrNotFound) {
		return nil, secrets.Held{}, secrets.ErrOperatorOnly
	}
	return nil, secrets.Held{Exists: err == nil, Origin: secrets.OriginOperator}, err
}

// Put: an operator writes a set's secrets as entries (Seal).
func (setSecrets) Put(context.Context, string, []byte) (secrets.Held, error) {
	return secrets.Held{}, errors.New("a replica set takes secrets as chain entries")
}

func (setSecrets) TopHolders(int) []secrets.HolderPaths { return nil }
