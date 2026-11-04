package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

const maxRegistrationBytes = 128 << 10

// Enrollment is custodian-owned policy, never supplied by a recovery relay.
// Pins uses the existing refvalues document format, with exact launch bindings.
type Enrollment struct {
	Identity Identity `json:"identity"`
	Pins     []byte   `json:"pins"`
	Origins  []string `json:"origins"`
}

type registration struct {
	Version   int        `json:"version"`
	Policy    Enrollment `json:"policy"`
	Genesis   []byte     `json:"genesis_request_hash"`
	KeyHash   []byte     `json:"key_sha256"`
	Signature []byte     `json:"signature"`
}

func registrationBytes(r registration) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("c8s/cds-recovery/registration/v1\x00"), b...)
}

func (p Enrollment) targets(verifier string) (map[string]Target, error) {
	if len(p.Pins) == 0 || len(p.Pins) > 64<<10 || len(p.Origins) == 0 || len(p.Origins) > 128 {
		return nil, errors.New("recovery: bounded pins and replica origins required")
	}
	pins, err := refvalues.Parse(p.Pins)
	if err != nil {
		return nil, errors.New("recovery: invalid image policy")
	}
	targets := make(map[string]Target, len(p.Origins))
	for _, origin := range p.Origins {
		target := Target{Origin: origin, Images: pins.Policy().Images, AttestationURL: verifier}
		if len(origin) > 2048 {
			return nil, errors.New("recovery: invalid replica origin")
		}
		if err := checkTarget(p.Identity, target); err != nil {
			return nil, err
		}
		if _, exists := targets[origin]; exists {
			return nil, errors.New("recovery: duplicate replica origin")
		}
		targets[origin] = target
	}
	return targets, nil
}

// Enroll binds initialization to one freshly attested process. The custodian
// must durably retain the returned signed public record BEFORE granting a key.
// Missing registration is an error on recovery, never a reason to re-enroll.
// No grant is issued here, and no secret is serialized into the record.
func Enroll(ctx context.Context, policy Enrollment, genesisOrigin, verifier string, key []byte, signer ed25519.PrivateKey) ([]byte, error) {
	if len(key) != 32 || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("recovery: invalid custody material")
	}
	targets, err := policy.targets(verifier)
	if err != nil {
		return nil, err
	}
	target, exists := targets[genesisOrigin]
	if !exists {
		return nil, errors.New("recovery: initial origin is not approved")
	}
	q, err := fetchRecipient(ctx, policy.Identity, target)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(key)
	r := registration{Version: 1, Policy: policy, Genesis: requestHash(q), KeyHash: hash[:]}
	r.Signature = ed25519.Sign(signer, registrationBytes(r))
	b, err := json.Marshal(r)
	if err != nil || len(b) > maxRegistrationBytes {
		return nil, errors.New("recovery: registration too large")
	}
	return b, nil
}

// Authority holds one cluster's immutable release policy and a bounded actor
// admission queue. It has no issued/genesis flag, mutable policy API or storage
// head. Its hosting TEE and external custodian must protect the supplied keys.
// Constructing this object in an ordinary process provides no hardware custody.
type Authority struct {
	identity Identity
	targets  map[string]Target // immutable after construction
	genesis  []byte
	key      []byte
	signer   ed25519.PrivateKey
	gate     *requestgate.Gate
	ctx      context.Context
	cancel   context.CancelFunc
	closing  atomic.Bool
	done     chan struct{}
}

// NewAuthority restores an already enrolled cluster. Neither a caller's
// destination nor a recovery request can change its pins, identity or initial
// recipient. Authentication of the record is independent of where it is stored.
func NewAuthority(parent context.Context, expected Identity, record, key []byte, signer ed25519.PrivateKey, verifier string) (*Authority, error) {
	r, err := checkRegistration(expected, record, key, signer)
	if err != nil {
		return nil, err
	}
	targets, err := r.Policy.targets(verifier)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	gate, err := requestgate.New(ctx, 4, 16)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Authority{identity: r.Policy.Identity, targets: targets, genesis: r.Genesis,
		key: bytes.Clone(key), signer: bytes.Clone(signer), gate: gate, ctx: ctx, cancel: cancel, done: make(chan struct{})}, nil
}

func checkRegistration(expected Identity, record, key []byte, signer ed25519.PrivateKey) (registration, error) {
	if len(record) == 0 || len(record) > maxRegistrationBytes || len(key) != 32 || len(signer) != ed25519.PrivateKeySize {
		return registration{}, errors.New("recovery: existing registration and custody material required")
	}
	if strictjson.Validate(record) != nil {
		return registration{}, errors.New("recovery: invalid registration JSON")
	}
	var r registration
	if err := decode(record, &r); err != nil {
		return registration{}, errors.New("recovery: invalid registration")
	}
	if r.Policy.Identity != expected {
		return registration{}, errors.New("recovery: registration belongs to another custody identity")
	}
	hash := sha256.Sum256(key)
	if r.Version != 1 || len(r.Genesis) != sha512.Size384 || len(r.KeyHash) != sha256.Size ||
		subtle.ConstantTimeCompare(r.KeyHash, hash[:]) != 1 || !ed25519.Verify(signer.Public().(ed25519.PublicKey), registrationBytes(r), r.Signature) {
		return registration{}, errors.New("recovery: registration or custody key mismatch")
	}
	return r, nil
}

// Release accepts only an enrolled origin. It fetches fresh evidence itself;
// request hashes, image pins and initialization flags are never caller inputs.
func (a *Authority) Release(ctx context.Context, origin string) (*Grant, error) {
	target, exists := a.targets[origin]
	if !exists {
		return nil, errors.New("recovery: replica origin is not approved")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	release, err := a.gate.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	q, err := fetchRecipient(ctx, a.identity, target)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return seal(q, Material{Key: a.key, AllowGenesis: bytes.Equal(a.genesis, requestHash(q))}, a.signer)
}

func (a *Authority) Stats() requestgate.Stats { return a.gate.Stats() }

func (a *Authority) Close() {
	if a.closing.CompareAndSwap(false, true) {
		a.cancel()
		a.gate.Close() // Active releases finish before their key copies are cleared.
		clear(a.key)
		clear(a.signer)
		close(a.done)
	}
	<-a.done
}
