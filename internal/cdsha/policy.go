package cdsha

import (
	"errors"
	"fmt"
)

// FSMPolicy is the immutable, comparable policy governing replicated decisions.
// TTL is in nanoseconds, preserving the ledger's exact time.Duration.
// Version zero (including an absent policy) is never a valid policy.
// Numeric settings retain their exact constructor semantics: zero and negative
// limits are not normalized or interpreted as unlimited here.
type FSMPolicy struct {
	Version             uint32 `json:"version"`
	LedgerTTLNS         int64  `json:"ledger_ttl_ns"`
	LedgerMax           int    `json:"ledger_max"`
	SecretsMaxPaths     int    `json:"secrets_max_paths"`
	SecretsMaxPerHolder int    `json:"secrets_max_per_holder"`
	SecretsMaxValue     int    `json:"secrets_max_value"`
}

// ErrPolicy reports an absent, unsupported, or locally incompatible FSM policy.
var ErrPolicy = errors.New("cds-ha: incompatible FSM policy")

// Validate rejects absent or unsupported policy schemas.
func (p FSMPolicy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("%w: policy version %d, require 1", ErrPolicy, p.Version)
	}
	return nil
}

// LocalPolicy returns a value copy of the local stores' immutable settings.
// It must never substitute for the policy persisted by Genesis.
func (f *FSM) LocalPolicy() FSMPolicy {
	ttl, max := f.ledger.Policy()
	paths, holder, value := f.secrets.Policy()
	return FSMPolicy{Version: 1, LedgerTTLNS: int64(ttl), LedgerMax: max,
		SecretsMaxPaths: paths, SecretsMaxPerHolder: holder, SecretsMaxValue: value}
}

// ValidatePolicy checks a persisted or advertised policy against local settings.
func (f *FSM) ValidatePolicy(p FSMPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if local := f.LocalPolicy(); p != local {
		return fmt.Errorf("%w: persisted %+v, local %+v", ErrPolicy, p, local)
	}
	return nil
}
