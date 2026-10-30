package cdsha

import (
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// Policy is the limits every replica applies commands under: a sandbox
// binding's lifetime and the ledger's capacity, and the secret store's path,
// holder and value bounds. The Genesis decree fixes them for the cluster's
// life, so a replica whose stores hold other limits cannot apply the log and
// is refused before it changes any state.
type Policy struct {
	LedgerTTLNS         int64 `json:"ledger_ttl_ns"`
	LedgerMax           int   `json:"ledger_max"`
	SecretsMaxPaths     int   `json:"secrets_max_paths"`
	SecretsMaxPerHolder int   `json:"secrets_max_per_holder"`
	SecretsMaxValue     int   `json:"secrets_max_value"`
}

// ErrPolicy is a cluster whose policy this replica's stores do not hold.
var ErrPolicy = errors.New("cds-ha: the cluster's policy is not this replica's")

// LocalPolicy is the limits this replica's own stores hold.
func (f *FSM) LocalPolicy() Policy {
	ttl, max := f.ledger.Policy()
	paths, perHolder, value := f.secrets.Policy()
	return Policy{
		LedgerTTLNS:         int64(ttl),
		LedgerMax:           max,
		SecretsMaxPaths:     paths,
		SecretsMaxPerHolder: perHolder,
		SecretsMaxValue:     value,
	}
}

// checkPolicy refuses a cluster policy this replica's stores do not hold.
func (f *FSM) checkPolicy(p Policy) error {
	if local := f.LocalPolicy(); p != local {
		return fmt.Errorf("%w: the cluster applies commands under %+v, and this replica holds %+v", ErrPolicy, p, local)
	}
	return nil
}

// checkEstablishedPolicy refuses an entry a replica would apply under limits
// its stores do not hold. The entries that bring a policy with them validate
// their own (applyDecree, applyRestore), and a replica holding no cluster has
// nothing else to apply an entry against.
func (f *FSM) checkEstablishedPolicy(e Entry) error {
	f.mu.RLock()
	core := f.core
	f.mu.RUnlock()
	switch {
	case fixesPolicy(e):
		return nil
	case !core.Joined():
		return errors.New("cds-ha: this replica holds no cluster to apply the entry to")
	}
	return f.checkPolicy(core.Policy)
}

// fixesPolicy reports the entries that bring a cluster's policy with them:
// the Genesis that fixes it, and the Restore that brings back the policy of
// the cluster whose state it restores.
func fixesPolicy(e Entry) bool {
	if e.Kind == KindRestore {
		return e.Restore != nil
	}
	return e.Kind == KindDecree && e.Decree != nil && e.Decree.kind() == cdsdecree.Genesis
}
