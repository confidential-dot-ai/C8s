package cdsha

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const decreeDomain = "c8s-cds-ha-decree-v1\n"

// DecreeKind is the operator intent.
type DecreeKind string

// Decree kinds (§10, plus Genesis).
const (
	UpdateMeasurements DecreeKind = "UpdateMeasurements"
	RotateKey          DecreeKind = "RotateKey"
	// Genesis authorizes minting the first mesh CA key of a chain. It
	// replaces G1's peer-reachability timers, which the host could game
	// through DNS to obtain several genuine keys. base_epoch is 0.
	Genesis DecreeKind = "Genesis"
)

// Decree is an operator intent (D1). It never names a target epoch (D4).
type Decree struct {
	ClusterID    string     `json:"cluster_id"`
	IntentID     string     `json:"intent_id"`
	BaseEpoch    uint64     `json:"base_epoch"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Kind         DecreeKind `json:"kind"`
	Measurements []string   `json:"measurements,omitempty"` // full set (D6); optional for RotateKey (D14)
	// BootstrapNode names the one replica, by node name, that may start the
	// cluster's Raft group for a Genesis decree. Any other replica joins it,
	// so one decree can never start two clusters.
	BootstrapNode string `json:"bootstrap_node,omitempty"`
}

// SignedDecree carries the operator's ECDSA signature over the decree.
type SignedDecree struct {
	Decree    Decree `json:"decree"`
	Signature []byte `json:"signature"`
}

func (d Decree) signedBytes() ([]byte, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append([]byte(decreeDomain), body...), nil
}

// SignDecree signs d with the operator key. Used by the CLI.
func SignDecree(d Decree, key *ecdsa.PrivateKey) (SignedDecree, error) {
	d.Measurements = normalizePins(d.Measurements)
	msg, err := d.signedBytes()
	if err != nil {
		return SignedDecree{}, err
	}
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return SignedDecree{}, err
	}
	return SignedDecree{Decree: d, Signature: sig}, nil
}

// PreGenesis is the state a Genesis decree is checked against: epoch 0, no
// key, the operator key the replica was launched with.
func PreGenesis(clusterID string, operatorPubKey []byte) Core {
	return Core{ClusterID: clusterID, OperatorPubKey: operatorPubKey}
}

// ErrNoOperatorKey rejects every decree in a cluster born without one (G5).
var ErrNoOperatorKey = errors.New("cluster has no operator key")

// CheckDecree applies D3 (plus the cluster_id check D3 omits) against the
// current state, including expiry. Every replica checks it when it applies
// the decree, at the time the leader stamped on the log entry.
func CheckDecree(sd SignedDecree, tail Core, now time.Time) error {
	if err := verifyDecree(sd, tail); err != nil {
		return err
	}
	if !now.Before(sd.Decree.ExpiresAt) {
		return errors.New("decree expired")
	}
	return nil
}

// verifyDecree checks everything in D3 except time. The signature is
// verified before any other field is used.
func verifyDecree(sd SignedDecree, tail Core) error {
	if len(tail.OperatorPubKey) == 0 {
		return ErrNoOperatorKey
	}
	pubAny, err := x509.ParsePKIXPublicKey(tail.OperatorPubKey)
	if err != nil {
		return fmt.Errorf("operator key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("operator key is not ECDSA")
	}
	msg, err := sd.Decree.signedBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], sd.Signature) {
		return errors.New("bad operator signature")
	}
	d := sd.Decree
	switch {
	case d.ClusterID != tail.ClusterID:
		return fmt.Errorf("decree for cluster %q", d.ClusterID)
	case d.IntentID == "":
		return errors.New("empty intent_id")
	case slices.Contains(tail.AppliedDecrees, d.IntentID):
		return errors.New("intent_id already applied")
	case d.BaseEpoch != tail.Epoch:
		return fmt.Errorf("base_epoch %d, current epoch %d", d.BaseEpoch, tail.Epoch)
	case d.Kind == UpdateMeasurements && len(d.Measurements) == 0:
		return errors.New("empty measurement set") // D8
	case d.Kind == Genesis && (len(tail.RootCert) != 0 || len(d.Measurements) != 0):
		return errors.New("a Genesis decree applies only to a cluster without a key, and carries no measurements")
	case d.Kind == Genesis && d.BootstrapNode == "":
		return errors.New("a Genesis decree must name its bootstrap node")
	case d.Kind != Genesis && d.BootstrapNode != "":
		return errors.New("only a Genesis decree names a bootstrap node")
	case d.Kind != UpdateMeasurements && d.Kind != RotateKey && d.Kind != Genesis:
		return fmt.Errorf("unknown kind %q", d.Kind)
	case !slices.Equal(d.Measurements, normalizePins(d.Measurements)):
		return errors.New("measurements not in canonical form")
	}
	return nil
}

// normalizePins sorts and de-duplicates a pin list.
func normalizePins(p []string) []string {
	if len(p) == 0 {
		return nil
	}
	return slices.Compact(slices.Sorted(slices.Values(p)))
}
