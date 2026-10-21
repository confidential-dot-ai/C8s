package cdsha

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// Recover is break-glass after the permanent loss of a majority: it
	// makes the named surviving replica (BootstrapNode) the only voter, with
	// the state it holds, and the replacements join it. Entries the lost
	// replicas had committed but the survivor had not received are gone. If
	// the lost replicas were only cut off, they could go on as the old
	// majority: follow Recover with RotateKey, so they hold a retired key.
	Recover DecreeKind = "Recover"
	// Restore starts a cluster that lost every replica from an operator
	// backup: the named node (BootstrapNode) starts a one-voter group and
	// commits the snapshot whose SHA-256 the decree names. Like Genesis it
	// applies only to a replica that holds no cluster.
	Restore DecreeKind = "Restore"
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
	// SnapshotSHA256 names the backup a Restore decree restores (hex).
	SnapshotSHA256 string `json:"snapshot_sha256,omitempty"`
	// Images are the launch identities behind Measurements, for clients
	// outside the group (node agents, pods) that pin CDS by its full launch
	// identity rather than by a replica pin. When set, Measurements must be
	// exactly their replica pins, so one signed decree tells replicas and
	// nodes the same thing. Nodes fetch it from any replica (GET /ha/pins).
	Images []DecreeImage `json:"images,omitempty"`
}

// DecreeImage is one TDX launch identity: MRTD and RTMR[1..2], lowercase hex.
type DecreeImage struct {
	MRTD  string `json:"mrtd"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// Pin is the replica pin of the image, as a TDX replica reports its own:
// SHA-384 over MRTD, RTMR1 and RTMR2.
func (i DecreeImage) Pin() (string, error) {
	h := sha512.New384()
	for _, v := range []string{i.MRTD, i.RTMR1, i.RTMR2} {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != sha512.Size384 || v != strings.ToLower(v) {
			return "", fmt.Errorf("image register %q is not 48 bytes of lowercase hex", v)
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// imagePins are the replica pins of images, canonical.
func imagePins(images []DecreeImage) ([]string, error) {
	pins := make([]string, 0, len(images))
	for _, i := range images {
		p, err := i.Pin()
		if err != nil {
			return nil, err
		}
		pins = append(pins, p)
	}
	return normalizePins(pins), nil
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
	case (d.Kind == Genesis || d.Kind == Restore) && (len(tail.RootCert) != 0 || len(d.Measurements) != 0):
		return errors.New("a Genesis or Restore decree applies only to a cluster without a key, and carries no measurements")
	case (d.Kind == Restore) != (d.SnapshotSHA256 != ""):
		return errors.New("a Restore decree, and only one, names the snapshot it restores")
	case (d.Kind == Genesis || d.Kind == Recover || d.Kind == Restore) && d.BootstrapNode == "":
		return errors.New("a Genesis, Recover or Restore decree must name its node")
	case d.Kind != Genesis && d.Kind != Recover && d.Kind != Restore && d.BootstrapNode != "":
		return errors.New("only Genesis, Recover and Restore decrees name a node")
	case d.Kind == Recover && (len(tail.RootCert) == 0 || len(d.Measurements) != 0):
		return errors.New("a Recover decree applies to a cluster with a key, and carries no measurements")
	case d.Kind != UpdateMeasurements && d.Kind != RotateKey && d.Kind != Genesis && d.Kind != Recover && d.Kind != Restore:
		return fmt.Errorf("unknown kind %q", d.Kind)
	case !slices.Equal(d.Measurements, normalizePins(d.Measurements)):
		return errors.New("measurements not in canonical form")
	case len(d.Images) > 0 && d.Kind != UpdateMeasurements && d.Kind != RotateKey:
		return errors.New("only UpdateMeasurements and RotateKey decrees carry images")
	}
	if len(d.Images) > 0 {
		pins, err := imagePins(d.Images)
		if err != nil {
			return err
		}
		if !slices.Equal(pins, d.Measurements) {
			return errors.New("measurements are not exactly the pins of the decree's images")
		}
	}
	return nil
}

// VerifyPinDecree is what a client outside the group checks before it pins
// CDS to a decree's images: the operator's signature with the decree key
// from its launch document, the cluster, and that the decree sets images.
// Expiry does not apply: a decree expires as a request to the replicas, and
// the pin set it made stays in force until a later decree replaces it.
func VerifyPinDecree(sd SignedDecree, clusterID string, decreeKey []byte) error {
	d := sd.Decree
	switch {
	case d.ClusterID != clusterID:
		return fmt.Errorf("pin decree for cluster %q", d.ClusterID)
	case len(d.Images) == 0 || (d.Kind != UpdateMeasurements && d.Kind != RotateKey):
		return errors.New("not a pin decree: no images")
	}
	tail := Core{ClusterID: clusterID, OperatorPubKey: decreeKey, Epoch: d.BaseEpoch}
	return verifyDecree(sd, tail)
}

// normalizePins sorts and de-duplicates a pin list.
func normalizePins(p []string) []string {
	if len(p) == 0 {
		return nil
	}
	return slices.Compact(slices.Sorted(slices.Values(p)))
}
