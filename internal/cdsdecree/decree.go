// Package cdsdecree is the operator's signed instruction to a CDS cluster:
// which images a CDS of this cluster may run, which node images it certifies,
// which process may start or carry on the cluster, and which unjoined replica
// may admit an image beside its own.
//
// A decree is JSON, signed detached with a key of the cluster's
// operatorPublicKeys over a domain-separated message. Replicas, nodes and the
// operator CLI all read decrees, so this package holds the types and every
// check that needs no cluster state, and depends on neither Raft nor HTTP.
//
// An expiry bounds adoption only: a replica refuses a decree that has expired,
// and the state an adopted decree made stays in force until a later decree
// replaces it.
//
// Genesis, Recover and Admit act on one process. They name the member id their
// target minted at its start, so a recorded decree never acts a second time,
// and a Genesis names the mesh CA its target mints, so a replica replaying one
// cannot install a CA of its own.
package cdsdecree

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// signingDomain separates a decree signature from every other operator
// signature over JSON.
const signingDomain = "c8s-cds-decree-v1\n"

// Kind is the intent a decree carries.
type Kind string

const (
	// Genesis starts a cluster: its target mints the mesh CA, and the decree
	// carries the CDS and node image sets the cluster begins with.
	Genesis Kind = "Genesis"
	// UpdateMeasurements replaces the set of images a CDS of this cluster may
	// run, which is also the set its clients and nodes pin it by.
	UpdateMeasurements Kind = "UpdateMeasurements"
	// RotateKey mints a mesh CA key and forks the mesh: every leaf must be
	// issued again under the new key.
	RotateKey Kind = "RotateKey"
	// SetVoters names the voter seats the cluster holds. The replicas fill
	// or give up one seat at a time until they hold that many.
	SetVoters Kind = "SetVoters"
	// Recover is break-glass after a majority is lost for good: the target
	// carries the cluster on alone with the state it holds, and entries the
	// lost voters committed and it never received are gone.
	Recover Kind = "Recover"
	// DismissRecover lifts the doubt a sighted Recover decree left on the
	// cluster, once no other side can serve.
	DismissRecover Kind = "DismissRecover"
	// Admit names the images one unjoined replica may admit beside its own, so
	// a replica of a new image reaches a cluster still running the old one.
	Admit Kind = "Admit"
)

// Decree is one operator intent for one cluster. Every kind carries the
// cluster, the intent id, the kind and the expiry; the kinds table says what
// else each kind carries.
type Decree struct {
	ClusterID string    `json:"cluster_id"`
	IntentID  string    `json:"intent_id"`
	Kind      Kind      `json:"kind"`
	ExpiresAt time.Time `json:"expires_at"`
	// BaseVersion is the count of applied operator commands this decree
	// applies on top of.
	BaseVersion uint64 `json:"base_version,omitempty"`
	// CDSPins is the image set a CDS of this cluster may run.
	CDSPins *PinDocument `json:"cds_pins,omitempty"`
	// NodePins is the full set of node images the cluster certifies.
	NodePins *NodeImages `json:"node_pins,omitempty"`
	Voters   int         `json:"voters,omitempty"`
	// TargetMember is the member id the target process minted at its start.
	TargetMember string `json:"target_member,omitempty"`
	// TargetAddress is the address the operator reached the target at.
	TargetAddress string `json:"target_address,omitempty"`
	// IssuedAtMS is the operator's clock when they signed (Unix ms), and the
	// earliest start time a cluster this decree starts takes.
	IssuedAtMS int64 `json:"issued_at_ms,omitempty"`
	// GenesisCA is the SHA-256 of the mesh CA certificate the target mints.
	GenesisCA string `json:"genesis_ca,omitempty"`
	// ResumeVersion is the highest version the operator knows a cluster under
	// this cluster id reached; the cluster resumes above it.
	ResumeVersion uint64 `json:"resume_version,omitempty"`
	// Alone starts a cluster whose discovery answers with no other replica.
	Alone bool `json:"alone,omitempty"`
	// RecoverIntent is the Recover decree whose doubt a DismissRecover lifts.
	RecoverIntent string `json:"recover_intent,omitempty"`
}

// Signed is a decree with the operator's detached signature over it.
type Signed struct {
	Decree    Decree `json:"decree"`
	Signature string `json:"signature"`
}

// Parse reads a signed decree as it travels: an object on a board the host
// controls. It refuses a key the decree does not define, and anything
// encoding/json would otherwise reinterpret, so what a reader checks is
// everything the object says.
func Parse(object []byte) (Signed, error) {
	if err := strictjson.Validate(object); err != nil {
		return Signed{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(object))
	decoder.DisallowUnknownFields()
	var signed Signed
	if err := decoder.Decode(&signed); err != nil {
		return Signed{}, fmt.Errorf("decode decree: %w", err)
	}
	return signed, nil
}

// Sign signs d with an operator private key.
func Sign(d Decree, key *ecdsa.PrivateKey) (Signed, error) {
	message, err := d.signedBytes()
	if err != nil {
		return Signed{}, err
	}
	signature, err := operatorauth.SignDetached(key, message)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Decree: d, Signature: signature}, nil
}

// Verify checks the operator's signature over sd, then everything about the
// decree that needs no cluster state. A reader holding the cluster's state
// also checks the base version, the intent against the decrees already
// applied, and, where it adopts the decree, the expiry.
func Verify(sd Signed, keys []*ecdsa.PublicKey, clusterID string) error {
	if err := verifySignature(sd, keys); err != nil {
		return err
	}
	d := sd.Decree
	if d.ClusterID != clusterID {
		return fmt.Errorf("decree for cluster %q, not %q", d.ClusterID, clusterID)
	}
	if err := checkIntentID(d.IntentID); err != nil {
		return err
	}
	if err := d.checkTimes(); err != nil {
		return err
	}
	if err := d.checkFields(); err != nil {
		return err
	}
	if err := d.checkVersions(); err != nil {
		return err
	}
	if err := d.checkPins(); err != nil {
		return err
	}
	return d.checkSeats()
}

// signedBytes is the message a signature covers: the decree's fields as this
// package encodes them, so an object carrying anything else is checked, and
// applied, as what it decodes to.
func (d Decree) signedBytes() ([]byte, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append([]byte(signingDomain), body...), nil
}

// verifySignature checks the operator's signature before any field is read.
func verifySignature(sd Signed, keys []*ecdsa.PublicKey) error {
	message, err := sd.Decree.signedBytes()
	if err != nil {
		return err
	}
	if err := operatorauth.VerifyDetached(keys, message, sd.Signature); err != nil {
		return fmt.Errorf("decree signature: %w", err)
	}
	return nil
}

// intentIDSize is how long an intent id is: the length of NewIntentID's,
// which also names the decree's board object.
const intentIDSize = 26

// NewIntentID is one decree's name, in the lowercase base32 of rand.Text, so
// a board object can be named after it.
func NewIntentID() string {
	return strings.ToLower(rand.Text())
}

// checkIntentID requires a name NewIntentID writes, which is also a name a
// board object path can hold.
func checkIntentID(id string) error {
	if len(id) != intentIDSize {
		return fmt.Errorf("intent_id is %d characters, want the %d c8s cds ha decree writes", len(id), intentIDSize)
	}
	for _, r := range id {
		if !isIntentRune(r) {
			return fmt.Errorf("intent_id %q holds %q, want lowercase letters and digits", id, r)
		}
	}
	return nil
}

func isIntentRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// checkTimes requires an expiry, and an issue time inside it: a decree issued
// past its own expiry comes from an operator clock that is wrong, and its
// issue time becomes a cluster's start time.
func (d Decree) checkTimes() error {
	if d.ExpiresAt.IsZero() {
		return errors.New("decree names no expires_at")
	}
	if d.IssuedAtMS != 0 && d.issuedAt().After(d.ExpiresAt) {
		return errors.New("issued_at_ms is past expires_at: check the signing clock and sign the decree again")
	}
	return nil
}

// issuedAt is when the operator signed a decree that starts or carries on a
// cluster.
func (d Decree) issuedAt() time.Time {
	return time.UnixMilli(d.IssuedAtMS)
}

// checkVersions requires a decree that resumes a cluster to resume above the
// version it applies on: a lower one would let a decree of the cluster it
// resumes apply again.
func (d Decree) checkVersions() error {
	if d.ResumeVersion != 0 && d.ResumeVersion < d.BaseVersion {
		return fmt.Errorf("resume_version %d is below base_version %d", d.ResumeVersion, d.BaseVersion)
	}
	return nil
}

// fields are the decree fields whose presence depends on the kind, each with
// the test for whether a decree sets it.
var fields = map[string]func(Decree) bool{
	"alone":          func(d Decree) bool { return d.Alone },
	"base_version":   func(d Decree) bool { return d.BaseVersion != 0 },
	"cds_pins":       func(d Decree) bool { return d.CDSPins != nil },
	"genesis_ca":     func(d Decree) bool { return d.GenesisCA != "" },
	"issued_at_ms":   func(d Decree) bool { return d.IssuedAtMS != 0 },
	"node_pins":      func(d Decree) bool { return d.NodePins != nil },
	"recover_intent": func(d Decree) bool { return d.RecoverIntent != "" },
	"resume_version": func(d Decree) bool { return d.ResumeVersion != 0 },
	"target_address": func(d Decree) bool { return d.TargetAddress != "" },
	"target_member":  func(d Decree) bool { return d.TargetMember != "" },
	"voters":         func(d Decree) bool { return d.Voters != 0 },
}

// carried is one kind's shape: the fields its decrees must set, and the ones
// they may.
type carried struct {
	must []string
	may  []string
}

func (c carried) allows(name string) bool {
	return slices.Contains(c.must, name) || slices.Contains(c.may, name)
}

// kinds is the shape of every decree kind. A Genesis applies to a cluster with
// no version yet, and an Admit to a replica that holds none, so neither names
// a base version; a first Genesis resumes above no version.
var kinds = map[Kind]carried{
	Genesis: {
		must: []string{"cds_pins", "node_pins", "target_member", "target_address", "issued_at_ms", "genesis_ca"},
		may:  []string{"resume_version", "alone"},
	},
	UpdateMeasurements: {must: []string{"base_version", "cds_pins"}},
	RotateKey:          {must: []string{"base_version"}},
	SetVoters:          {must: []string{"base_version", "voters"}},
	Recover:            {must: []string{"base_version", "target_member", "target_address", "issued_at_ms", "resume_version"}},
	DismissRecover:     {must: []string{"base_version", "recover_intent"}},
	Admit:              {must: []string{"cds_pins", "target_member"}},
}

// checkFields requires a decree to carry exactly what its kind does.
func (d Decree) checkFields() error {
	shape, known := kinds[d.Kind]
	if !known {
		return fmt.Errorf("unknown decree kind %q", d.Kind)
	}
	for _, name := range shape.must {
		if !fields[name](d) {
			return fmt.Errorf("a %s decree must carry %s", d.Kind, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if fields[name](d) && !shape.allows(name) {
			return fmt.Errorf("a %s decree carries no %s", d.Kind, name)
		}
	}
	return nil
}

// checkPins requires the image sets a decree carries to be documents their own
// parser reads back, and the mesh CA it names to be a digest.
func (d Decree) checkPins() error {
	if d.CDSPins != nil {
		if err := d.CDSPins.check(); err != nil {
			return fmt.Errorf("cds_pins: %w", err)
		}
	}
	if d.NodePins != nil {
		if _, err := d.NodePins.Images(); err != nil {
			return fmt.Errorf("node_pins: %w", err)
		}
	}
	if d.GenesisCA != "" && !isCertificateDigest(d.GenesisCA) {
		return fmt.Errorf("genesis_ca %q is not a SHA-256 digest in hex", d.GenesisCA)
	}
	return nil
}

const MaxVoterSeats = 9

// An even seat count tolerates no more loss than the odd count below it.
// Callers name the field they read the count from.
func CheckVoterSeats(seats int) error {
	if seats < 1 || seats > MaxVoterSeats || seats%2 == 0 {
		return fmt.Errorf("must be odd, between 1 and %d", MaxVoterSeats)
	}
	return nil
}

func (d Decree) checkSeats() error {
	if d.Voters == 0 {
		return nil
	}
	if err := CheckVoterSeats(d.Voters); err != nil {
		return fmt.Errorf("voters: %w", err)
	}
	return nil
}

// isCertificateDigest reports whether s is the SHA-256 of a certificate, as a
// replica reports its mesh CA.
func isCertificateDigest(s string) bool {
	digest, err := hex.DecodeString(s)
	return err == nil && len(digest) == sha256.Size
}
