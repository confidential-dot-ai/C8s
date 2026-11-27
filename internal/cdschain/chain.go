// Package cdschain is the Trust Authority policy log: a hash chain of signed entries
// (docs/ta-ha.md). Every input comes from an untrusted store or peer and is
// verified, never trusted.
package cdschain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/strictjson"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

// Version is the format version of every body, head and note.
const Version = 1

// MaxEntryBytes bounds one encoded entry; a 1 MiB allowlist fits.
const MaxEntryBytes = 2 << 20

const (
	signDomain  = "c8s-cds-chain-sign-v1\x00"
	entryDomain = "c8s-cds-chain-entry-v1\x00"
)

// Hash identifies an entry: SHA-256 over its signed body. The signature is
// outside it, so a re-encoded signature names the same entry.
type Hash [32]byte

func (h Hash) String() string               { return hex.EncodeToString(h[:]) }
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }
func (h *Hash) UnmarshalText(b []byte) error {
	if len(b) != 64 || !bytes.Equal(b, bytes.ToLower(b)) {
		return errors.New("a hash is 64 lowercase hex characters")
	}
	_, err := hex.Decode(h[:], b)
	return err
}

// ParseHash reads the hex form of a hash.
func ParseHash(s string) (Hash, error) {
	var h Hash
	return h, h.UnmarshalText([]byte(s))
}

// ParsePin reads "<seq>:<hash>", one entry a reader pins a chain by.
func ParsePin(s string) (Head, error) {
	seq, hash, ok := strings.Cut(s, ":")
	n, err := strconv.ParseUint(seq, 10, 64)
	if !ok || err != nil {
		return Head{}, fmt.Errorf("%q is not <seq>:<hash>", s)
	}
	h, err := ParseHash(hash)
	return Head{Seq: n, Hash: h}, err
}

// Type names an entry's payload.
type Type string

const (
	TypeGenesis      Type = "genesis"
	TypeOperatorKeys Type = "operator-keys"
	TypeMember       Type = "member"
	TypePolicy       Type = "policy"
	TypeRoutes       Type = "routes"
	TypeAccepted     Type = "accepted"
)

// Body is what a writer signs. Seq and Prev place it at one position of one
// chain, so a signed body cannot be replayed elsewhere.
type Body struct {
	V       int             `json:"v"`
	Cluster string          `json:"cluster"`
	Seq     uint64          `json:"seq"`
	Prev    Hash            `json:"prev"`
	Type    Type            `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Entry is a signed body as stored and sent, with the exact signed bytes.
type Entry struct {
	Body []byte `json:"body"`
	Sig  string `json:"sig"`
}

// Hash is the entry's identity.
func (e Entry) Hash() Hash { return Hash(sha256.Sum256(append([]byte(entryDomain), e.Body...))) }

// Encode is the stored form of an entry.
func (e Entry) Encode() ([]byte, error) { return json.Marshal(e) }

// ParseEntry reads the stored form of an entry; Apply verifies it.
func ParseEntry(data []byte) (Entry, error) {
	var e Entry
	if len(data) > MaxEntryBytes {
		return e, fmt.Errorf("entry exceeds %d bytes", MaxEntryBytes)
	}
	return e, DecodeStrict(data, &e)
}

// Decode reads the signed body without verifying it.
func (e Entry) Decode() (Body, error) {
	var b Body
	if err := DecodeStrict(e.Body, &b); err != nil {
		return b, fmt.Errorf("entry body: %w", err)
	}
	if b.V != Version {
		return b, fmt.Errorf("entry format version %d, this build reads %d", b.V, Version)
	}
	return b, nil
}

// Sign signs body with key, an operator or member key.
func Sign(key *ecdsa.PrivateKey, body Body) (Entry, error) {
	body.V = Version
	encoded, err := json.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	sig, err := operatorauth.SignDetached(key, append([]byte(signDomain), encoded...))
	return Entry{Body: encoded, Sig: sig}, err
}

// VerifySignature checks that one of keys signed the entry.
func (e Entry) VerifySignature(keys []*ecdsa.PublicKey) error {
	return operatorauth.VerifyDetached(keys, append([]byte(signDomain), e.Body...), e.Sig)
}

// Head names the newest entry of a chain.
type Head struct {
	V       int    `json:"v"`
	Cluster string `json:"cluster"`
	Seq     uint64 `json:"seq"`
	Hash    Hash   `json:"hash"`
}

// Genesis is entry 0: endpoints, member keys by slot, writers, the mesh CA
// key and the first accepted builds.
type Genesis struct {
	Endpoints    []string `json:"endpoints"`
	Members      []string `json:"members"`
	OperatorKeys string   `json:"operator_keys"`
	CAKey        string   `json:"ca_key"`
	Accepted     []Build  `json:"accepted"`
}

// Build is a Trust Authority build the set accepts: its pin, which binds the launch file,
// and its release version.
type Build struct {
	Measurements string `json:"measurements"`
	Version      string `json:"version"`
}

// Accepted replaces the whole set of accepted builds. Raising the floor is
// writing a set without the old builds.
type Accepted struct {
	Accepted []Build `json:"accepted"`
}

// Member names the member key of one slot.
type Member struct {
	Slot int    `json:"slot"`
	Key  string `json:"key"`
}

// OperatorKeys replaces the writers; a key of the old set signs it.
type OperatorKeys struct {
	Keys string `json:"keys"`
}

// Policy is a whole allowlist document, canonical.
type Policy struct {
	Allowlist json.RawMessage `json:"allowlist"`
}

// Routes is the route manifest in the router's envelope.
type Routes struct {
	Manifest []byte `json:"manifest"`
	Token    string `json:"token"`
}

// State is what a verified chain decides.
type State struct {
	Cluster      string
	Genesis      Hash
	Head         Head
	Endpoints    []string
	Members      []string
	OperatorKeys []*ecdsa.PublicKey
	CAKey        *ecdsa.PublicKey
	Accepted     []Build
	// Policy is the canonical allowlist of the newest policy entry, at
	// PolicySeq; nil before one.
	Policy    []byte
	PolicySeq uint64
	Routes    *Routes
	Entries   int
	Bytes     int64
}

// VerifyGenesis checks entry 0 on its own: a chain's genesis is pinned by
// its hash or by the operator keys a caller trusts.
func VerifyGenesis(e Entry) (*State, error) {
	b, err := e.Decode()
	if err != nil {
		return nil, err
	}
	if b.Seq != 0 || b.Prev != (Hash{}) || b.Type != TypeGenesis {
		return nil, errors.New("entry 0 must be a genesis at seq 0")
	}
	if len(validation.IsDNS1123Label(b.Cluster)) != 0 {
		return nil, fmt.Errorf("cluster %q is not an RFC1123 label", b.Cluster)
	}
	var g Genesis
	if err := DecodeStrict(b.Payload, &g); err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	if err := cmdsutil.ValidateCDSEndpoints(g.Endpoints); err != nil {
		return nil, err
	}
	operatorKeys, err := parseKeys(g.OperatorKeys)
	if err != nil {
		return nil, fmt.Errorf("genesis operator keys: %w", err)
	}
	if err := e.VerifySignature(operatorKeys); err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	caKey, err := ParseKey(g.CAKey)
	if err != nil {
		return nil, fmt.Errorf("genesis CA key: %w", err)
	}
	if len(g.Members) != len(g.Endpoints) {
		return nil, fmt.Errorf("genesis names %d members for %d endpoints", len(g.Members), len(g.Endpoints))
	}
	empty := &State{
		Cluster:      b.Cluster,
		Genesis:      e.Hash(),
		Endpoints:    g.Endpoints,
		OperatorKeys: operatorKeys,
		CAKey:        caKey,
	}
	return empty.extend(e, b, func(s *State) error {
		for slot, key := range g.Members {
			if err := s.setMember(slot, key); err != nil {
				return err
			}
		}
		return s.setAccepted(g.Accepted)
	})
}

// Apply verifies e as the entry after s's head and returns the state after it.
func (s *State) Apply(e Entry) (*State, error) {
	b, err := e.Decode()
	if err != nil {
		return nil, err
	}
	if b.Cluster != s.Cluster {
		return nil, fmt.Errorf("entry of cluster %q, not %q", b.Cluster, s.Cluster)
	}
	if b.Seq != s.Head.Seq+1 || b.Prev != s.Head.Hash {
		return nil, fmt.Errorf("%w: entry %d after %s does not follow head %d (%s)", ErrNotNext, b.Seq, b.Prev, s.Head.Seq, s.Head.Hash)
	}
	signers := s.OperatorKeys
	if b.Type == TypeMember {
		members, err := parseEach(s.Members)
		if err != nil {
			return nil, err
		}
		signers = append(slices.Clone(signers), members...)
	}
	if err := e.VerifySignature(signers); err != nil {
		return nil, fmt.Errorf("entry %d: %w", b.Seq, err)
	}
	next, err := s.extend(e, b, func(next *State) error { return next.applyPayload(b) })
	if err != nil {
		return nil, fmt.Errorf("entry %d (%s): %w", b.Seq, b.Type, err)
	}
	return next, nil
}

// extend is the one way a state gains an entry: decide applies e's payload
// to a copy of s, and the copy's head and size then count e.
func (s *State) extend(e Entry, b Body, decide func(*State) error) (*State, error) {
	next := *s
	next.Members = slices.Clone(s.Members)
	next.Accepted = slices.Clone(s.Accepted)
	if err := decide(&next); err != nil {
		return nil, err
	}
	next.Head = Head{V: Version, Cluster: s.Cluster, Seq: b.Seq, Hash: e.Hash()}
	next.Entries++
	next.Bytes += int64(len(e.Body) + len(e.Sig))
	return &next, nil
}

// ErrNotNext is an entry that does not follow the head: a conflict, not a
// bad entry.
var ErrNotNext = errors.New("not the next entry")

func (s *State) applyPayload(b Body) error {
	switch b.Type {
	case TypeOperatorKeys:
		var p OperatorKeys
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		keys, err := parseKeys(p.Keys)
		s.OperatorKeys = keys
		return err
	case TypeMember:
		var p Member
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		return s.setMember(p.Slot, p.Key)
	case TypePolicy:
		var p Policy
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		doc, err := allowlist.ParseJSON(p.Allowlist)
		if err != nil {
			return err
		}
		canonical, err := doc.Canonical()
		if err != nil || !bytes.Equal(canonical, p.Allowlist) {
			return errors.New("the allowlist is not in canonical form")
		}
		s.Policy, s.PolicySeq = canonical, b.Seq
		return nil
	case TypeRoutes:
		var p Routes
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		if len(p.Manifest) == 0 {
			return errors.New("routes entry carries no manifest")
		}
		s.Routes = &p
		return nil
	case TypeAccepted:
		var p Accepted
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		return s.setAccepted(p.Accepted)
	}
	return fmt.Errorf("unknown entry type %q", b.Type)
}

// setMember names key for slot. A key holds at most one slot, so one
// instance votes once.
func (s *State) setMember(slot int, key string) error {
	if slot < 0 || slot >= len(s.Endpoints) {
		return fmt.Errorf("member slot %d outside the %d endpoints", slot, len(s.Endpoints))
	}
	if _, err := runtimemeasure.ParsePublicKeyPEM([]byte(key)); err != nil {
		return fmt.Errorf("member key: %w", err)
	}
	if len(s.Members) == 0 {
		s.Members = make([]string, len(s.Endpoints))
	}
	for other, k := range s.Members {
		if other != slot && k == key {
			return fmt.Errorf("member key of slot %d already holds slot %d", slot, other)
		}
	}
	s.Members[slot] = key
	return nil
}

func (s *State) setAccepted(builds []Build) error {
	if len(builds) == 0 {
		return fmt.Errorf("%w: no accepted build pins an image", cmdsutil.ErrTAPinUnbound)
	}
	seen := map[string]bool{}
	var launchFile []byte
	var family teetypes.Family
	for _, b := range builds {
		if !semver.IsValid(b.Version) {
			return fmt.Errorf("build version %q is not a semantic version", b.Version)
		}
		values, err := b.Values()
		if err != nil {
			return fmt.Errorf("build %s: %w", b.Version, err)
		}
		// The combined pin set retains only one family; validate before combining.
		if err := cmdsutil.CheckCDSPins(values); err != nil {
			return fmt.Errorf("build %s: %w", b.Version, err)
		}
		if family == "" {
			family = values.Family
		} else if values.Family != family {
			return fmt.Errorf("accepted builds use different TEE families: %s and %s", family, values.Family)
		}
		file := values.Images[0].LaunchFile
		if launchFile == nil {
			launchFile = file
		}
		if !bytes.Equal(file, launchFile) {
			return fmt.Errorf("build %s: %w: binds another configuration, and one pin names one Trust Authority", b.Version, cmdsutil.ErrTAPinUnbound)
		}
		if seen[b.Measurements] {
			return fmt.Errorf("build %s is listed twice", b.Version)
		}
		seen[b.Measurements] = true
	}
	s.Accepted = builds
	return nil
}

// Values parses the build's pin.
func (b Build) Values() (refvalues.ReferenceValues, error) {
	values, err := refvalues.Parse([]byte(b.Measurements))
	if err != nil {
		return values, fmt.Errorf("measurements: %w", err)
	}
	return values, nil
}

// Pins are the images of every accepted build, which an attested client of
// this chain holds a replica to.
func (s *State) Pins() refvalues.ReferenceValues {
	var all refvalues.ReferenceValues
	for _, b := range s.Accepted {
		values, _ := b.Values()
		for _, img := range values.Images {
			// Two builds' pins may name their images alike.
			img.Name = b.Version + "/" + img.Name
			all.Images = append(all.Images, img)
		}
		all.Family = values.Family
	}
	return all
}

// CurrentPolicyVersion is the allowlist version (the ETag) a replica serves
// the policy in force at s's head at: 1 for the launch file's seed, the
// newest policy entry's seq plus one after one.
// INVARIANT: the version changes whenever the served document does, and only
// goes up along a chain, so a node's If-None-Match never hides a new policy.
func (s *State) CurrentPolicyVersion() string {
	if s.Policy == nil {
		return "1"
	}
	return strconv.FormatUint(s.PolicySeq+1, 10)
}

// Verify checks a whole chain from its genesis.
func Verify(entries []Entry) (*State, error) {
	if len(entries) == 0 {
		return nil, errors.New("empty chain")
	}
	s, err := VerifyGenesis(entries[0])
	for _, e := range entries[1:] {
		if err != nil {
			break
		}
		s, err = s.Apply(e)
	}
	return s, err
}

// PublicKeyPEM encodes a public key as a PEM PKIX block.
func PublicKeyPEM(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), err
}

// ParseKey reads one PEM EC public key of any curve: the mesh CA key is
// P-384. A member key is P-256 (runtimemeasure.ParsePublicKeyPEM).
func ParseKey(pemKey string) (*ecdsa.PublicKey, error) {
	keys, err := operatorauth.ParsePublicKeysPEM([]byte(pemKey))
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("want one public key, got %d", len(keys))
	}
	return keys[0], nil
}

func parseKeys(bundle string) ([]*ecdsa.PublicKey, error) {
	b, err := operatorauth.ParseKeyBundle([]byte(bundle))
	if err != nil {
		return nil, err
	}
	return b.Keys(), nil
}

func parseEach(pems []string) ([]*ecdsa.PublicKey, error) {
	keys := make([]*ecdsa.PublicKey, len(pems))
	for i, p := range pems {
		k, err := runtimemeasure.ParsePublicKeyPEM([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("member %d: %w", i, err)
		}
		keys[i] = k
	}
	return keys, nil
}

// DecodeStrict refuses duplicate keys, unknown fields and trailing data, so a
// signer and a verifier never read one byte string two ways.
func DecodeStrict(data []byte, v any) error {
	if err := strictjson.Validate(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
