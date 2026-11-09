// Package cdschain is the CDS policy log: a hash chain of signed entries
// (docs/cds-ha.md). Every input comes from an untrusted store or peer and is
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

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
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
	TypeNodes        Type = "nodes"
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
	OperatorKeys string   `json:"operatorKeys"`
	CAKey        string   `json:"caKey"`
	Accepted     []Build  `json:"accepted"`
}

// Build is a CDS build the set accepts: its pin, which binds the launch file,
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

// Nodes replaces the whole set of node images the CDS certifies (a measurements
// document): the launch file's nodes until the first one.
type Nodes struct {
	Nodes string `json:"nodes"`
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
	// Nodes is the measurements document of the newest nodes entry: the node
	// images the CDS certifies. "" before one: the launch file's nodes.
	Nodes   string
	Routes  *Routes
	Entries int
	Bytes   int64
}

// VerifyGenesis checks entry 0 on its own: a chain's genesis is pinned by
// its hash or by the operator keys a caller trusts.
func VerifyGenesis(e Entry) (*State, error) {
	b, err := e.Decode()
	if err != nil {
		return nil, err
	}
	var g Genesis
	switch {
	case b.Seq != 0 || b.Prev != Hash{} || b.Type != TypeGenesis:
		return nil, errors.New("entry 0 must be a genesis at seq 0")
	case len(validation.IsDNS1123Label(b.Cluster)) != 0:
		return nil, fmt.Errorf("cluster %q is not an RFC1123 label", b.Cluster)
	}
	if err := DecodeStrict(b.Payload, &g); err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	if err := cmdsutil.ValidateCDSEndpoints(g.Endpoints); err != nil {
		return nil, err
	}
	s := &State{Cluster: b.Cluster, Endpoints: g.Endpoints}
	if s.OperatorKeys, err = parseKeys(g.OperatorKeys); err != nil {
		return nil, fmt.Errorf("genesis operator keys: %w", err)
	}
	if err := e.VerifySignature(s.OperatorKeys); err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	if s.CAKey, err = ParseKey(g.CAKey); err != nil {
		return nil, fmt.Errorf("genesis CA key: %w", err)
	}
	if len(g.Members) != len(g.Endpoints) {
		return nil, fmt.Errorf("genesis names %d members for %d endpoints", len(g.Members), len(g.Endpoints))
	}
	for slot, key := range g.Members {
		if err := s.setMember(slot, key); err != nil {
			return nil, err
		}
	}
	if err := s.setAccepted(g.Accepted); err != nil {
		return nil, err
	}
	s.Genesis = e.Hash()
	s.count(e)
	return s, nil
}

// Apply verifies e as the entry after s's head and returns the state after it.
func (s *State) Apply(e Entry) (*State, error) {
	b, err := e.Decode()
	if err != nil {
		return nil, err
	}
	switch {
	case b.Cluster != s.Cluster:
		return nil, fmt.Errorf("entry of cluster %q, not %q", b.Cluster, s.Cluster)
	case b.Seq != s.Head.Seq+1 || b.Prev != s.Head.Hash:
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
	next := *s
	next.Members, next.Accepted = slices.Clone(s.Members), slices.Clone(s.Accepted)
	if err := next.applyPayload(b); err != nil {
		return nil, fmt.Errorf("entry %d (%s): %w", b.Seq, b.Type, err)
	}
	next.count(e)
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
	case TypeNodes:
		var p Nodes
		if err := DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		if err := CheckNodes([]byte(p.Nodes)); err != nil {
			return err
		}
		s.Nodes = p.Nodes
		return nil
	}
	return fmt.Errorf("unknown entry type %q", b.Type)
}

func (s *State) count(e Entry) {
	b, _ := e.Decode()
	s.Head = Head{V: Version, Cluster: s.Cluster, Seq: b.Seq, Hash: e.Hash()}
	s.Entries++
	s.Bytes += int64(len(e.Body) + len(e.Sig))
}

// setMember names key for slot. A key holds at most one slot, so one
// instance votes once.
func (s *State) setMember(slot int, key string) error {
	if slot < 0 || slot >= len(s.Endpoints) {
		return fmt.Errorf("member slot %d outside the %d endpoints", slot, len(s.Endpoints))
	}
	if _, err := ParseKey(key); err != nil {
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
	seen := map[string]bool{}
	for _, b := range builds {
		if !semver.IsValid(b.Version) {
			return fmt.Errorf("build version %q is not a semantic version", b.Version)
		}
		if _, err := b.Values(); err != nil {
			return fmt.Errorf("build %s: %w", b.Version, err)
		}
		if seen[b.Measurements] {
			return fmt.Errorf("build %s is listed twice", b.Version)
		}
		seen[b.Measurements] = true
	}
	s.Accepted = builds
	// INVARIANT: every accepted image binds the one launch file, so a replica
	// is admitted only on the operator's configuration, and the set is
	// a pin every node client loads. An empty set is refused here too.
	_, err := cmdsutil.CDSLaunchFile(s.Pins())
	return err
}

// CheckNodes holds a node image set to what a nodes entry may carry: at least
// one image, every one binding the launch of the nodes it certifies.
// INVARIANT: an entry binding no launch would certify its image however the
// host launched it.
func CheckNodes(measurements []byte) error {
	nodes, err := refvalues.Parse(measurements)
	if err != nil {
		return fmt.Errorf("nodes: %w", err)
	}
	if len(nodes.Images) == 0 {
		return errors.New("nodes: the set names no image")
	}
	for _, image := range nodes.Images {
		if !BindsLaunch(image) {
			return fmt.Errorf("nodes: entry %q binds no launch: give it an approver_key, launch_file or launch_file_digest", image.Name)
		}
	}
	return nil
}

// BindsLaunch reports whether one entry binds the launch of the guests it
// admits: by approver key, launch file or launch file digest.
func BindsLaunch(image remote.ImagePin) bool {
	return image.Anchor != nil || image.LaunchFile != nil || image.LaunchFileDigest != nil
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

// PolicyVersion is the allowlist version (the ETag) a replica serves the
// chain's policy at: 1 for the launch file's seed, the policy entry's seq
// plus one after one.
// INVARIANT: the version changes whenever the served document does, and only
// goes up along a chain, so a node's If-None-Match never hides a new policy.
func (s *State) PolicyVersion() string {
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

// ParseKey reads one PEM EC public key.
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
		k, err := ParseKey(p)
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
