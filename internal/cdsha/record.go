package cdsha

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// recordDomain separates epoch-record signatures from every other signature
// made by the mesh CA key (leaves are X.509 TBS structures, never this prefix).
const recordDomain = "c8s-cds-ha-epoch-v1\n"

// Record is the public state of one epoch (O2). It carries no private key (O5).
type Record struct {
	ClusterID      string   `json:"cluster_id"`
	Epoch          uint64   `json:"epoch"`
	Term           uint64   `json:"term"`
	RootCert       []byte   `json:"root_cert"`       // DER of the mesh CA certificate
	Measurements   []string `json:"measurements"`    // replica pin set, sorted lowercase hex
	OperatorPubKey []byte   `json:"operator_pubkey"` // PKIX DER; nil means decrees are rejected (G5)
	AppliedDecrees []string `json:"applied_decrees"`
	PrevEpochHash  []byte   `json:"prev_epoch_hash"` // nil at epoch 0
	// Decree is the operator decree that produced this epoch from the
	// previous one (nil at epoch 0). Binding it here makes the operator,
	// not whoever holds the previous key, the authority for every change (T3).
	Decree *SignedDecree `json:"decree,omitempty"`
}

// SignedRecord is a Record with the signature of the previous epoch's key,
// or of its own key at epoch 0 (O3).
type SignedRecord struct {
	Record    Record `json:"record"`
	Signature []byte `json:"signature"`
}

// Chain is a verified-or-not sequence of records starting at epoch 0.
type Chain []SignedRecord

func (r Record) signedBytes() ([]byte, error) {
	r.Measurements = slices.Sorted(slices.Values(r.Measurements))
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(recordDomain), body...), nil
}

// Hash is SHA-256 over the signed content; the next epoch commits to it.
// The signature is excluded, so ECDSA malleability cannot change it.
func (s SignedRecord) Hash() []byte {
	body, _ := s.Record.signedBytes() // INVARIANT: plain struct, marshal cannot fail
	h := sha256.Sum256(body)
	return h[:]
}

// Tuple is the ordering key (E1), with the tail hash as the Q1 tie-break.
type Tuple struct {
	Epoch uint64
	Term  uint64
	Hash  []byte
}

// Less orders tuples by (epoch, term, hash).
func (a Tuple) Less(b Tuple) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch < b.Epoch
	}
	if a.Term != b.Term {
		return a.Term < b.Term
	}
	return bytes.Compare(a.Hash, b.Hash) < 0
}

// Tuple of a non-empty chain is the tuple of its tail.
func (c Chain) Tuple() Tuple {
	t := c[len(c)-1]
	return Tuple{Epoch: t.Record.Epoch, Term: t.Record.Term, Hash: t.Hash()}
}

// Tail returns the last record.
func (c Chain) Tail() Record { return c[len(c)-1].Record }

// SignRecord signs r with key, which must be the key of epoch r.Epoch-1, or of
// r itself at epoch 0.
func SignRecord(r Record, key *ecdsa.PrivateKey) (SignedRecord, error) {
	msg, err := r.signedBytes()
	if err != nil {
		return SignedRecord{}, err
	}
	sig, err := key.Sign(rand.Reader, digest384(msg), crypto.SHA384)
	if err != nil {
		return SignedRecord{}, fmt.Errorf("sign epoch %d: %w", r.Epoch, err)
	}
	r.Measurements = slices.Sorted(slices.Values(r.Measurements))
	return SignedRecord{Record: r, Signature: sig}, nil
}

func digest384(msg []byte) []byte {
	h := sha512.Sum384(msg)
	return h[:]
}

// RootPublicKey parses the mesh CA public key of a record.
func (r Record) RootPublicKey() (*ecdsa.PublicKey, *x509.Certificate, error) {
	cert, err := x509.ParseCertificate(r.RootCert)
	if err != nil {
		return nil, nil, fmt.Errorf("epoch %d root_cert: %w", r.Epoch, err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("epoch %d root_cert: not an ECDSA key", r.Epoch)
	}
	return pub, cert, nil
}

func verifyRecord(s SignedRecord, signer Record) error {
	pub, _, err := signer.RootPublicKey()
	if err != nil {
		return err
	}
	msg, err := s.Record.signedBytes()
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, digest384(msg), s.Signature) {
		return fmt.Errorf("epoch %d: signature does not verify against epoch %d key", s.Record.Epoch, signer.Epoch)
	}
	return nil
}

// Verify checks the whole chain for clusterID (E2, O3): epoch 0 self-signed,
// each later record signed by the previous key, contiguous epochs, hash links,
// one cluster, an immutable operator key and non-decreasing terms.
// Signatures are checked before any field of a record is relied on.
func (c Chain) Verify(clusterID string) error {
	if len(c) == 0 {
		return errors.New("empty chain")
	}
	for i, s := range c {
		signer := s.Record
		if i > 0 {
			signer = c[i-1].Record
		}
		if err := verifyRecord(s, signer); err != nil {
			return err
		}
		if err := checkLink(c, i, clusterID); err != nil {
			return err
		}
	}
	return nil
}

func checkLink(c Chain, i int, clusterID string) error {
	r := c[i].Record
	if r.ClusterID != clusterID {
		return fmt.Errorf("epoch %d: cluster_id %q, want %q", r.Epoch, r.ClusterID, clusterID)
	}
	if len(r.Measurements) == 0 {
		return fmt.Errorf("epoch %d: empty measurement set", r.Epoch) // D8
	}
	if !slices.IsSorted(r.Measurements) {
		return fmt.Errorf("epoch %d: measurements not in canonical order", r.Epoch)
	}
	if i == 0 {
		if r.Epoch != 0 || r.PrevEpochHash != nil || r.Decree == nil || r.Decree.Decree.Kind != Genesis {
			return fmt.Errorf("chain must start at a self-signed epoch 0 carrying a Genesis decree")
		}
		if err := verifyDecree(*r.Decree, PreGenesis(r.ClusterID, r.OperatorPubKey)); err != nil {
			return fmt.Errorf("epoch 0 genesis decree: %w", err)
		}
		if !slices.Equal(r.AppliedDecrees, []string{r.Decree.Decree.IntentID}) {
			return errors.New("epoch 0: applied_decrees must list exactly the genesis decree")
		}
		return nil
	}
	p := c[i-1].Record
	if err := checkTransition(p, r); err != nil {
		return fmt.Errorf("epoch %d: %w", r.Epoch, err)
	}
	switch {
	case r.Epoch != p.Epoch+1:
		return fmt.Errorf("epoch %d follows epoch %d", r.Epoch, p.Epoch)
	case !bytes.Equal(r.PrevEpochHash, c[i-1].Hash()):
		return fmt.Errorf("epoch %d: prev_epoch_hash mismatch", r.Epoch)
	case !bytes.Equal(r.OperatorPubKey, p.OperatorPubKey):
		return fmt.Errorf("epoch %d: operator key changed", r.Epoch)
	case r.Term < p.Term:
		return fmt.Errorf("epoch %d: term %d below previous %d", r.Epoch, r.Term, p.Term)
	}
	return nil
}

// HasPrefix reports whether c extends (or equals) prefix.
func (c Chain) HasPrefix(prefix Chain) bool {
	if len(prefix) == 0 || len(prefix) > len(c) {
		return len(prefix) == 0
	}
	return bytes.Equal(c[len(prefix)-1].Hash(), prefix[len(prefix)-1].Hash())
}

// checkTransition requires that next is exactly what its decree allows
// from prev: the operator signed it for prev's epoch, it is recorded as
// applied, the pins are the decree's (or unchanged), and the root changes
// if and only if the decree rotates. Decree expiry is checked by the writer
// at application time only; a verifier cannot know when that was.
func checkTransition(prev, next Record) error {
	if next.Decree == nil {
		return errors.New("no operator decree")
	}
	if err := verifyDecree(*next.Decree, prev); err != nil {
		return fmt.Errorf("decree: %w", err)
	}
	d := next.Decree.Decree
	pins := prev.Measurements
	if len(d.Measurements) > 0 {
		pins = d.Measurements
	}
	switch {
	case !slices.Equal(next.AppliedDecrees, append(slices.Clone(prev.AppliedDecrees), d.IntentID)):
		return errors.New("applied_decrees does not record exactly this decree")
	case !slices.Equal(next.Measurements, pins):
		return errors.New("measurements differ from the decree")
	case (d.Kind == RotateKey) == bytes.Equal(next.RootCert, prev.RootCert):
		return errors.New("root_cert change does not match the decree kind")
	}
	return nil
}
