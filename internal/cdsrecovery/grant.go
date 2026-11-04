// Package cdsrecovery seals recovery keys to an attested CDS process. It does
// not store keys, choose approved images, or establish storage freshness.
package cdsrecovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

const RequestPath = "/ha/object-wal/recovery-request"

// Identity is chosen by the authority's policy, never learned from an
// untrusted request. ConfigSHA256 commits to the complete measured launch file.
type Identity struct {
	ClusterID    string `json:"cluster_id"`
	ConfigSHA256 string `json:"config_sha256"`
	Prefix       string `json:"prefix"`
}

func (i Identity) check() error {
	h, err := hex.DecodeString(i.ConfigSHA256)
	if err != nil || len(h) != 32 || hex.EncodeToString(h) != i.ConfigSHA256 ||
		i.ClusterID == "" || len(i.ClusterID) > 256 || i.Prefix == "" || len(i.Prefix) > 1024 {
		return errors.New("recovery: invalid cluster identity")
	}
	return nil
}

type Request struct {
	Version   int      `json:"version"`
	Identity  Identity `json:"identity"`
	Nonce     []byte   `json:"nonce"`
	PublicKey []byte   `json:"public_key"`
}

func (r Request) check() error {
	if r.Version != 1 || len(r.Nonce) != overenc.SessionIDBytes || len(r.PublicKey) != overenc.XWingEKBytes {
		return errors.New("recovery: invalid recipient")
	}
	return r.Identity.check()
}

// Material is available only inside the authority and recipient. Recovery
// grants default to refusing Genesis, even when the storage head is missing.
type Material struct {
	Key          []byte `json:"key"`
	AllowGenesis bool   `json:"allow_genesis"`
}

type Grant struct {
	RequestHash []byte         `json:"request_hash"`
	KEM         []byte         `json:"kem"`
	Record      overenc.Record `json:"record"`
	Signature   []byte         `json:"signature"`
}

// Check bounds allocations before admitting a grant to the control actor.
func (g Grant) Check() error {
	if len(g.RequestHash) != sha512.Size384 || len(g.KEM) != overenc.XWingCTBytes ||
		g.Record.Seq != 1 || len(g.Record.CT) < 16 || len(g.Record.CT) > 256 || len(g.Signature) != ed25519.SignatureSize {
		return errors.New("recovery: malformed grant")
	}
	return nil
}

func (g Grant) Clone() *Grant {
	g.RequestHash = bytes.Clone(g.RequestHash)
	g.KEM = bytes.Clone(g.KEM)
	g.Record.CT = bytes.Clone(g.Record.CT)
	g.Signature = bytes.Clone(g.Signature)
	return &g
}

// Recipient lives for one process incarnation. Request returns only copied
// public data; Open is called by the CDS provisioning actor.
type Recipient struct {
	request Request
	key     *overenc.ClientKey
}

func NewRecipient(identity Identity) (*Recipient, error) {
	if err := identity.check(); err != nil {
		return nil, err
	}
	key, err := overenc.GenerateClientKey()
	if err != nil {
		return nil, err
	}
	nonce, err := overenc.GenerateSessionID()
	if err != nil {
		return nil, err
	}
	return &Recipient{key: key, request: Request{Version: 1, Identity: identity, Nonce: nonce, PublicKey: bytes.Clone(key.EncapsulationKey())}}, nil
}

func (r *Recipient) Request() Request {
	q := r.request
	q.PublicKey, q.Nonce = bytes.Clone(q.PublicKey), bytes.Clone(q.Nonce)
	return q
}

func ParseAuthority(encoded string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("recovery: authority must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

func requestHash(q Request) []byte {
	b, _ := json.Marshal(q) // Fixed structs contain no values Marshal can reject.
	h := sha512.Sum384(append([]byte("c8s/cds-recovery/request/v1\x00"), b...))
	return h[:]
}

func transcript(g Grant) []byte {
	h := sha512.New384()
	h.Write([]byte("c8s/cds-recovery/channel/v1\x00"))
	h.Write(g.RequestHash)
	h.Write(g.KEM)
	return h.Sum(nil)
}

func signedBytes(g Grant) []byte {
	g.Signature = nil
	b, _ := json.Marshal(g)
	return append([]byte("c8s/cds-recovery/grant/v1\x00"), b...)
}

// seal is deliberately private: Release obtains the recipient key itself
// through pinned armTLS, rather than signing an operator-supplied request.
func seal(q Request, m Material, signer ed25519.PrivateKey) (*Grant, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	if len(m.Key) != 32 || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("recovery: invalid authority material")
	}
	ct, shared, err := overenc.Encapsulate(q.PublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	g := Grant{RequestHash: requestHash(q), KEM: ct}
	channel, err := overenc.NewServerChannel(shared, transcript(g), q.Nonce)
	if err != nil {
		return nil, err
	}
	plaintext, _ := json.Marshal(m)
	defer clear(plaintext)
	g.Record, err = channel.SealResponse(plaintext, 1)
	if err != nil {
		return nil, err
	}
	g.Signature = ed25519.Sign(signer, signedBytes(g))
	return &g, nil
}

func (r *Recipient) Open(g Grant, authority ed25519.PublicKey) (Material, error) {
	if err := g.Check(); err != nil {
		return Material{}, err
	}
	if len(authority) != ed25519.PublicKeySize || !bytes.Equal(g.RequestHash, requestHash(r.request)) ||
		!ed25519.Verify(authority, signedBytes(g), g.Signature) {
		return Material{}, errors.New("recovery: wrong recipient or authority")
	}
	shared, err := r.key.Decapsulate(g.KEM)
	if err != nil {
		return Material{}, err
	}
	defer clear(shared)
	channel, err := overenc.NewClientChannel(shared, transcript(g), r.request.Nonce)
	if err != nil {
		return Material{}, err
	}
	plaintext, err := channel.OpenResponse(g.Record, 1)
	if err != nil {
		return Material{}, errors.New("recovery: invalid sealed material")
	}
	defer clear(plaintext)
	var m Material
	if err := decode(plaintext, &m); err != nil || len(m.Key) != 32 {
		clear(m.Key)
		return Material{}, errors.New("recovery: invalid recovered key")
	}
	return m, nil
}

func decode(body []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("recovery: trailing JSON")
	}
	return nil
}
