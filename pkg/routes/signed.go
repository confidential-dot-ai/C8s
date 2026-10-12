package routes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Envelope is the wire form of a signed manifest that GET /routes and
// PublicationPath serve (C1, E4). Its JSON form carries Manifest as standard
// padded base64 (RFC 4648 §4).
type Envelope struct {
	// Manifest is the manifest bytes.
	Manifest []byte
	// Token is the write token that authorized them: a compact JWT, without
	// the "Bearer " prefix.
	Token string
}

type envelopeJSON struct {
	Manifest string `json:"manifest"`
	Token    string `json:"token"`
}

// MarshalJSON encodes e as {"manifest": "<base64>", "token": "<token>"}.
func (e Envelope) MarshalJSON() ([]byte, error) {
	return json.Marshal(envelopeJSON{
		Manifest: base64.StdEncoding.EncodeToString(e.Manifest),
		Token:    e.Token,
	})
}

// UnmarshalJSON decodes an envelope strictly: exactly the members manifest
// and token, no duplicate keys, and manifest in canonical standard padded
// base64, so one envelope has one encoding.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	if err := strictjson.Validate(data); err != nil {
		return fmt.Errorf("route envelope: %w", err)
	}
	obj, err := members(data, "route envelope", []string{"manifest", "token"}, nil)
	if err != nil {
		return err
	}
	encoded, err := stringValue(obj["manifest"], "route envelope: manifest")
	if err != nil {
		return err
	}
	token, err := stringValue(obj["token"], "route envelope: token")
	if err != nil {
		return err
	}
	manifest, err := base64.StdEncoding.DecodeString(encoded)
	// DecodeString skips newlines; re-encoding rejects them and any other
	// non-canonical form.
	if err != nil || base64.StdEncoding.EncodeToString(manifest) != encoded {
		return errors.New("route envelope: manifest is not standard padded base64")
	}
	*e = Envelope{Manifest: manifest, Token: token}
	return nil
}

// Signed is a verified signed manifest. Its accessors return copies.
// Holders of a *Signed must not assign through the pointer.
type Signed struct {
	bytes    []byte
	token    string
	manifest *Manifest
	digest   [sha256.Size]byte
}

// Bytes returns the manifest bytes.
func (s *Signed) Bytes() []byte { return bytes.Clone(s.bytes) }

// Token returns the write token that authorized the manifest bytes.
func (s *Signed) Token() string { return s.token }

// Manifest returns the parsed manifest bytes.
func (s *Signed) Manifest() *Manifest { return s.manifest.clone() }

// Digest returns the route digest of the manifest bytes.
func (s *Signed) Digest() [sha256.Size]byte { return s.digest }

// Envelope returns s in its wire form.
func (s *Signed) Envelope() Envelope {
	return Envelope{Manifest: s.Bytes(), Token: s.token}
}

// VerifySigned verifies env under the trusted operator keys as W2 requires,
// in order: the token's signature (ES256, ES384 or ES512), htm PUT and htu
// /routes, pbh against the manifest bytes, then the manifest itself (§5).
// It then rejects a ca holding one of meshCAs or a certificate one of them
// issued (B3). The router passes its full trusted mesh CA bundle, every
// rotation generation included; a client verifying a publication (V2)
// passes nil.
// It checks no time claim (W3) and no revision; see Supersedes for W4.
// Only a fetch over A1 TLS may renew freshness; see State.
func VerifySigned(env Envelope, keys []*ecdsa.PublicKey, meshCAs []*x509.Certificate) (*Signed, error) {
	// Verify, parse and hash one private copy, so a caller that changes
	// env.Manifest concurrently cannot make pbh cover other bytes than s.bytes.
	b := bytes.Clone(env.Manifest)
	if err := operatorauth.VerifyStoredToken(keys, env.Token, http.MethodPut, Path, b); err != nil {
		return nil, fmt.Errorf("verify route write token: %w", err)
	}
	m, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if err := m.CheckAnchorsExclude(meshCAs); err != nil {
		return nil, err
	}
	return &Signed{bytes: b, token: env.Token, manifest: m, digest: Digest(b)}, nil
}

var (
	// ErrRollback reports a revision lower than the one last accepted (W4).
	ErrRollback = errors.New("route manifest revision is lower than the accepted one")
	// ErrRevisionConflict reports the accepted revision with a different
	// route digest (W4).
	ErrRevisionConflict = errors.New("route manifest revision equals the accepted one with a different digest")
)

// Supersedes applies W4 against the revision and route digest a verifier
// last accepted; zero values mean it has accepted none. A router passes the
// highest revision it accepted: its staged manifest's while it holds one,
// else its applied manifest's (A3). It returns nil when s may be accepted.
// When s carries the accepted revision and digest, it is the manifest
// already held and accepting it changes nothing (F3).
func (s *Signed) Supersedes(revision uint64, digest [sha256.Size]byte) error {
	switch r := s.manifest.Revision; {
	case r < revision:
		return fmt.Errorf("%w: %d < %d", ErrRollback, r, revision)
	case r == revision && s.digest != digest:
		return fmt.Errorf("%w: revision %d", ErrRevisionConflict, r)
	}
	return nil
}
