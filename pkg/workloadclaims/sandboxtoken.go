// Signed sandbox tokens: the inventory's verifiable answer to "which pod sandbox
// is the calling process in". The inventory signs (sandbox ID, requester-key
// digest, CDS challenge nonce, its own node's IP) with an in-process key, so the
// binding is to one requester and fresh for exactly the issuance whose challenge
// it carries (docs/armtls.md, "Sandbox identity"). Freshness rides the same
// single-use CDS challenge as the evidence — no clock.
//
// The signature is only worth as much as CDS's confidence that the key is the
// inventory's, which is established out of band — see digests.go.

package workloadclaims

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// maxNonceLen bounds the challenge a token may carry; the CDS challenge is a
// 32-byte nonce, so this rejects a hostile POST /sandbox body stuffing a large
// OCTET STRING into the signed token.
const maxNonceLen = 128

// sandboxTokenDomainSep tags the token signature preimage so an inventory-key
// signature over a token can never be confused with any other statement by
// the same key. Its "v1" names the statement type, not the token structure —
// sandboxTokenVersion versions that, inside the signed bytes.
var sandboxTokenDomainSep = []byte("c8s/sandbox-token/v1\x00")

// sandboxTokenVersion is 2: v1 carried no inventory host, so CDS had no way to
// reach the inventory back for the sandbox's digests.
const sandboxTokenVersion = 2

// sandboxTokenASN1 is the DER structure the inventory signs.
//
//	SandboxToken ::= SEQUENCE {
//	    version        INTEGER,
//	    sandboxId      IA5String,
//	    keyDigest      OCTET STRING (32),  -- SHA-256(requester PKIX pubkey DER)
//	    nonce          OCTET STRING,       -- the CDS challenge for this issuance
//	    inventoryHost  IA5String           -- IP of the node serving the digests endpoint
//	}
//
// The host is an IP only; the port is not carried. CDS dials DigestsPort, which
// it holds itself — see digests.go for why that is the whole basis of the
// inventory's identity.
type sandboxTokenASN1 struct {
	Version       int
	SandboxID     string `asn1:"ia5"`
	KeyDigest     []byte
	Nonce         []byte
	InventoryHost string `asn1:"ia5"`
}

// SignedSandboxToken is the inventory's SandboxPath answer.
//
// It carries no credential for the signing key. CDS resolves that key by
// dialing the signer's own digests endpoint on a privileged port
// (DigestsClient.InventoryKey), which is what distinguishes the inventory from
// any other TEE sharing the node's launch measurement.
type SignedSandboxToken struct {
	// Token is the DER-encoded sandbox token.
	Token []byte `json:"token"`
	// Signature is the inventory key's ASN.1 ECDSA-SHA256 signature over the
	// domain-separated Token bytes.
	Signature []byte `json:"signature"`
}

func sandboxTokenSigningHash(tokenDER []byte) []byte {
	h := sha256.New()
	h.Write(sandboxTokenDomainSep)
	h.Write(tokenDER)
	return h.Sum(nil)
}

// RequesterKeyDigest is the caller-key commitment a sandbox token carries:
// SHA-256 over the canonical PKIX DER of pub. Both sides derive it from a
// parsed key, so a non-canonical caller encoding cannot split the binding.
func RequesterKeyDigest(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal requester key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// VerifiedSandbox is what a valid token establishes: which sandbox the
// requester is in, and which node's inventory vouched for it.
type VerifiedSandbox struct {
	SandboxID string
	// InventoryHost is the IP of the node whose inventory signed this token,
	// read from the signed bytes.
	InventoryHost string
}

// UnverifiedInventoryHost reads the inventory host out of an unverified token.
//
// It exists for one purpose: the host says which endpoint holds the key that
// would verify the signature, so it must be read before verification can
// happen. Nothing may be trusted on its basis — a caller uses it only to
// select a dial target it independently constrains, and a wrong value simply
// yields a key under which the signature fails. The authenticated host is the
// one Verify returns.
func UnverifiedInventoryHost(tokenDER []byte) (string, error) {
	var tok sandboxTokenASN1
	if _, err := asn1.Unmarshal(tokenDER, &tok); err != nil {
		return "", fmt.Errorf("workloadclaims: unmarshal sandbox token: %w", err)
	}
	return tok.InventoryHost, nil
}

// Verify checks the envelope against the inventory key (which the caller must
// have resolved from the inventory's own endpoint and trusts), the requester
// key, and the CDS
// challenge for this request. It fails closed on a bad signature, a malformed
// or wrong-version token, a nonce that is not this request's challenge, or a
// requester-key mismatch. nonce is the single-use challenge CDS is consuming
// for the issuance, so a token cannot be replayed against a later request or
// pre-signed against a future one.
func (s *SignedSandboxToken) Verify(inventoryPub *ecdsa.PublicKey, requesterPub crypto.PublicKey, nonce []byte) (VerifiedSandbox, error) {
	if inventoryPub == nil {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: no inventory key to verify the sandbox token against")
	}
	if len(nonce) == 0 {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: no challenge to verify the sandbox token freshness against")
	}
	if !ecdsa.VerifyASN1(inventoryPub, sandboxTokenSigningHash(s.Token), s.Signature) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token signature invalid")
	}
	var tok sandboxTokenASN1
	rest, err := asn1.Unmarshal(s.Token, &tok)
	if err != nil {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: unmarshal sandbox token: %w", err)
	}
	if len(rest) > 0 {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: %d trailing bytes after sandbox token", len(rest))
	}
	if tok.Version != sandboxTokenVersion {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: unsupported sandbox token version %d", tok.Version)
	}
	if !bytes.Equal(tok.Nonce, nonce) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token nonce does not match this request's challenge")
	}
	want, err := RequesterKeyDigest(requesterPub)
	if err != nil {
		return VerifiedSandbox{}, err
	}
	if !bytes.Equal(tok.KeyDigest, want) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token is bound to a different requester key")
	}
	if err := ValidateInventoryHost(tok.InventoryHost); err != nil {
		return VerifiedSandbox{}, err
	}
	return VerifiedSandbox{SandboxID: tok.SandboxID, InventoryHost: tok.InventoryHost}, nil
}

// SandboxTokenSigner signs sandbox tokens with an in-process P-256 key. The key
// never leaves the process and is not persisted; an inventory restart mints a
// new one, which CDS picks up because it reads the key from the inventory's own
// endpoint on every issuance rather than caching a credential.
type SandboxTokenSigner struct {
	key    *ecdsa.PrivateKey
	pubDER []byte
	host   string
}

// NewSandboxTokenSigner generates the signing key. host is the IP of the node
// serving this inventory's digests endpoint, signed into every token so CDS
// knows which endpoint holds the key that verifies it.
func NewSandboxTokenSigner(host string) (*SandboxTokenSigner, error) {
	if err := ValidateInventoryHost(host); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: generate sandbox signing key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal sandbox signing key: %w", err)
	}
	return &SandboxTokenSigner{key: key, pubDER: pubDER, host: host}, nil
}

// PublicKey is the signing key CDS fetches from the digests endpoint.
func (s *SandboxTokenSigner) PublicKey() *ecdsa.PublicKey { return &s.key.PublicKey }

// PublicKeyDER is PublicKey in PKIX DER, as IdentityPath serves it.
func (s *SandboxTokenSigner) PublicKeyDER() []byte { return s.pubDER }

// Sign issues a signed sandbox token binding sandboxID to the requester-key
// digest and the CDS challenge nonce for this issuance.
func (s *SandboxTokenSigner) Sign(sandboxID string, requesterKeyDigest, nonce []byte) (*SignedSandboxToken, error) {
	if len(nonce) == 0 || len(nonce) > maxNonceLen {
		return nil, fmt.Errorf("workloadclaims: sandbox token nonce must be 1..%d bytes", maxNonceLen)
	}
	der, err := asn1.Marshal(sandboxTokenASN1{
		Version:       sandboxTokenVersion,
		SandboxID:     sandboxID,
		KeyDigest:     requesterKeyDigest,
		Nonce:         nonce,
		InventoryHost: s.host,
	})
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal sandbox token: %w", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sandboxTokenSigningHash(der))
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: sign sandbox token: %w", err)
	}
	return &SignedSandboxToken{Token: der, Signature: sig}, nil
}
