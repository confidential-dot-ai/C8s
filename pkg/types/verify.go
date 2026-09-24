package types

import "encoding/json"

// Browser-facing attestation + over-encryption wire types for the c8s-verify
// protocol served by the router. These mirror c8s-verify-js/PROTOCOL.md
// and are consumed by the JavaScript client (c8s-verify-js) and any other
// out-of-cluster verifier. All key-exchange byte fields are base64url
// (unpadded); the evidence sub-fields follow the platform's attestation-rs
// evidence shape (SnpEvidence uses standard base64; see PROTOCOL.md for the
// per-platform encodings).

// AttestPQRequest is the body of POST /.well-known/c8s/attest-pq: the client's
// fresh challenge and its X-Wing encapsulation key. The server encapsulates to
// the key, so the hardware report can commit both sides of the key exchange.
type AttestPQRequest struct {
	Nonce   string `json:"nonce"`    // base64url, 32 bytes
	XWingEK string `json:"xwing_ek"` // base64url, 1216 bytes
}

const (
	// ProtocolVersion is the attest-pq identity-transcript domain: the exact
	// string overenc.IdentityTranscriptHash frames into report_data. It is a
	// hash input shipped in deployed evidence, so it never changes; the wire
	// discriminator clients check is the per-endpoint binding identifier below.
	ProtocolVersion = "c8s-verify/v1"

	// BindingAttestPQ / BindingAttestLB are the response binding identifiers
	// carried in AttestationBundle.Version by the two explicit attestation
	// endpoints. A client requires the identifier selected by its endpoint
	// mode and rejects the other response shape even if its evidence is
	// otherwise valid — there is no negotiation, alias, or fallback.
	BindingAttestPQ = "c8s/attest-pq/v1"
	BindingAttestLB = "c8s/attest-lb/v1"

	// MeshIdentityProofECDSASHA384 is the proof-of-possession algorithm.
	MeshIdentityProofECDSASHA384 = "ecdsa-sha384"
)

// MeshIdentityProof authenticates the PQ session transcript with the private
// key corresponding to the mesh leaf in AttestationBundle.CDSCertPEM. Hashes
// are unpadded base64url SHA-256; Signature is unpadded base64url ASN.1 DER
// ECDSA (minimal DER, as emitted by ecdsa.SignASN1 — the JS verifier rejects
// redundant integer padding).
type MeshIdentityProof struct {
	Algorithm    string `json:"algorithm"`      // MeshIdentityProofECDSASHA384
	LeafSHA256   string `json:"leaf_sha256"`    // base64url; exact leaf DER committed by report_data
	MeshCASHA256 string `json:"mesh_ca_sha256"` // base64url; issuing CA DER committed by report_data
	Signature    string `json:"signature"`      // base64url ASN.1 DER ECDSA signature
}

// FrontDoorMode names the credential model terminating public TLS in front of
// an attestation endpoint: cds (TEE-held mesh-issued serving key), acme
// (TEE-held in-guest ACME serving key), or webpki (host-visible Secret).
// attest-lb's transport binding rests on the serving key being TEE-held, so
// it is served only in the cds and acme shapes.
type FrontDoorMode string

const (
	FrontDoorModeCDS    FrontDoorMode = "cds"
	FrontDoorModeWebPKI FrontDoorMode = "webpki"
	FrontDoorModeACME   FrontDoorMode = "acme"
)

// AttestationBundle is the response body of the two explicit attestation
// endpoints, POST /.well-known/c8s/attest-pq and
// GET /.well-known/c8s/attest-lb?nonce=<b64url>. attest-pq binds report_data
// to the complete X-Wing key exchange, the session id, and the mesh identity
// (overenc.IdentityTranscriptHash); attest-lb binds it to the exact outer
// serving leaf plus the mesh identity (overenc.LBTranscriptHash) for native
// clients that ride ordinary nginx TLS. Version carries the endpoint's
// binding identifier (BindingAttestPQ / BindingAttestLB); a client requires
// the one its endpoint mode selects.
type AttestationBundle struct {
	Version    string          `json:"version"`      // BindingAttestPQ | BindingAttestLB
	Platform   string          `json:"platform"`     // "snp" | "az-snp" | "az-tdx" | "tdx"
	Generation string          `json:"generation"`   // AMD gen for "snp": milan|genoa|turin; empty otherwise
	Nonce      string          `json:"nonce"`        // echoed client nonce (b64url)
	Evidence   json.RawMessage `json:"evidence"`     // platform-shaped attestation-rs evidence
	CDSCertPEM string          `json:"cds_cert_pem"` // exact mesh leaf + issuing CA committed by report_data
	// FrontDoorMode is the credential model terminating public TLS in front
	// of the responder, committed by the endpoint's report_data transcript.
	FrontDoorMode FrontDoorMode `json:"front_door_mode"`
	// XWingEK (attest-pq only) echoes the client's encapsulation key, so a
	// saved bundle stays verifiable offline. A live client MUST compare it to
	// the key it sent, exactly like the nonce echo.
	XWingEK string `json:"xwing_ek,omitempty"`
	// XWingCT (attest-pq only) is the server's X-Wing ciphertext, committed by
	// report_data alongside the encapsulation key.
	XWingCT string `json:"xwing_ct,omitempty"`
	// SessionID (attest-pq only) is the 16-byte session identifier, committed
	// by report_data and framed into every tunnel record's AAD; attest-lb
	// creates no session.
	SessionID string `json:"session_id,omitempty"`
	// IdentityProof proves possession of the mesh leaf committed by
	// report_data, over the endpoint's transcript.
	IdentityProof *MeshIdentityProof `json:"identity_proof,omitempty"`
	// ServingLeafSHA256 (attest-lb only) is the unpadded base64url SHA-256 of
	// the serving-leaf DER the sidecar committed into report_data.
	// Informational: the client MUST recompute this hash from the leaf it
	// observed on its own TLS connection and verify the transcript with that
	// value — trusting the served field would let a relay substitute the leaf.
	ServingLeafSHA256 string `json:"serving_leaf_sha256,omitempty"`
	// CDSState (pinned-allowlist router) is CDS's rollout state bound to this
	// request's nonce; both transcripts commit overenc.StateDigest of its
	// exact state bytes. Its Bound is an attest-pq session's policy envelope.
	CDSState *SignedRolloutState `json:"cds_state,omitempty"`
}

// RolloutState is CDS's allowlist rollout state. Bound lists the policy
// digests that may still be executing, oldest first. See
// docs/allowlist-and-capabilities.md, "Rollout journal".
type RolloutState struct {
	Protocol  int      `json:"protocol"`
	Authority string   `json:"authority"`
	Position  uint64   `json:"position"`
	Head      string   `json:"head"`
	Version   string   `json:"allowlist_version"`
	Policy    string   `json:"policy"`
	Bound     []string `json:"bound"`
	Pending   string   `json:"pending,omitempty"`
	Lease     int64    `json:"lease_seconds"`
	Nonce     string   `json:"nonce,omitempty"`
}

// SignedRolloutState carries the exact RolloutState JSON bytes, base64 on the
// wire so every client hashes the bytes CDS signed, and an ASN.1 ECDSA
// signature over their SHA-384 by the mesh CA key.
type SignedRolloutState struct {
	State     []byte `json:"state"`
	Signature []byte `json:"signature"`
}

// HeaderField is one HTTP header field in a tunnel envelope, on the wire a
// two-element CBOR array [name, value]. A pair list preserves duplicate fields
// (Set-Cookie) and field order, which a header map cannot. CBOR only — the
// envelope never rides as JSON.
type HeaderField struct {
	_     struct{} `cbor:",toarray"`
	Name  string
	Value string
}

// TunnelRequest is the plaintext application request carried inside an
// over-encrypted record sent to POST /.well-known/c8s/tunnel. The whole request
// — method, path, headers, and body — is sealed, so a TLS-terminating proxy in
// front of the LB sees only ciphertext. The sidecar decrypts it and forwards the
// reconstructed request as plaintext to the backend (the cluster raTLS mesh wraps
// that hop).
type TunnelRequest struct {
	Method  string        `cbor:"method"`
	Path    string        `cbor:"path"`
	Headers []HeaderField `cbor:"headers,omitempty"`
	Body    []byte        `cbor:"body,omitempty"` // raw body, CBOR byte string
}

// TunnelResponse is the backend response, sealed back to the client.
type TunnelResponse struct {
	Status  int           `cbor:"status"`
	Headers []HeaderField `cbor:"headers,omitempty"`
	Body    []byte        `cbor:"body,omitempty"` // raw body, CBOR byte string
}
