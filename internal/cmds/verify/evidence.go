package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// attestationPath is the LB's explicit attest-pq endpoint for nonce-bound
// attestation evidence (client-first POST {nonce, xwing_ek}), per
// c8s-verify-js PROTOCOL.md. There is no alias for the retired /attestation
// path and no fallback to attest-lb: a response must carry the attest-pq
// binding identifier.
const attestationPath = "/.well-known/c8s/attest-pq"

// nonceSize is the verifier challenge length (bytes) for the endpoint flow.
const nonceSize = 32

// evidence is normalized attestation evidence ready for verification, plus the
// metadata needed to explain the result to a human. platform + rawEvidence are
// the self-describing evidence envelope ({platform, evidence}) forwarded
// verbatim to the verifier, so SEV-SNP, TDX, and az-snp all pass through in
// their own shape.
type evidence struct {
	// platform is the evidence-envelope platform discriminator (snp, tdx, az-snp…).
	platform string
	// rawEvidence is the platform-specific evidence object, forwarded verbatim.
	rawEvidence json.RawMessage
	// erd is the expected freshness anchor — the exact bytes the producer bound,
	// unpadded (48-byte SHA-384 for c8s bindings). Hardware-report verifiers
	// zero-pad it to the 64-byte REPORTDATA field; the Azure vTPM verifiers
	// compare it raw against the quote's extraData, so a pre-padded value fails
	// there (PROTOCOL.md "az-snp").
	erd []byte
	// fresh is true when erd binds a caller-supplied nonce, so a passing
	// verification proves the evidence was produced for THIS check (not replayed).
	fresh bool
	// source describes where the evidence came from (for output).
	source string
	// certSHA256 is the hex SHA-256 of the serving certificate (cert modes only).
	certSHA256 string
	// bindingNote explains what the REPORTDATA is bound to.
	bindingNote string
	// leaf is the CDS-issued leaf the evidence speaks for: the serving cert in
	// cert and discovery modes, the transcript-committed mesh leaf in
	// attest-pq mode, nil otherwise. Kept so --mesh-ca can check what CDS
	// actually signed. Every leaf set here has passed body authentication
	// (authenticateLeafBody, or verifyCommittedChain on attest-pq) AND one of
	// the body-authentication backstops below.
	leaf *x509.Certificate
	// leafBody is what authenticateLeafBody proved about the leaf's body
	// fields: BodySelfSigned (authenticated by its own attested key) or
	// BodyCAVouched (authenticated by nothing on its own). Meaningless when
	// leaf is nil.
	leafBody certutil.BodyAuthentication
	// leafChainVerified is true when the leaf's issuing chain was verified
	// against the operator-pinned --mesh-ca bundle while gathering, so a
	// CA-vouched body is authenticated by an anchor the operator chose.
	leafChainVerified bool
	// leafChainDerived is true when the leaf's issuing chain was checked
	// against the CA the responder committed into its own attestation
	// transcript (attest-pq). The transcript binds those CA bytes to the
	// hardware evidence, but the anchor is responder-chosen: it is not a
	// pinned trust anchor and the verdict must never treat it as one.
	leafChainDerived bool
	// frontDoor is what a discovery gather's live TLS handshake showed about
	// the front door's serving key (frontDoorNone when not discovery-sourced).
	frontDoor frontDoorObservation
	// frontDoorCertSHA256 is the hex SHA-256 of the leaf the live handshake
	// presented ("" when no handshake was observed).
	frontDoorCertSHA256 string
	// leafKeyProven is true when a live TLS handshake with the leaf completed,
	// which proves the presenter holds the attested private key. A forged body
	// carrying someone else's attested SubjectPublicKeyInfo cannot complete
	// one, so on that path possession — not the body check — is the backstop.
	leafKeyProven bool
	// sandboxID is the CRI pod sandbox the leaf names (cert modes only; ""
	// when the cert carries no sandbox-ID extension). CDS stamps it into the
	// signed area, so unlike the rest of this struct it is vouched by the mesh
	// CA rather than by the hardware evidence — see applySandboxPolicy.
	sandboxID string
	// sandboxErr records a carried sandbox-ID extension this build cannot
	// interpret. The verdict fails closed on it.
	sandboxErr error
	// rollout is the attest-pq bundle's CDS rollout state, signed by the
	// transcript-committed mesh CA and bound to the bundle's nonce; nil when
	// the bundle carries none. rolloutErr records a state that failed either
	// check. See applyPinPolicy.
	rollout    *types.RolloutState
	rolloutErr error
	// workload is the leaf's matched-workload stamp (cert modes only; nil when
	// the cert carries none). CA-vouched like the sandbox ID — see
	// applyWorkloadPolicy.
	workload *ratls.MatchedWorkload
	// workloadErr records a carried matched-workload extension this build
	// cannot interpret (or a duplicate). The verdict fails closed on it.
	workloadErr error
}

// platformOrDefault returns p, or "snp" when p is empty (the historical default
// for evidence carriers that predate the platform field). The verifier rejects a
// genuinely unknown platform, so a wrong guess fails closed.
func platformOrDefault(p string) string {
	if p == "" {
		return string(teetypes.PlatformSNP)
	}
	return p
}

// attestationResponse is the JSON the attest-pq endpoint returns. The evidence
// object is kept raw and forwarded verbatim (platform-specific); the version,
// nonce, session keys, served mesh chain, and identity proof (which together
// derive and authenticate the REPORTDATA binding) are parsed here.
type attestationResponse struct {
	Version       string                    `json:"version"`
	Platform      string                    `json:"platform"`
	Nonce         string                    `json:"nonce"`
	Evidence      json.RawMessage           `json:"evidence"`
	CDSCertPEM    string                    `json:"cds_cert_pem"`
	FrontDoorMode types.FrontDoorMode       `json:"front_door_mode"`
	XWingEK       string                    `json:"xwing_ek"`
	XWingCT       string                    `json:"xwing_ct"`
	SessionID     string                    `json:"session_id"`
	IdentityProof *types.MeshIdentityProof  `json:"identity_proof"`
	CDSState      *types.SignedRolloutState `json:"cds_state"`
}

// stateDigest is the transcript commitment to the bundle's rollout state.
func (r *attestationResponse) stateDigest() []byte {
	if r.CDSState == nil {
		return nil
	}
	return overenc.StateDigest(r.CDSState.State)
}

// leafTrust is what a caller can offer to authenticate a leaf body that is
// only CA-vouched. A self-issued leaf authenticates its own body under the
// attested key and needs neither of these.
type leafTrust struct {
	// keyProven is set by evidence sources that completed a TLS handshake
	// with the leaf: the peer demonstrably holds the private half of the
	// attested SubjectPublicKeyInfo, so it could not be replaying a body some
	// third party re-minted around a genuine attestation extension.
	keyProven bool
	// meshCA is the operator's --mesh-ca anchor (nil when unset). It is the
	// only thing that can authenticate a CA-vouched body on a source with no
	// proof of possession — a saved file, or a discovery document whose gather
	// made no usable handshake observation (non-TLS target, or a leaf the
	// document does not attest).
	meshCA *x509.CertPool
}

// gatherFromRATLSCert dials an RA-TLS TLS endpoint, captures the serving
// certificate without trusting PKI (trust comes from the embedded hardware
// attestation), and binds REPORTDATA to the certificate key.
func gatherFromRATLSCert(ctx context.Context, addr, serverName string, timeout time.Duration, trust leafTrust) (*evidence, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// INVARIANT: PKI verification is intentionally skipped — the RA-TLS
		// attestation in the cert extension is the trust anchor, verified below.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("dial %s: %w", addr, err)}
	}
	defer conn.Close()

	// tls.Dialer.DialContext always returns a *tls.Conn, so this assertion is safe.
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, &connectError{err: fmt.Errorf("%s presented no certificate", addr)}
	}
	// The handshake above completed against this leaf, so the peer holds the
	// attested key: that is the proof of possession this path relies on, not
	// the certificate body's own bytes.
	trust.keyProven = true
	return evidenceFromCert(certs[0], fmt.Sprintf("RA-TLS serving certificate at %s", addr), trust)
}

// authenticateLeafBody runs the shared certificate-body checks on an
// evidence-carrying leaf: validity (NotBefore within certutil.LeafValiditySkew,
// NotAfter with none) and, for a self-issued leaf, its own signature under its
// attested key. The attestation extension binds only the key, so without the
// signature check every other field of a self-signed body — subject, serial,
// validity — could be rewritten under a genuine extension and still verify.
// Failures are securityErrors: the response was reachable and well-formed but
// its certificate must not be trusted, so auto-mode never falls through past
// one.
func authenticateLeafBody(cert *x509.Certificate) (certutil.BodyAuthentication, error) {
	body, err := certutil.AuthenticateLeafBody(cert, time.Now())
	if err != nil {
		return body, &securityError{err: err}
	}
	return body, nil
}

// authorizeLeafBody is the fail-closed half of the body check: it turns
// certutil's classification plus what the caller can offer into a decision.
// A BodyCAVouched leaf has had NOTHING verified — x509.ParseCertificate checks
// no signature, so an attacker who keeps one genuine unauthenticated response
// can re-mint its certificate around the same attested SubjectPublicKeyInfo
// (same REPORTDATA, so the hardware evidence still verifies) with an Issuer DN
// one byte off the Subject, a junk Signature, NotAfter decades out, and any
// sandbox-ID / matched-workload stamp it likes. Only a verified chain or live
// proof of possession closes that; without one this is a securityError, so
// auto-mode never falls through past it and the verdict is a failure rather
// than an "evidence unavailable".
//
// Returns whether the chain was verified here, which is what tells the verdict
// a CA anchor stands behind the leaf.
func authorizeLeafBody(cert *x509.Certificate, body certutil.BodyAuthentication, trust leafTrust) (chainVerified bool, err error) {
	if body == certutil.BodySelfSigned || trust.keyProven {
		return false, nil
	}
	if trust.meshCA == nil {
		return false, &securityError{err: fmt.Errorf(
			"leaf certificate body is unauthenticated: the certificate is CA-issued (issuer != subject) and this evidence source proves neither the issuing chain nor possession of the attested key, so its validity window, subject and CA-vouched stamps are chosen by whoever produced the bytes — pass --mesh-ca to check the chain")}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     trust.meshCA,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, &securityError{err: fmt.Errorf("leaf does not chain to the --mesh-ca bundle: %w", err)}
	}
	return true, nil
}

// evidenceFromCert extracts the attestation extension from a certificate and
// binds REPORTDATA to the certificate's public key (localverify.CertEnvelope).
// The serving cert carries no per-request nonce, so the binding proves "this
// key was born in a TEE" but not freshness (fresh=false): the certificate is
// replayable within its validity window — a bound that only means anything
// once the body carrying that window is itself authenticated, which
// authenticateLeafBody + authorizeLeafBody enforce together.
func evidenceFromCert(cert *x509.Certificate, source string, trust leafTrust) (*evidence, error) {
	platform, raw, erd, err := localverify.CertEnvelope(cert)
	if err != nil {
		return nil, err
	}
	body, err := authenticateLeafBody(cert)
	if err != nil {
		return nil, err
	}
	chainVerified, err := authorizeLeafBody(cert, body, trust)
	if err != nil {
		return nil, err
	}
	binding := "REPORTDATA binds the certificate public key (no per-request nonce — replayable within the authenticated certificate validity window, which is the only freshness bound on this path)"
	sandboxID, sandboxErr := ratls.SandboxIDFromCert(cert)
	workload, workloadErr := ratls.MatchedWorkloadFromCert(cert)
	sum := sha256.Sum256(cert.Raw)
	return &evidence{
		platform:          platform,
		rawEvidence:       raw,
		erd:               erd,
		fresh:             false,
		source:            source,
		certSHA256:        hex.EncodeToString(sum[:]),
		bindingNote:       binding,
		leaf:              cert,
		leafBody:          body,
		leafChainVerified: chainVerified,
		leafKeyProven:     trust.keyProven,
		frontDoor:         frontDoorNone,
		sandboxID:         sandboxID,
		sandboxErr:        sandboxErr,
		workload:          workload,
		workloadErr:       workloadErr,
	}, nil
}

// insecureClient is the HTTP client for endpoints whose trust anchor is the
// attestation in the payload, not PKI on the hop.
func insecureClient(serverName string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}}
}

// gatherFromEndpoint fetches nonce-bound evidence from the attestation
// endpoint, client-first: it generates a fresh challenge and a throwaway
// X-Wing keypair, POSTs both, requires the response to echo them, and binds
// REPORTDATA to the complete key exchange + session id + nonce (a freshness
// proof). The keypair is discarded — this verifier never opens the channel.
func gatherFromEndpoint(ctx context.Context, base, serverName string, timeout time.Duration) (*evidence, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	clientKey, err := overenc.GenerateClientKey()
	if err != nil {
		return nil, fmt.Errorf("generate X-Wing key: %w", err)
	}
	endpoint, err := joinAttestationURL(base)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(types.AttestPQRequest{
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		XWingEK: base64.RawURLEncoding.EncodeToString(clientKey.EncapsulationKey()),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attest-pq request: %w", err)
	}

	client := insecureClient(serverName, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("POST %s: %w", endpoint, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &connectError{err: fmt.Errorf("POST %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("read response: %w", err)}
	}
	return evidenceFromEndpointJSON(data, nonce, clientKey.EncapsulationKey(), fmt.Sprintf("attestation endpoint %s", endpoint))
}

// evidenceFromEndpointJSON parses an attestation response. When expectNonce is
// non-nil (live fetch) the response must echo it and expectEK (the client's
// X-Wing encapsulation key); when nil (from-file) the response's own echoed
// values are used and the result is not a freshness proof.
func evidenceFromEndpointJSON(data, expectNonce, expectEK []byte, source string) (*evidence, error) {
	var r attestationResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse attestation response: %w", err)
	}
	// This parser consumes exactly the attest-pq binding. Anything else —
	// including the retired "c8s-verify/v1" tag or a cross-endpoint attest-lb
	// response — is rejected even if its evidence is otherwise valid: the
	// endpoints are non-negotiated and there is no downgrade.
	if r.Version != types.BindingAttestPQ {
		return nil, fmt.Errorf("attestation response version %q is not the attest-pq binding %q", r.Version, types.BindingAttestPQ)
	}
	if len(r.Evidence) == 0 {
		return nil, fmt.Errorf("attestation response carries no evidence")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.Nonce, "="))
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	fresh := false
	if expectNonce != nil {
		if !bytes.Equal(nonce, expectNonce) {
			return nil, &securityError{err: fmt.Errorf("response nonce does not echo the challenge (possible replay or MITM)")}
		}
		fresh = true
	}

	xwingEK, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.XWingEK, "="))
	if err != nil {
		return nil, fmt.Errorf("decode xwing_ek: %w", err)
	}
	if expectEK != nil && !bytes.Equal(xwingEK, expectEK) {
		return nil, &securityError{err: fmt.Errorf("response xwing_ek does not echo the key the client sent (possible replay or MITM)")}
	}
	xwingCT, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.XWingCT, "="))
	if err != nil {
		return nil, fmt.Errorf("decode xwing_ct: %w", err)
	}
	sessionID, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.SessionID, "="))
	if err != nil {
		return nil, fmt.Errorf("decode session_id: %w", err)
	}
	if len(xwingCT) == 0 {
		return nil, fmt.Errorf("attestation response has no xwing_ct; pass --expected-report-data to verify bare evidence")
	}

	leaf, ca, err := committedMeshChain(r.CDSCertPEM, r.IdentityProof)
	if err != nil {
		return nil, err
	}
	// The transcript rejects wrong-size keys and nonces: report_data framing is
	// length-prefixed, so a wrong-size field can never reproduce the served
	// hash — refuse it here instead of failing report-data match downstream.
	erd, err := overenc.IdentityTranscriptHash(r.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, leaf.Raw, ca.Raw, r.stateDigest())
	if err != nil {
		return nil, fmt.Errorf("compute identity transcript: %w", err)
	}
	// §5 step 4 (proof of possession) and step 5 (chain to the committed CA)
	// come before anything from the leaf is surfaced. The hardware evidence
	// itself is verified downstream against erd; a failure here means the
	// responder does not hold the committed identity, whatever its evidence
	// says. The chain check anchors to the CA the responder committed — a
	// derived anchor, recorded as such: only --mesh-ca turns it into a
	// verified chain (applyChainAnchorPolicy).
	if err := verifyIdentityProof(r.IdentityProof, leaf, erd); err != nil {
		return nil, &securityError{err: err}
	}
	if err := verifyCommittedChain(leaf, ca); err != nil {
		return nil, &securityError{err: err}
	}

	// The CA-vouched leaf stamps, read off the transcript-committed mesh leaf.
	// --mesh-ca / --workload enforce them downstream exactly as in cert modes.
	sandboxID, sandboxErr := ratls.SandboxIDFromCert(leaf)
	workload, workloadErr := ratls.MatchedWorkloadFromCert(leaf)
	var rollout *types.RolloutState
	var rolloutErr error
	if r.CDSState != nil {
		rollout, rolloutErr = verifyRolloutState(r.CDSState, ca, nonce)
	}
	return &evidence{
		rollout:          rollout,
		rolloutErr:       rolloutErr,
		platform:         platformOrDefault(r.Platform),
		rawEvidence:      r.Evidence,
		erd:              erd,
		fresh:            fresh,
		source:           source,
		bindingNote:      "REPORTDATA binds the identity transcript: front-door mode + session keys + nonce + the exact mesh leaf and its transcript-committed issuing CA (leaf proof of possession verified)",
		leaf:             leaf,
		leafChainDerived: true,
		frontDoor:        frontDoorNone,
		sandboxID:        sandboxID,
		sandboxErr:       sandboxErr,
		workload:         workload,
		workloadErr:      workloadErr,
	}, nil
}

// verifyRolloutState checks that ca's key signed the state and that the state
// answers nonce.
func verifyRolloutState(signed *types.SignedRolloutState, ca *x509.Certificate, nonce []byte) (*types.RolloutState, error) {
	key, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mesh CA key is %T, not ECDSA", ca.PublicKey)
	}
	sum := sha512.Sum384(signed.State)
	if !ecdsa.VerifyASN1(key, sum[:], signed.Signature) {
		return nil, fmt.Errorf("CDS rollout state signature does not verify against the committed mesh CA")
	}
	var st types.RolloutState
	if err := json.Unmarshal(signed.State, &st); err != nil {
		return nil, fmt.Errorf("decode CDS rollout state: %w", err)
	}
	if st.Nonce != hex.EncodeToString(nonce) {
		return nil, fmt.Errorf("CDS rollout state answers another nonce")
	}
	return &st, nil
}

// committedMeshChain parses the served mesh chain and returns the leaf plus
// the issuing CA the identity proof commits: the first CERTIFICATE block is
// the mesh leaf; the CA is selected among the remaining blocks by
// SHA-256(DER) == identity_proof.mesh_ca_sha256 — by commitment, not by
// position, so an extra served certificate cannot displace the CA the
// transcript binds.
func committedMeshChain(chainPEM string, proof *types.MeshIdentityProof) (leaf, ca *x509.Certificate, err error) {
	if proof == nil {
		return nil, nil, fmt.Errorf("attestation response carries no identity_proof")
	}
	certs, err := certutil.ParsePEMCertificates([]byte(chainPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("parse cds_cert_pem: %w", err)
	}
	if len(certs) < 2 {
		return nil, nil, fmt.Errorf("cds_cert_pem must carry the mesh leaf and its issuing CA, got %d certificate(s)", len(certs))
	}
	leaf = certs[0]
	caHash, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(proof.MeshCASHA256, "="))
	if err != nil {
		return nil, nil, fmt.Errorf("decode identity proof mesh_ca_sha256: %w", err)
	}
	for _, candidate := range certs[1:] {
		sum := sha256.Sum256(candidate.Raw)
		if bytes.Equal(sum[:], caHash) {
			// Equal hashes mean byte-equal certificates, so a repeat is not
			// ambiguous; take the first.
			return leaf, candidate, nil
		}
	}
	return nil, nil, &securityError{err: fmt.Errorf("no served certificate matches the transcript-committed mesh_ca_sha256 (possible CA substitution)")}
}

// verifyIdentityProof checks proof of possession of the mesh leaf key (§5
// step 4): the proof must commit exactly the served leaf and carry an
// ECDSA-SHA384 signature by that leaf's key over sha512.Sum384(transcript) —
// the same construction the sidecar's prove() emits.
func verifyIdentityProof(proof *types.MeshIdentityProof, leaf *x509.Certificate, transcript []byte) error {
	if proof.Algorithm != types.MeshIdentityProofECDSASHA384 {
		return fmt.Errorf("unsupported identity proof algorithm %q (want %q)", proof.Algorithm, types.MeshIdentityProofECDSASHA384)
	}
	claimed, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(proof.LeafSHA256, "="))
	if err != nil {
		return fmt.Errorf("decode identity proof leaf_sha256: %w", err)
	}
	leafHash := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(claimed, leafHash[:]) {
		return fmt.Errorf("identity proof leaf_sha256 does not match the served mesh leaf")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("mesh leaf public key is %T, want ECDSA", leaf.PublicKey)
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(proof.Signature, "="))
	if err != nil {
		return fmt.Errorf("decode identity proof signature: %w", err)
	}
	digest := sha512.Sum384(transcript)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return fmt.Errorf("identity proof signature did not verify: the responder does not hold the committed mesh leaf key")
	}
	return nil
}

// verifyCommittedChain requires the committed mesh leaf to be a currently
// valid certificate issued by the committed CA (§5 step 5) — that CA chain is
// what authenticates the leaf's body fields. Validity on both certificates
// uses the same bounded NotBefore skew as every other cert-sourced path
// (certutil.AuthenticateLeafBody). The CA here is transcript-derived, not
// operator-pinned; --mesh-ca additionally pins it via the standard chain
// check downstream.
func verifyCommittedChain(leaf, ca *x509.Certificate) error {
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("mesh leaf is not signed by the transcript-committed CA: %w", err)
	}
	now := time.Now()
	for _, c := range []struct {
		role string
		cert *x509.Certificate
	}{{"leaf", leaf}, {"CA", ca}} {
		// The classification is deliberately unused on this path: the
		// CheckSignatureFrom above already authenticated the leaf body against
		// the CA, and the CA's own DER is hashed into the identity transcript
		// the hardware evidence is bound to, so neither body rests on a
		// self-signature. AuthenticateLeafBody is called here purely for the
		// shared validity rule.
		if _, err := certutil.AuthenticateLeafBody(c.cert, now); err != nil {
			return fmt.Errorf("committed mesh %s: %w", c.role, err)
		}
	}
	return nil
}

// keyAnchor extracts the unpadded SHA-384 anchor from ReportDataForKey's
// zero-padded 64-byte REPORTDATA — the form producers bind (see
// attestclient.MakeSNPRATLSAttestFunc) and Azure vTPM quotes carry raw.
func keyAnchor(rd [64]byte) []byte { return rd[:sha512.Size384] }

// gatherFromFile loads evidence from a saved PEM certificate or attestation
// response JSON. overrideERD, when non-nil, replaces the computed REPORTDATA —
// used to inspect bare evidence that carries no key/session binding.
//
// A saved file is bytes with no connection behind them, so trust never
// carries proof of possession here: a CA-issued certificate in it is
// authenticated by --mesh-ca or not at all (authorizeLeafBody).
func gatherFromFile(data []byte, overrideERD []byte, source string, trust leafTrust) (*evidence, error) {
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		if overrideERD != nil {
			// A certificate's REPORTDATA binding is the certificate key; an
			// override would silently replace a real binding with an arbitrary
			// value while still reporting "binds the certificate public key".
			return nil, fmt.Errorf("--expected-report-data does not apply to a certificate (its binding is the certificate key)")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return evidenceFromCert(cert, source, trust)
	}
	if overrideERD != nil {
		ev, err := evidenceFromBareJSON(data, overrideERD, source)
		if err == nil {
			return ev, nil
		}
		// fall through to full-response parsing if it wasn't bare evidence
	}
	return evidenceFromEndpointJSON(data, nil, nil, source)
}

// evidenceFromBareJSON parses a bare {platform, evidence:{attestation_report,
// cert_chain:{vcek}}} object (no session keys) and binds the caller-supplied
// REPORTDATA.
func evidenceFromBareJSON(data []byte, erd []byte, source string) (*evidence, error) {
	var r attestationResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if len(r.Evidence) == 0 {
		return nil, fmt.Errorf("bare evidence has no evidence object")
	}
	return &evidence{
		platform:    platformOrDefault(r.Platform),
		rawEvidence: r.Evidence,
		erd:         erd,
		fresh:       false,
		source:      source,
		bindingNote: "REPORTDATA supplied via --expected-report-data (not independently bound)",
		frontDoor:   frontDoorNone,
	}, nil
}

// joinAttestationURL appends the well-known attestation path to a base URL
// (scheme + host[:port]). The challenge travels in the POST body.
func joinAttestationURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = attestationPath
	return u.String(), nil
}

// parseExpectedReportData decodes the hex REPORTDATA / TPM-nonce anchor
// override, keeping the caller's exact bytes (verifiers pad per platform —
// see evidence.erd).
func parseExpectedReportData(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("--expected-report-data is not hex: %w", err)
	}
	// The binding digest length isn't fixed across platforms/schemes (SHA-384 =
	// 48, a raw nonce, etc.). The only hard constraint is 1–64 bytes.
	if len(raw) == 0 || len(raw) > 64 {
		return nil, fmt.Errorf("--expected-report-data is %d bytes, want 1–64", len(raw))
	}
	return raw, nil
}
