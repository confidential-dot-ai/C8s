package cds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// AttestHandler serves POST /attest by verifying TEE evidence and signing the
// requester's CSR in-process.
//
// THREAT MODEL: the image check is the only thing standing between an
// attacker who controls a TEE workload and a CA-signed leaf for any subject
// they choose: the pinned node set for a node, PodImages for a Pod whose
// claims the quote binds. Each gate is independent of the other and a set
// that names no image admits nobody.
type AttestHandler struct {
	Challenges        attestation.Challenges
	AttestationClient remote.Client
	MeshCA            meshCA
	CertTTL           time.Duration

	// RequestTimeout caps how long /attest may spend on attestation
	// verification + signing. Zero = no timeout.
	RequestTimeout time.Duration

	// NodeImages are the node images permitted to obtain a signed leaf, each
	// matched as one entry: its launch digest with the registers measured from
	// the same build. Read per request, so the set in force decides.
	NodeImages armtls.PinSource

	// PodImages grants only quote-bound Pod mesh issuance. It is never used
	// for node callbacks, operator authorization, or node credential release.
	PodImages []remote.ImagePin

	// Policy enforces SAN/CN constraints on the CSR before signing. Without
	// this, an attestation-passing workload could mint a leaf for any
	// subject — see THREAT MODEL on issuer.CA.SignCSR.
	Policy issuer.CSRPolicy

	// SANValidation, when true, binds Policy.SourceIP to the request's
	// RemoteAddr at handler time. When false, Policy.SourceIP stays empty and
	// ValidateCSR rejects any CSR carrying IP SANs.
	SANValidation bool

	// AllowlistStore, when set, gates a sandbox's running images: every image
	// the inventory reports must be allowlisted (docs/armtls.md), all checked
	// against ONE atomic policy snapshot which also decides the
	// matched-workload stamp. nil rejects any request carrying a sandbox
	// token, since it could not be checked.
	AllowlistStore policyStore

	// PolicySnapshots memoizes that snapshot between allowlist writes, so the
	// issuance path does not re-read and re-hash the whole document per
	// request. nil loads afresh every time — same decision, more work.
	PolicySnapshots *policySnapshotCache

	// NamedCertTTL caps the TTL of a leaf that carries a matched-workload
	// stamp — the documented stale-identity bound. It can only shorten
	// issuer.MaxNamedLeafTTL, never raise it; zero means the ceiling itself.
	// Never applied to membership-only leaves.
	NamedCertTTL time.Duration

	// RouterCertTTL caps the TTL of a leaf for a sandbox the inventory reports
	// a router-role container in. It is shorter than the delay before an
	// allowlist write takes effect on nodes, so every router renews under it
	// first.
	// Zero leaves router leaves uncapped.
	RouterCertTTL time.Duration

	// SandboxDigests resolves a sandbox's inventory: its signing key and what
	// the sandbox is running, over mutually-attested armTLS to a privileged
	// port. nil rejects any request carrying a sandbox token, for the same
	// reason as a nil AllowlistStore.
	SandboxDigests sandboxDigestSource

	// InventoryHosts bounds which addresses the callback may dial — the
	// operator's node CIDRs. Empty rejects any request carrying a sandbox
	// token: without it a workload could point CDS at its own pod IP and
	// answer as the inventory.
	InventoryHosts workloadclaims.CIDRHosts

	// SandboxBindings records which inventory vouched for a sandbox, so a
	// later decision about that sandbox asks the same one rather than one the
	// requester names (internal/sandboxledger). nil records nothing.
	SandboxBindings sandboxBinder
}

// sandboxBinder records the inventory that vouched for a sandbox. Record
// reports whether the binding holds; a false is never a reason to refuse
// issuance — see recordSandboxBinding.
type sandboxBinder interface {
	Record(sandboxID, inventoryHost string) bool
}

// sandboxDigestSource is the inventory callback, satisfied by
// *workloadclaims.DigestsClient. An interface so tests can drive issuance
// without standing up an armTLS inventory. FetchSandbox returns the whole
// answer — the deduplicated digests view and the per-container (digest, argv)
// view — so one fetch backs both the membership gate and workload matching.
type sandboxDigestSource interface {
	InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error)
	FetchSandbox(ctx context.Context, host, sandboxID string) (workloadclaims.SandboxDigestsResponse, error)
}

// issuanceProfile is the kind of identity one /attest request asks for: a node,
// optionally in a sandbox the inventory vouched for, or a Pod CVM whose quote
// binds its claims. HandleAttest selects one per request and runs every shared
// gate over it in one order. A refusing method writes its own response and log
// line and reports false; resolveWorkload's error is refused by the handler.
type issuanceProfile interface {
	// bind is the REPORTDATA this profile requires the evidence to carry for
	// the requester's CSR key and this request's challenge, and the sandbox
	// the leaf is stamped with.
	bind(ctx context.Context, w http.ResponseWriter, csrPub *ecdsa.PublicKey, challenge []byte) ([64]byte, workloadclaims.VerifiedSandbox, bool)

	// admitImage holds the verified evidence to this profile's image policy —
	// see THREAT MODEL above.
	admitImage(w http.ResponseWriter, verified remote.VerifyResponse, launchDigest string) bool

	resolveWorkload(ctx context.Context, sandbox workloadclaims.VerifiedSandbox) (matched *armtls.MatchedWorkload, router bool, err error)

	// clientDocument is the digest stamped on the leaf, with the raw claim the
	// issuance record names it by.
	clientDocument() (stamped []byte, recorded string)

	recordIssued(sandbox workloadclaims.VerifiedSandbox)
}

func (h AttestHandler) HandleAttest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.RequestTimeout)
		defer cancel()
	}

	req, fields, ok := decodeAttestRequest(w, r)
	if !ok {
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}
	if !h.Challenges.Consume(challengeBytes) {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}

	csr, err := certutil.ParseCSRPEM([]byte(req.CSR))
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	var profile issuanceProfile = nodeIssuance{
		h:          h,
		req:        req,
		remoteAddr: r.RemoteAddr,
	}
	if len(req.PodClaims) > 0 {
		claims, claimErr := workloadclaims.DecodePodClaims(req.PodClaims)
		if cause := h.podProfileRefusal(req, fields, csr, claimErr); cause != "" {
			slog.Warn("Pod attestation profile refused", "reason", cause, "remote_addr", r.RemoteAddr)
			httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "Pod attestation profile not authorized")
			return
		}
		profile = podIssuance{
			h:          h,
			req:        req,
			claims:     claims,
			remoteAddr: r.RemoteAddr,
		}
	}
	csrPubKey, err := attestation.ECDSAPublicKeyFromCSR(csr)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	// challengeBytes was consumed above, so this binding is fresh for exactly
	// this issuance.
	expectedReportData, sandbox, ok := profile.bind(ctx, w, csrPubKey, challengeBytes)
	if !ok {
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid evidence: %s", err))
		return
	}

	verifyReq := remote.NewVerifyRequestNoToken(req.Evidence, &remote.VerifyParams{
		ExpectedReportData: expectedReportData[:sha512.Size384],
	})
	verifyResp, err := h.AttestationClient.VerifyEnforced(ctx, verifyReq)
	if err != nil {
		status, code, msg := classifyVerifyError(err)
		slog.Warn("attestation verification failed", "status", status, "error", err, "remote_addr", r.RemoteAddr)
		httputil.WriteError(w, status, code, msg)
		return
	}

	launchDigest := strings.ToLower(verifyResp.Result.Claims.LaunchDigest)
	if !profile.admitImage(w, verifyResp, launchDigest) {
		return
	}

	policy := h.Policy
	if h.SANValidation {
		policy.SourceIP = issuer.SourceIPFromRemoteAddr(r.RemoteAddr)
	}
	if err := issuer.ValidateCSR(csr, policy); err != nil {
		slog.Warn("CSR validation failed", "error", err, "remote_addr", r.RemoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
		return
	}

	matched, router, err := profile.resolveWorkload(ctx, sandbox)
	if err != nil {
		// The detail stays in the log. A requester picks both the sandbox ID and
		// the address CDS just dialled, so echoing what happened there would
		// hand it a reachability oracle for CDS's network position.
		slog.Warn("sandbox workload rejected",
			"sandbox_id", sandbox.SandboxID, "inventory_addr", sandbox.InventoryHost, "error", err,
			"remote_addr", r.RemoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "sandbox workload not authorized")
		return
	}

	if ctx.Err() != nil {
		httputil.WriteError(w, http.StatusGatewayTimeout, types.ErrorCodeTimeout, "request timeout")
		return
	}

	ttl := h.leafTTL(matched, router)
	// One read: the certificate that signs the leaf is the chain returned with it.
	signing, issuing := h.MeshCA.Current()
	if !issuing {
		// A replica that stopped serving between the gate and the signature.
		httputil.WriteError(w, http.StatusServiceUnavailable, types.ErrorCodeInternal, "this CDS holds no mesh CA to sign with")
		return
	}
	clientDocument, clientDocumentDigest := profile.clientDocument()
	// The evidence verified above is bound to the consumed challenge and so is
	// not embeddable; the leaf carries the CSR's own key-bound armTLS extension
	// instead (issuer.SignCSR copies it).
	certPEM, leafCN, serial, err := signing.CA.SignCSR(issuer.SignCSRParams{
		CSR:                  csr,
		TTL:                  ttl,
		Evidence:             evidenceJSON,
		SandboxID:            sandbox.SandboxID,
		MatchedWorkload:      matched,
		ClientDocumentDigest: clientDocument,
	})
	if errors.Is(err, issuer.ErrSubjectDenied) {
		slog.Warn("leaf subject denied", "error", err, "remote_addr", r.RemoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
		return
	}
	if err != nil {
		slog.Error("in-process sign failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, err.Error())
		return
	}

	profile.recordIssued(sandbox)

	// The issuance record is the audit event for a granted mesh identity: the
	// serial names the leaf, the SANs the identity it carries, launch_digest what
	// attested for it, and a named leaf adds its workload, policy and sandbox.
	issued := []any{
		"cn", leafCN,
		"sans", csr.DNSNames,
		"serial", serialHex(serial),
		"ttl", ttl,
		"launch_digest", launchDigest,
		"remote_addr", r.RemoteAddr,
	}
	if sandbox.SandboxID != "" {
		issued = append(issued, "sandbox_id", sandbox.SandboxID, "inventory_addr", sandbox.InventoryHost)
	}
	if matched != nil {
		issued = append(issued,
			"workload", matched.Name,
			"allowlist_version", matched.AllowlistVersion,
			"allowlist_digest", hex.EncodeToString(matched.AllowlistDigest))
	}
	if clientDocument != nil {
		issued = append(issued, "client_document_digest", clientDocumentDigest)
	}
	slog.Info("certificate issued (in-process)", issued...)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(slices.Concat(certPEM, signing.CertPEM))
}

// decodeAttestRequest strictly decodes the request body, or writes the
// refusal and reports false.
func decodeAttestRequest(w http.ResponseWriter, r *http.Request) (types.AttestRequestBody, map[string]json.RawMessage, bool) {
	// The route's capBody bounds the body; a body over that bound is a size
	// error, not malformed JSON.
	var req types.AttestRequestBody
	raw, readErr := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(readErr, &tooLarge) {
		httputil.WriteError(w, http.StatusRequestEntityTooLarge, types.ErrorCodeInvalidRequest, "attestation request exceeds the request size limit")
		return req, nil, false
	}
	if readErr != nil || strictjson.Validate(raw) != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, "invalid attestation request JSON")
		return req, nil, false
	}
	// fields tells an absent runtime_extensions from an explicit null;
	// the strict decode that follows rejects any field the body does not name.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, "invalid attestation request JSON")
		return req, nil, false
	}
	if err := strictjson.Unmarshal(raw, &req); err != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return req, nil, false
	}
	if len(req.RuntimeExtensions) > 0 && !req.Evidence.Platform.HasRegisters() {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			"runtime_extensions requires evidence from a platform with runtime measurement registers")
		return req, nil, false
	}
	return req, fields, true
}

// leafTTL is an issued leaf's lifetime. issuer.MaxNamedLeafTTL is a ceiling
// NamedCertTTL can only lower; a non-positive NamedCertTTL lands on it.
func (h AttestHandler) leafTTL(matched *armtls.MatchedWorkload, router bool) time.Duration {
	ttl := issuer.CapTTL(h.CertTTL, issuer.MaxLeafTTL)
	if matched != nil {
		namedTTL := issuer.MaxNamedLeafTTL
		if h.NamedCertTTL > 0 && h.NamedCertTTL < namedTTL {
			namedTTL = h.NamedCertTTL
		}
		ttl = issuer.CapTTL(ttl, namedTTL)
	}
	if router && h.RouterCertTTL > 0 {
		ttl = min(ttl, h.RouterCertTTL)
	}
	return ttl
}

// matchPinnedNodeImage holds the verified evidence to one node image this CDS
// certifies, judging the platform and extensions the caller claims.
func (h AttestHandler) matchPinnedNodeImage(verified remote.VerifyResponse, claimedPlatform teetypes.PlatformType, claimedExtensions []string) error {
	images := h.NodeImages.Current().Images
	if len(images) == 0 {
		return errors.New("this CDS certifies no node image")
	}
	return armtls.EnforceImages(verified, images, claimedPlatform, claimedExtensions)
}

// serialHex renders a certificate serial the way `openssl x509 -serial` does,
// so an issuance record can be matched against a leaf in hand.
func serialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return fmt.Sprintf("%X", serial)
}

// verifySandboxToken verifies an inventory-signed sandbox token and returns its
// sandbox ID. The chain (docs/armtls.md, "Sandbox identity"): the envelope's
// signing key is fetched from the inventory's own endpoint on a node address
// the operator configured; that key must sign the token; the token's nonce must
// be this request's challenge (freshness, single-use); and its key digest must
// name the requester's CSR key — so only the key's holder can redeem it, only
// for this issuance, and only with inventory provenance.
func (h AttestHandler) verifySandboxToken(ctx context.Context, raw json.RawMessage, requesterPub crypto.PublicKey, nonce []byte) (workloadclaims.VerifiedSandbox, error) {
	if h.SandboxDigests == nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token presented but this CDS cannot reach an inventory to verify it")
	}
	if len(h.InventoryHosts) == 0 {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token presented but the inventory callback has no node addresses to bound it")
	}
	var token workloadclaims.SignedSandboxToken
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&token); err != nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("decode sandbox token: %w", err)
	}

	// The host says which endpoint holds the key that would verify the
	// signature, so it has to be read before verification can happen. Nothing
	// is trusted on its basis: it only selects a dial target, which must be a
	// node address the operator configured — a pod IP is never dialed, so a
	// workload cannot stand in for its node's inventory. A wrong host simply
	// yields a key the signature fails under.
	host, err := workloadclaims.UnverifiedInventoryHost(token.Token)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	if !h.InventoryHosts.Contains(host) {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token names an inventory outside the node bound")
	}
	// The key comes from the inventory's own endpoint on a privileged port,
	// which is what separates the inventory from a compromised workload in the
	// same node: an unprivileged pod cannot bind the node's network namespace
	// (the chart's deny-host-namespaces policy). Measurement alone cannot make
	// that distinction on node-CVM, where every pod shares the node's.
	inventoryPub, err := h.SandboxDigests.InventoryKey(ctx, host)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("resolve inventory key: %w", err)
	}
	// Freshness is the challenge itself: the token must carry the same nonce
	// CDS is consuming for this request, so it cannot be replayed against a
	// later request or pre-signed against a future one.
	sandbox, err := token.Verify(inventoryPub, requesterPub, nonce)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	if err := armtls.ValidateSandboxID(sandbox.SandboxID); err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	// The prefix is reserved for Pod CVM issuance (PodInstancePrefix).
	if strings.HasPrefix(sandbox.SandboxID, workloadclaims.PodInstancePrefix) {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox ID prefix %q is reserved for Pod CVM issuance", workloadclaims.PodInstancePrefix)
	}
	return sandbox, nil
}

// resolveSandboxWorkload asks the sandbox's own inventory what it is running
// (exactly once), loads one atomic policy snapshot, and makes both attest-time
// workload decisions from those two values (docs/armtls.md, "Sandbox identity"
// and "Matched workload"):
//
//  1. The membership gate: every image the inventory reports must be
//     allowlisted before issuing. It deliberately does NOT require the running
//     set to match a whole workload entry: issuance happens at arbitrary
//     points in the pod lifecycle — while a user init container runs, between
//     main containers coming up, while one restarts, and after completed init
//     containers are reaped — and in every one of those the running set is a
//     strict subset of what the pod declares. Gating on the whole set would
//     deny certificates for ordinary lifecycle states, permanently so for pods
//     with init containers. Membership is subset-safe: any subset of an
//     allowlisted set is still allowlisted. A failure here refuses issuance.
//
//  2. The matched-workload stamp: when the high-water (digest, argv) inventory
//     additionally matches exactly one allowlist entry, that name and the
//     snapshot's (version, digest) are returned for CDS to stamp. Every
//     failure to establish the name — an old inventory without the containers
//     view, a malformed or self-disagreeing answer, no or ambiguous match —
//     suppresses the stamp and preserves today's membership-only issuance,
//     because incomplete pods need a mesh certificate to bootstrap. Pinned
//     verifiers fail closed on the absent stamp.
//
// No sandbox ⇒ nothing to check: a requester that presents no token gets a
// leaf with no sandbox ID and no stamp. With a token, an unreachable inventory
// or allowlist store, a malformed digests view, or a non-allowlisted image is
// fail-closed — CDS cannot establish what the pod runs, or has established
// that it should not run, and it never stamps from stale cached state.
func (h AttestHandler) resolveSandboxWorkload(ctx context.Context, sandbox workloadclaims.VerifiedSandbox) (matched *armtls.MatchedWorkload, router bool, err error) {
	if sandbox.SandboxID == "" {
		return nil, false, nil
	}
	if h.AllowlistStore == nil {
		return nil, false, fmt.Errorf("sandbox token presented but this CDS has no allowlist to check it against")
	}
	if h.SandboxDigests == nil {
		return nil, false, fmt.Errorf("sandbox token presented but this CDS cannot reach the inventory for its digests")
	}
	resp, err := h.SandboxDigests.FetchSandbox(ctx, sandbox.InventoryHost, sandbox.SandboxID)
	if err != nil {
		return nil, false, fmt.Errorf("resolve sandbox digests from %s: %w", sandbox.InventoryHost, err)
	}
	snapshot, err := h.policySnapshot()
	if err != nil {
		return nil, false, err
	}

	if len(resp.Digests) == 0 {
		// "No containers" is not "nothing to check" — it is no evidence at all,
		// and looping over it would pass the gate vacuously. A sandbox always
		// runs at least the sidecar that is asking, so an empty answer means
		// the inventory is still syncing (or is lying), both of which must wait.
		return nil, false, fmt.Errorf("inventory reports no containers in sandbox %s", sandbox.SandboxID)
	}
	membership := make(map[string]struct{}, len(resp.Digests))
	for _, d := range resp.Digests {
		digest, err := types.ParseDigest(d)
		if err != nil {
			return nil, false, fmt.Errorf("container digest %q: %w", d, err)
		}
		if !snapshot.Contains(digest.String()) {
			return nil, false, fmt.Errorf("container image %s is not allowlisted", digest)
		}
		membership[digest.String()] = struct{}{}
	}

	router = slices.ContainsFunc(resp.Containers, func(c workloadclaims.SandboxContainer) bool {
		return c.Role == workloadclaims.RouterRole
	})
	return h.matchWorkload(ctx, snapshot, resp, membership, sandbox), router, nil
}

// policySnapshot returns the one immutable snapshot this issuance decides
// against, memoized when the handler was given a cache.
func (h AttestHandler) policySnapshot() (*PolicySnapshot, error) {
	if h.PolicySnapshots == nil {
		return loadPolicySnapshot(h.AllowlistStore)
	}
	return h.PolicySnapshots.snapshot(h.AllowlistStore)
}

// matchWorkload resolves the matched-workload stamp from an inventory answer
// whose digests view already passed the membership gate. It never refuses
// issuance: every failure returns nil (unnamed) with a bounded log line —
// the diagnostics name the sandbox and attested inventory, never the full
// inventory response.
func (h AttestHandler) matchWorkload(ctx context.Context, snapshot *PolicySnapshot, resp workloadclaims.SandboxDigestsResponse, membership map[string]struct{}, sandbox workloadclaims.VerifiedSandbox) *armtls.MatchedWorkload {
	unnamed := func(level slog.Level, why string, args ...any) *armtls.MatchedWorkload {
		args = append(args, "sandbox_id", sandbox.SandboxID, "inventory_addr", sandbox.InventoryHost)
		slog.Log(ctx, level, "issuing unnamed: "+why, args...)
		return nil
	}

	reported, err := resp.RequireContainers()
	if err != nil {
		// An old inventory (no containers view) or an incomplete answer: the
		// membership-only leaf is still issued, pinned clients reject it.
		return unnamed(slog.LevelWarn, "inventory cannot support a (digest, argv) decision", "error", err)
	}
	// Canonicalize the per-container digests with the same normalization the
	// membership view went through, and derive the containers-view digest set
	// for the cross-check.
	canonical := make([]workloadclaims.SandboxContainer, 0, len(reported))
	containerSet := make(map[string]struct{}, len(reported))
	for _, c := range reported {
		digest, err := types.ParseDigest(c.Digest)
		if err != nil {
			return unnamed(slog.LevelError, "inventory reported a malformed container digest", "error", err)
		}
		canonical = append(canonical, workloadclaims.SandboxContainer{
			Digest: digest.String(),
			Role:   c.Role,
			Argv:   c.Argv,
			Env:    c.Env,
			Mounts: c.Mounts,
		})
		containerSet[digest.String()] = struct{}{}
	}
	// The two views describe the same sandbox and must agree. The inventory is
	// measured trusted code inside the TEE, so a disagreement is a serious
	// implementation or integrity fault, never a valid alternate
	// representation — it can never produce a workload identity. The
	// membership decision from the independent digests view stands.
	if !maps.Equal(membership, containerSet) {
		return unnamed(slog.LevelError, "inventory digests and containers views disagree")
	}

	candidates := secrets.WorkloadContainers(canonical)
	name, _, err := snapshot.Allowlist.MatchWorkload(candidates)
	if err != nil {
		// ErrNoMatch mid-lifecycle and ErrAmbiguous are ordinary unnamed
		// states, not faults.
		return unnamed(slog.LevelInfo, "no unique workload match", "error", err)
	}
	matched := &armtls.MatchedWorkload{
		Name:             name,
		AllowlistVersion: snapshot.Version,
		AllowlistDigest:  snapshot.Digest,
	}
	if err := matched.Validate(); err != nil {
		return unnamed(slog.LevelError, "matched workload failed validation", "error", err)
	}
	return matched
}

// recordSandboxBinding notes which inventory vouched for this sandbox.
//
// A refused binding — a second inventory claiming a sandbox another one already
// owns — does NOT refuse the certificate. get-cert has no token-less retry
// (internal/cmds/getcert/run.go), so denying here would let one pre-claim wedge
// a pod for a whole certificate lifetime, which is worse than what it prevents.
// The consequence is narrower and lands where the stake is: no binding means no
// inventory the secrets path is willing to believe about the sandbox, so it
// fails closed there instead.
func (h AttestHandler) recordSandboxBinding(sandbox workloadclaims.VerifiedSandbox) {
	if h.SandboxBindings == nil || sandbox.SandboxID == "" {
		return
	}
	if !h.SandboxBindings.Record(sandbox.SandboxID, sandbox.InventoryHost) {
		slog.Warn("sandbox is already bound to a different inventory; issuing anyway, but secrets will refuse it",
			"sandbox_id", sandbox.SandboxID, "inventory_addr", sandbox.InventoryHost)
	}
}

// classifyVerifyError maps a VerifyEnforced error to (HTTP status, error code,
// message). A rejected verdict — bad signature, REPORTDATA mismatch, or a 4xx
// the attestation-api returns for malformed/unacceptable evidence — is the
// caller's fault and must not be reported as attestation_api_unreachable.
// Upstream 408 (timeout) and 429 (rate-limited) are retryable availability
// conditions, not evidence rejections, so they classify as unreachable too.
func classifyVerifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, remote.ErrSignatureInvalid):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "attestation signature invalid"
	case errors.Is(err, remote.ErrReportDataMismatch):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "challenge mismatch in attestation evidence"
	}
	var apiErr *remote.APIError
	if errors.As(err, &apiErr) && refusesEvidence(apiErr.Status) {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation evidence rejected by attestation-api"
	}
	// The api answers its own refusals in the JSON envelope, so a non-JSON body
	// names the request rather than the evidence, and only where there is a
	// body to have named it.
	var unexpected *remote.UnexpectedError
	if errors.As(err, &unexpected) && rejectsRequest(unexpected.Status) && unexpected.Text != "" {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation-api rejected the request"
	}
	return http.StatusBadGateway, types.ErrorCodeAttestationApiUnreachable,
		fmt.Sprintf("failed to reach attestation-api: %s", err)
}

// refusesEvidence reports whether a status names the evidence rather than the
// service; 408 and 429 are availability.
func refusesEvidence(status int) bool {
	return status >= 400 && status < 500 &&
		status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}

// rejectsRequest reports whether a status names what was sent. These are the
// statuses axum's extractors reject a body with, outside the JSON envelope.
func rejectsRequest(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusUnsupportedMediaType ||
		status == http.StatusUnprocessableEntity
}
