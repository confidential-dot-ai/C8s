package secrets

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Route is the path prefix the handler serves. The trailing wildcard is
// required: a store path has slashes in it, and a single-segment pattern would
// only ever match a top-level path.
const Route = "/secrets/*"

// ChallengeRoute mints the single-use nonce a secret request must carry. It is
// "/secrets" exactly, which Route (which always has a path under it) can never
// match, so no store path is shadowed by it.
const ChallengeRoute = "/secrets"

// AuthScheme prefixes the sandbox token in the Authorization header, and
// ChallengeHeader carries the nonce. The token travels in a header rather than
// the URL so it is covered by the server's header bound and never reaches a
// request log.
const (
	AuthScheme      = "SandboxToken "
	ChallengeHeader = "X-C8s-Challenge"
)

// RateKey charges a request to the sandbox its client certificate names, so a
// rate limit bounds one workload rather than one address.
//
// Pods reach CDS through a NodePort and the host-network mesh proxy, so every
// pod on a node arrives from the same address: keyed on that, one hostile pod
// exhausts the bucket its co-tenants share and wedges their fetchers into a
// CrashLoop. The sandbox ID is stamped by CDS into a leaf that crypto/tls has
// verified against the mesh CA, so a caller can only ever name its own.
//
// An unverified or absent certificate returns "", charging the request to the
// source address. Such a request is refused by the handler regardless, and a
// caller cannot escape limiting by withholding a certificate.
func RateKey(r *http.Request) string {
	leaf, err := verifiedLeaf(r)
	if err != nil {
		return ""
	}
	id, err := armtls.SandboxIDFromCert(leaf)
	if err != nil || id == "" {
		return ""
	}
	return "sandbox:" + id
}

// challengeSource issues and consumes the single-use nonces that make a request
// fresh. The secrets listener holds its own, so a nonce minted for issuance
// cannot be redeemed here.
type challengeSource interface {
	Consume(challenge []byte) bool
}

// inventorySource is the callback to a node's admission inventory: its
// sandbox-token signing key, and what a sandbox has run.
type inventorySource interface {
	InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error)
	FetchSandbox(ctx context.Context, host, sandboxID string) (workloadclaims.SandboxDigestsResponse, error)
}

// bindingSource resolves which inventory this process is willing to believe
// about a sandbox.
type bindingSource interface {
	Lookup(sandboxID string) (host string, ok bool)
}

// policySource supplies the current allowlist.
type policySource interface {
	Allowlist() (*pkgallowlist.Allowlist, error)
}

// Handler serves GET and POST on Route.
type Handler struct {
	Store      Store
	Challenges challengeSource
	Inventory  inventorySource
	Bindings   bindingSource
	Policy     policySource

	// InventoryHosts bounds the addresses the callback may dial. Empty refuses
	// every request: without it a workload could name its own pod.
	InventoryHosts workloadclaims.InventoryHosts

	Logger *slog.Logger
}

// grant is the allowlist entry authorization matched: workload keys the store's
// holder, secrets gates the path.
type grant struct {
	workload string
	secrets  *pkgallowlist.SecretsPolicy
}

// denial is a refusal to release. The reason reaches the CDS log; the client is
// told only that it was refused, because the detail describes the state of a
// pod the caller may not be entitled to learn about.
type denial struct {
	status int
	reason string
}

func (d denial) Error() string { return d.reason }

func deny(reason string, args ...any) denial {
	return denial{status: http.StatusForbidden, reason: fmt.Sprintf(reason, args...)}
}

func (h Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	path, err := requestPath(r)
	if err != nil {
		http.Error(w, "invalid secret path", http.StatusBadRequest)
		return
	}

	// The challenge is consumed unconditionally and first, exactly as issuance
	// does: a nonce that survives an early error path is a nonce that can be
	// replayed against another path.
	nonce, err := h.consumeChallenge(r)
	if err != nil {
		h.logger().Warn("secret request rejected", "path", path, "error", err)
		http.Error(w, "invalid or expired challenge", http.StatusBadRequest)
		return
	}

	g, err := h.authorize(ctx, r, nonce)
	if err != nil {
		var d denial
		if !errors.As(err, &d) {
			d = denial{status: http.StatusForbidden, reason: err.Error()}
		}
		h.logger().Warn("secret request denied", "path", path, "reason", d.reason)
		http.Error(w, "not authorized for this secret", d.status)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.serveGet(ctx, w, g, path)
	case http.MethodPost:
		h.servePost(ctx, w, g, path)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h Handler) serveGet(ctx context.Context, w http.ResponseWriter, g grant, path string) {
	if !g.secrets.Allows(path, pkgallowlist.OpRead) {
		// Indistinguishable from a path that does not exist: telling a caller
		// which of its ungranted guesses are real would enumerate the store.
		h.logger().Warn("secret read denied", "path", path)
		http.Error(w, "no such secret", http.StatusNotFound)
		return
	}
	value, err := h.Store.Get(ctx, path)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "no such secret", http.StatusNotFound)
			return
		}
		h.logger().Error("secret read failed", "path", path, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	writeValue(w, value, http.StatusOK)
}

func (h Handler) servePost(ctx context.Context, w http.ResponseWriter, g grant, path string) {
	if !g.secrets.Allows(path, pkgallowlist.OpWrite) {
		h.logger().Warn("secret create denied", "path", path)
		http.Error(w, "no such secret", http.StatusNotFound)
		return
	}
	// The value is minted here and never supplied by the caller, so no client
	// chooses what another client will later read.
	candidate, err := Generate()
	if err != nil {
		h.logger().Error("generate secret failed", "path", path, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	_, held, err := h.Store.PutIfAbsent(ctx, path, candidate, WorkloadHolder(g.workload))
	switch {
	case errors.Is(err, ErrHolderQuota):
		h.logger().Warn("secret create refused", "path", path, "workload", g.workload, "error", err)
		writeError(w, http.StatusInsufficientStorage, types.ErrorCodeSecretHolderQuota, "secret storage limit reached")
		return
	case errors.Is(err, ErrStoreFull):
		// Enabled gates the census: slog evaluates attributes before it filters
		// on level.
		if log := h.logger(); log.Enabled(ctx, slog.LevelWarn) {
			log.Warn("secret create refused", "path", path, "workload", g.workload, "error", err,
				"holders", h.Store.TopHolders(censusHolders))
		}
		writeError(w, http.StatusInsufficientStorage, types.ErrorCodeSecretStoreFull, "secret storage limit reached")
		return
	}
	if err != nil {
		h.logger().Error("secret create failed", "path", path, "workload", g.workload, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	if held.Exists {
		// The existing value is withheld: returning it here would make a write
		// grant a read grant. A caller that also holds read re-reads with GET,
		// which is how the replica that loses this race recovers.
		w.WriteHeader(http.StatusConflict)
		return
	}
	writeValue(w, candidate, http.StatusCreated)
}

// valueResponse carries a secret value. Base64 because a generated value is raw
// bytes.
type valueResponse struct {
	Value string `json:"value"`
}

func writeValue(w http.ResponseWriter, value []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(valueResponse{Value: base64.StdEncoding.EncodeToString(value)})
}

// writeError is httputil.WriteError with the no-store every secrets response
// carries.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	httputil.WriteError(w, status, code, message)
}

// censusHolders is how many holders the full-store log line names.
const censusHolders = 5

// requestPath returns the canonical store path a request names.
//
// It reads the escaped form and refuses anything not already canonical rather
// than repairing it, so the bytes matched against a grant, and the bytes used as
// a store key, are the bytes the client sent. Chi routes on the raw or the
// decoded path depending on whether the URL contained escapes, so deriving from
// one source and rejecting "%" removes that difference.
func requestPath(r *http.Request) (string, error) {
	raw := r.URL.EscapedPath()
	rest, ok := strings.CutPrefix(raw, "/secrets")
	if !ok {
		return "", fmt.Errorf("path %q is not under /secrets", raw)
	}
	return pkgallowlist.CanonicalSecretPath(rest)
}

func (h Handler) consumeChallenge(r *http.Request) ([]byte, error) {
	if h.Challenges == nil {
		return nil, fmt.Errorf("no challenge store configured")
	}
	raw := r.Header.Get(ChallengeHeader)
	if raw == "" {
		return nil, fmt.Errorf("missing challenge")
	}
	nonce, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("challenge is not base64")
	}
	if !h.Challenges.Consume(nonce) {
		return nil, fmt.Errorf("challenge is unknown, expired, or already used")
	}
	return nonce, nil
}

// authorize establishes which workload is calling and returns the secret grant
// that workload holds. Every failure is fail-closed.
func (h Handler) authorize(ctx context.Context, r *http.Request, nonce []byte) (grant, error) {
	leaf, err := verifiedLeaf(r)
	if err != nil {
		return grant{}, deny("%v", err)
	}
	sandboxID, err := armtls.SandboxIDFromCert(leaf)
	if err != nil || sandboxID == "" {
		return grant{}, deny("client certificate carries no sandbox ID")
	}

	// The token re-proves, against this request's own challenge, that the
	// caller is still in that sandbox, and names the inventory that says so.
	token, err := h.parseToken(r)
	if err != nil {
		return grant{}, deny("%v", err)
	}
	host, err := h.verifyToken(ctx, token, leaf.PublicKey, nonce, sandboxID)
	if err != nil {
		return grant{}, deny("%v", err)
	}

	al, err := h.Policy.Allowlist()
	if err != nil {
		return grant{}, fmt.Errorf("load allowlist: %w", err)
	}
	containers, err := h.workloadContainers(ctx, host, sandboxID)
	if err != nil {
		return grant{}, deny("%v", err)
	}
	name, workload, err := al.MatchWorkload(containers)
	if err != nil {
		return grant{}, deny("sandbox %s: %v", sandboxID, err)
	}
	if workload.Secrets == nil {
		return grant{}, deny("workload %q holds no secret grant", name)
	}
	// The write path refuses this shape; the store may still hold one written
	// before it did.
	if !workload.ArgvPinned() {
		return grant{}, deny("workload %q holds a secret grant but leaves a container's argv unconstrained", name)
	}
	return grant{workload: name, secrets: workload.Secrets}, nil
}

// verifiedLeaf returns the client certificate, requiring that crypto/tls
// verified it against the configured roots. VerifiedChains is empty unless the
// listener both asked for a certificate and had roots to check it against, so
// this refuses a listener misconfigured to accept a self-signed peer — whose
// sandbox-ID extension would be whatever it chose.
func verifiedLeaf(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate")
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return nil, fmt.Errorf("client certificate was not verified against the mesh CA")
	}
	return r.TLS.PeerCertificates[0], nil
}

func (h Handler) parseToken(r *http.Request) (*workloadclaims.SignedSandboxToken, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), AuthScheme)
	if !ok || raw == "" {
		return nil, fmt.Errorf("missing sandbox token")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("sandbox token is not base64")
	}
	var token workloadclaims.SignedSandboxToken
	dec := json.NewDecoder(bytes.NewReader(der))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&token); err != nil {
		return nil, fmt.Errorf("decode sandbox token: %w", err)
	}
	return &token, nil
}

// verifyToken checks the token against the inventory this process already
// believes owns the sandbox, and returns that inventory's host.
func (h Handler) verifyToken(ctx context.Context, token *workloadclaims.SignedSandboxToken, requesterPub crypto.PublicKey, nonce []byte, sandboxID string) (string, error) {
	if h.Inventory == nil || h.Bindings == nil {
		return "", fmt.Errorf("secrets are not configured to reach an inventory")
	}
	if h.InventoryHosts == nil || h.InventoryHosts.Empty() {
		return "", fmt.Errorf("the inventory callback has no node addresses to bound it")
	}
	// The binding, not the token, decides who is asked. The token names a host
	// too, but that is the requester's choice; taking it would let anything able
	// to answer on the inventory port vouch for someone else's sandbox.
	host, ok := h.Bindings.Lookup(sandboxID)
	if !ok {
		return "", fmt.Errorf("no inventory is bound to sandbox %s", sandboxID)
	}
	if !h.InventoryHosts.Contains(host) {
		return "", fmt.Errorf("bound inventory is outside the node bound")
	}
	claimed, err := workloadclaims.UnverifiedInventoryHost(token.Token)
	if err != nil {
		return "", err
	}
	if claimed != host {
		return "", fmt.Errorf("sandbox token names an inventory other than the one bound to this sandbox")
	}
	key, err := h.Inventory.InventoryKey(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve inventory key: %w", err)
	}
	verified, err := token.Verify(key, requesterPub, nonce)
	if err != nil {
		return "", err
	}
	if verified.SandboxID != sandboxID {
		return "", fmt.Errorf("sandbox token names a different sandbox than the certificate")
	}
	return host, nil
}

// workloadContainers asks the bound inventory what the sandbox has run and
// removes the platform's own containers, so a workload entry never has to
// enumerate C8s's own.
func (h Handler) workloadContainers(ctx context.Context, host, sandboxID string) ([]pkgallowlist.RunningContainer, error) {
	resp, err := h.Inventory.FetchSandbox(ctx, host, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox containers: %w", err)
	}
	reported, err := resp.RequireContainers()
	if err != nil {
		return nil, err
	}
	out := WorkloadContainers(reported)
	if len(out) == 0 {
		return nil, fmt.Errorf("sandbox %s reports no workload containers", sandboxID)
	}
	return out, nil
}

// WorkloadContainers converts an inventory's reported container set to the
// candidate set workload matching runs on, dropping every container the
// reporting node's measured base binds a platform role to, so a workload entry
// never has to enumerate C8s's own containers. It is a pure function of the
// report — the one drop-set implementation shared by secrets release, the
// release diagnostic, and CDS certificate issuance. pkg/allowlist stays
// ignorant of injection by design (its doc: "the caller converts").
//
// The role is the enforcer's reading of its own boot config, which the digests
// channel carries from an attested inventory (docs/secrets.md).
func WorkloadContainers(reported []workloadclaims.SandboxContainer) []pkgallowlist.RunningContainer {
	out := make([]pkgallowlist.RunningContainer, 0, len(reported))
	for _, c := range reported {
		if c.Role != "" {
			continue
		}
		r := pkgallowlist.RunningContainer{Digest: c.Digest, Argv: c.Argv, Env: c.Env, Mounts: c.Mounts}
		out = append(out, r)
	}
	return out
}
