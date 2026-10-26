package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/nodetoken"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// NodeTokenHandler serves POST /node-token: a node of a hosted cluster proves
// what it runs, exactly as it would for a mesh leaf, and gets a minutes-long
// JWT its cluster's API server takes as the node's join credential
// (docs/node-tokens.md). It sits on the armTLS listener like /attest, so the
// node has checked CDS's attestation before it asks.
type NodeTokenHandler struct {
	// Attest admits the node: the same challenge store, verifier and node
	// pins /attest uses.
	Attest AttestHandler
	Issuer *nodetoken.Issuer
}

func (h NodeTokenHandler) HandleNodeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Attest.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.Attest.RequestTimeout)
		defer cancel()
	}

	var req types.NodeTokenRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	if len(req.RuntimeExtensions) > 0 && !req.Evidence.Platform.HasRegisters() {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			"runtime_extensions requires evidence from a platform with runtime measurement registers")
		return
	}
	if !h.pinsWholeImage(req.Evidence.Platform) {
		// The node's launch measurement pins only its firmware here, so any
		// image on it would pass; refused before the challenge is spent.
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied,
			"node tokens for TDX nodes need an image policy or --rtmrs on this CDS")
		return
	}
	nodeKey, err := parseNodeKey(req.NodeKey)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, err.Error())
		return
	}

	// The audience is checked before the challenge is spent or the verifier
	// called, so a request for another cluster costs nothing.
	if !h.Issuer.MintsFor(req.Audience) {
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeInvalidRequest, "not an audience of this issuer")
		return
	}

	challenge, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil || !h.Attest.Challenges.Consume(challenge) {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}
	reportData, err := armtls.ReportDataForKey(nodeKey, challenge)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	launchDigest, refused := h.Attest.verifyNode(ctx, r, req.Evidence, req.RuntimeExtensions, reportData[:sha512.Size384])
	if refused != nil {
		attestation.WriteError(w, refused.status, refused.code, refused.message)
		return
	}
	if ctx.Err() != nil {
		attestation.WriteError(w, http.StatusGatewayTimeout, types.ErrorCodeTimeout, "request timeout")
		return
	}

	token, expires, err := h.Issuer.Mint(req.Audience, nodetoken.Attested{
		NodeKey:      nodeKey,
		TEE:          req.Evidence.Platform.Family().String(),
		LaunchDigest: launchDigest,
	})
	if err != nil {
		slog.Error("node token mint failed", "error", err)
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, err.Error())
		return
	}
	sub, _ := nodetoken.Subject(nodeKey)
	// The issuance record names the node, what attested for it and where the
	// request came from, as /attest's does for a leaf.
	slog.Info("node token issued", "sub", sub, "aud", req.Audience, "launch_digest", launchDigest,
		"expires", expires, "remote_addr", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.NodeTokenResponse{Token: token, ExpiresAt: expires})
}

// pinsWholeImage says whether the node pins hold a node on platform to its
// whole image: image pins always do, and launch measurements do on a platform
// without runtime measurement registers. On TDX a measurement covers only the
// firmware, so RTMR pins must cover the kernel and command line.
func (h NodeTokenHandler) pinsWholeImage(platform teetypes.PlatformType) bool {
	if len(h.Attest.Images) > 0 {
		return true
	}
	return !platform.HasRegisters() || len(h.Attest.RTMRs) > 0
}

// parseNodeKey reads a node key: a P-256 ECDSA public key, PKIX DER in base64.
func parseNodeKey(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("node_key must be base64")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("node_key must be a PKIX public key")
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("node_key must be an ECDSA P-256 key")
	}
	return key, nil
}

// nodeTokenIssuerFlags are the flags that only mean something with
// --node-token-issuer.
var nodeTokenIssuerFlags = []string{"node-token-audience", "node-token-cluster", "node-token-ttl", "node-token-listen"}

// validateNodeTokenFlags refuses a --node-token-* flag set without
// --node-token-issuer: CDS would start with /node-token unrouted and log
// nothing about it.
func validateNodeTokenFlags(flags *pflag.FlagSet, cfg config) error {
	if cfg.nodeTokenIssuer != "" {
		return nil
	}
	for _, name := range nodeTokenIssuerFlags {
		if flags.Changed(name) {
			return fmt.Errorf("--%s requires --node-token-issuer", name)
		}
	}
	return nil
}

// newNodeTokenIssuer builds the node token issuer and its discovery listener's
// TLS identity from the --node-token-* flags, or nothing when
// --node-token-issuer is empty. nodesPinned says whether /attest pins nodes at
// all: image pins or launch measurements. On TDX a measurement alone pins only
// the firmware, so HandleNodeToken also refuses a TDX node unless RTMR pins
// are set; SNP's measurement covers the whole image.
func newNodeTokenIssuer(cfg config, nodesPinned bool) (*nodetoken.Issuer, *nodetoken.Serving, error) {
	if cfg.nodeTokenIssuer == "" {
		return nil, nil, nil
	}
	if cfg.armtlsPlatform == "" {
		// The token endpoint is only safe behind armTLS: the node must have
		// checked CDS before it hands over evidence for its join.
		return nil, nil, errors.New("--node-token-issuer requires --armtls-platform")
	}
	if !nodesPinned {
		// /attest tolerates unpinned nodes in development; a node token makes
		// its holder a node of the cluster, which schedules workloads on it,
		// so any genuine TEE running any image must not get one.
		return nil, nil, errors.New("--node-token-issuer requires node pins: an image policy or --measurements (with --rtmrs for TDX nodes)")
	}
	issuer, err := nodetoken.New(nodetoken.Config{
		URL:       cfg.nodeTokenIssuer,
		Audiences: cfg.nodeTokenAudiences,
		Cluster:   cfg.nodeTokenCluster,
		TTL:       cfg.nodeTokenTTL,
	})
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(cfg.nodeTokenIssuer)
	if err != nil {
		return nil, nil, err
	}
	serving, err := nodetoken.NewServing(u.Hostname())
	if err != nil {
		return nil, nil, err
	}
	return issuer, serving, nil
}

// errListenerFailed ends CDS when a listener it cannot do without stops.
var errListenerFailed = errors.New("listener failed")

// serveNodeTokenDiscovery serves the issuer's discovery document and keys on
// their own plain-TLS listener, which an API server's JWT authenticator can
// read: it pins the issuer's CA, and has no armTLS verifier. If the listener
// stops, fail ends CDS rather than leave it minting tokens nobody can check.
func serveNodeTokenDiscovery(ctx context.Context, fail context.CancelCauseFunc, cfg config, issuer *nodetoken.Issuer, serving *nodetoken.Serving) error {
	handler, err := issuer.Handler()
	if err != nil {
		return err
	}
	srv := newHTTPServer(cfg.nodeTokenListen, handler, cfg)
	srv.TLSConfig = serving.TLSConfig()
	ln, err := net.Listen("tcp", cfg.nodeTokenListen)
	if err != nil {
		return fmt.Errorf("node token discovery listener: %w", err)
	}
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("node token discovery listener stopped", "error", err)
			fail(fmt.Errorf("%w: node token discovery: %w", errListenerFailed, err))
		}
	}()
	slog.Info("node token issuer serving discovery", "addr", ln.Addr().String(),
		"issuer", cfg.nodeTokenIssuer, "ca_sha256", serving.Fingerprint())
	return nil
}
