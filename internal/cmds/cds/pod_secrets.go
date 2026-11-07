package cds

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// PodSecretHandler serves POST /pod-secrets: secret release to a pod CVM's
// guest broker (POC for workload attestation Q1). It authenticates the request
// exactly as Pod issuance does — consumed challenge, fresh TDX evidence over a
// binding of the claims, complete image/key/journal replay under Pod authority
// and membership — then releases one path under the allowlist entry whose
// secrets grant MatchPodGrant selects. The value is sealed to the response key
// the evidence binds.
type PodSecretHandler struct {
	Attest     AttestHandler
	Challenges attestation.Challenges
	Store      secrets.Store
	Policy     interface {
		Allowlist() (*pkgallowlist.Allowlist, error)
	}
}

func (h PodSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Attest.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.Attest.RequestTimeout)
		defer cancel()
	}
	w.Header().Set("Cache-Control", "no-store")
	raw, err := io.ReadAll(r.Body)
	var req workloadclaims.PodSecretRequest
	if err == nil {
		err = strictjson.Validate(raw)
	}
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		err = dec.Decode(&req)
	}
	if err != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, "invalid Pod secret request")
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil || !h.Challenges.Consume(nonce) {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}
	// Every refusal after the challenge is the same opaque 403; the cause is
	// for the CDS log only.
	refuse := func(reason string, args ...any) {
		slog.Warn("Pod secret refused", append([]any{"reason", reason, "path", req.Path, "remote_addr", r.RemoteAddr}, args...)...)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "not authorized for this secret")
	}
	path, err := pkgallowlist.CanonicalSecretPath(req.Path)
	if err != nil || path != req.Path {
		refuse("noncanonical path")
		return
	}
	claims, err := workloadclaims.DecodePodClaims(req.PodClaims)
	if err != nil {
		refuse("pod claims", "error", err)
		return
	}
	if !req.Evidence.Platform.IsTDX() || len(h.Attest.PodImages) == 0 {
		refuse("no TDX evidence or no pod image policy")
		return
	}
	binding, err := workloadclaims.PodSecretReportData(req.ResponseKey, nonce, req.PodClaims, path)
	if err != nil {
		refuse("binding", "error", err)
		return
	}
	verifyResp, err := h.Attest.AttestationClient.VerifyEnforced(ctx, remote.NewVerifyRequestNoToken(req.Evidence, &remote.VerifyParams{
		ExpectedReportData: binding[:sha512.Size384],
	}))
	if err != nil {
		status, code, msg := classifyVerifyError(err)
		slog.Warn("Pod secret evidence failed verification", "error", err, "remote_addr", r.RemoteAddr)
		httputil.WriteError(w, status, code, msg)
		return
	}
	if err := enforcePodImages(verifyResp, h.Attest.PodImages, req.Evidence.Platform, claims.RuntimeExtensions); err != nil {
		refuse("pod identity", "error", err)
		return
	}
	if err := h.Attest.authorizePodMembership(claims); err != nil {
		refuse("membership", "error", err)
		return
	}
	al, err := h.Policy.Allowlist()
	if err != nil {
		slog.Error("Pod secret: load allowlist", "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	grant, err := secrets.MatchPodGrant(al, claims)
	if err != nil {
		refuse("grant", "error", err, "instance", claims.InstanceID())
		return
	}
	value, err := secrets.ReleasePodSecret(ctx, h.Store, grant, path)
	switch {
	case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrPodSecretUngranted):
		slog.Warn("Pod secret not released", "path", path, "workload", grant.Workload, "error", err)
		http.Error(w, "no such secret", http.StatusNotFound)
		return
	case errors.Is(err, secrets.ErrUnavailable):
		httputil.WriteUnavailable(w, secrets.ErrUnavailable)
		return
	case err != nil:
		slog.Error("Pod secret release failed", "path", path, "workload", grant.Workload, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	sealed, err := workloadclaims.SealPodSecret(req.ResponseKey, binding, value)
	if err != nil {
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	slog.Info("Pod secret released", "path", path, "workload", grant.Workload, "instance", claims.InstanceID())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(workloadclaims.PodSecretResponse{Workload: grant.Workload, Readers: grant.Readers, Sealed: sealed})
}
