package cds

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// routeHandler serves GET and PUT /routes, the signed route manifest (route
// policy §8).
type routeHandler struct {
	Store *allowlist.Store
	// Authorize is the allowlist write authorizer: same keys, same checks (W1).
	Authorize allowlist.WriteAuthorizer
	// MeshCA is this CDS's mesh CA, which no address backend may anchor on (C3).
	MeshCA *x509.Certificate
}

// handleGet serves the stored signed manifest in the C1 envelope, or 404.
func (h routeHandler) handleGet(w http.ResponseWriter, _ *http.Request) {
	env, err := h.Store.LoadRoutes()
	if errors.Is(err, allowlist.ErrNoRoutes) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("load route manifest", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	body, err := json.Marshal(env)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handlePut stores a signed manifest, stopping at the first failure in the C3
// order: read, authorize, validate, mesh-CA exclusion, revision, If-Match,
// store.
func (h routeHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	body, ok := h.Authorize.ReadAuthorized(w, r, allowlistWriteBodyCap)
	if !ok {
		return
	}
	if h.MeshCA == nil {
		// Without it the C3 anchor check cannot run: fail closed.
		slog.Error("route manifest write refused: no mesh CA wired")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	m, err := routes.Parse(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := m.CheckAnchorsExclude([]*x509.Certificate{h.MeshCA}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// Authorize accepted exactly this header, so the token is well formed.
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	err = h.Store.ReplaceRoutes(routes.Envelope{Manifest: body, Token: token}, r.Header.Get("If-Match"))
	if errors.Is(err, allowlist.ErrRevisionNotGreater) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, allowlist.ErrDigestMismatch) {
		http.Error(w, err.Error()+"; fetch the stored manifest and apply the change again", http.StatusPreconditionFailed)
		return
	}
	if errors.Is(err, allowlist.ErrUnavailable) {
		httputil.WriteUnavailable(w, allowlist.ErrUnavailable)
		return
	}
	if err != nil {
		slog.Error("store route manifest", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	digest := routes.Digest(body)
	slog.Info("route manifest stored", "revision", m.Revision, "digest", hex.EncodeToString(digest[:]))
	w.WriteHeader(http.StatusNoContent)
}
