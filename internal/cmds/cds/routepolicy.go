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
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// routeHandler serves GET and PUT /routes, the signed route manifest (route
// policy §8).
type routeHandler struct {
	Allowlist *allowlist.Handle
	// Authorize is the allowlist write authorizer: same keys, same checks (W1).
	Authorize allowlist.WriteAuthorizer
	// MeshCA is this CDS's mesh CA, which no address backend may anchor on (C3).
	MeshCA meshCA
}

// handleGet serves the stored signed manifest in the C1 envelope, or 404.
func (h routeHandler) handleGet(w http.ResponseWriter, _ *http.Request) {
	env, err := h.Allowlist.LoadRoutes()
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
	current, issuing := h.MeshCA.Current()
	if !issuing {
		// Without the certificate the C3 anchor check cannot run: fail closed.
		slog.Error("route manifest write refused: this CDS holds no mesh CA")
		http.Error(w, "internal server error", http.StatusServiceUnavailable)
		return
	}
	m, err := routes.Parse(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := m.CheckAnchorsExclude([]*x509.Certificate{current.CA.Cert}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// Authorize accepted exactly this header, so the token is well formed.
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	err = h.Allowlist.ReplaceRoutes(
		routes.Envelope{
			Manifest: body,
			Token:    token,
		},
		r.Header.Get("If-Match"),
	)
	if errors.Is(err, allowlist.ErrRevisionNotGreater) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, allowlist.ErrDigestMismatch) {
		http.Error(w, err.Error()+"; fetch the stored manifest and apply the change again", http.StatusPreconditionFailed)
		return
	}
	if err != nil {
		allowlist.WriteFailed(w, err)
		return
	}
	digest := routes.Digest(body)
	slog.Info("route manifest stored", "revision", m.Revision, "digest", hex.EncodeToString(digest[:]))
	w.WriteHeader(http.StatusNoContent)
}
