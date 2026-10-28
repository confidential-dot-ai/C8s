package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultMaxOperatorBodyBytes caps a PUT body when OperatorHandler.MaxBodyBytes
// is zero. The value arrives base64-encoded inside a JSON envelope, so the body
// runs well ahead of the store's own per-value bound.
const DefaultMaxOperatorBodyBytes int64 = 64 * 1024

// PutRequest is the body of PUT /secrets/*.
type PutRequest struct {
	// Value is the secret, base64. Operator values are arbitrary bytes — a
	// wrapped key, a PEM, a token — so they are not representable raw.
	Value string `json:"value"`
	// Overwrite permits replacing a value already at the path. It lives in the
	// body rather than a query parameter so the operator token's body binding
	// covers it; htu binds only the path.
	Overwrite bool `json:"overwrite"`
}

// PutResponse reports what a PUT did, or on 409 what stopped it. Existing names
// what put the value that was already there and is empty when there was none.
type PutResponse struct {
	Path     string `json:"path"`
	Created  bool   `json:"created"`
	Existing Origin `json:"existing,omitempty"`
}

// OperatorHandler serves PUT on Route: an operator supplying a value CDS cannot
// generate — an API token, a database password, a wrapped key.
//
// Authorization is the operator key that already roots the secrets grants, via
// the same verifier the allowlist writes use. Its token binds method, path and
// body, so a captured one cannot be replayed against another path or value.
type OperatorHandler struct {
	Store Store
	// Authorize is operatorauth.Verifier.Authorize. Nil rejects every request.
	Authorize func(r *http.Request, body []byte) error
	// MaxBodyBytes caps the request body; zero means DefaultMaxOperatorBodyBytes.
	MaxBodyBytes int64

	Logger *slog.Logger
}

func (h OperatorHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h OperatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authorization runs before anything is read off the request, so an
	// unauthenticated caller learns nothing, not even whether a path parses.
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	path, err := requestPath(r)
	if err != nil {
		http.Error(w, "invalid secret path", http.StatusBadRequest)
		return
	}

	var req PutRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		http.Error(w, "value is not base64", http.StatusUnprocessableEntity)
		return
	}
	if len(value) == 0 {
		http.Error(w, "value is empty", http.StatusUnprocessableEntity)
		return
	}

	if req.Overwrite {
		h.replace(w, r, path, value)
		return
	}
	h.create(w, r, path, value)
}

// create refuses a path that already holds something, naming what put it there
// so the operator can decide before anything is destroyed. The store has no
// versioning and no delete, so a displaced value is gone.
func (h OperatorHandler) create(w http.ResponseWriter, r *http.Request, path string, value []byte) {
	_, held, err := h.Store.PutIfAbsent(r.Context(), path, value, OperatorHolder())
	if h.writeFailed(w, path, err) {
		return
	}
	if held.Exists {
		writeResult(w, http.StatusConflict, PutResponse{Path: path, Existing: held.Origin})
		return
	}
	h.logger().Info("operator secret created", "path", path, "bytes", len(value))
	writeResult(w, http.StatusCreated, PutResponse{Path: path, Created: true})
}

func (h OperatorHandler) replace(w http.ResponseWriter, r *http.Request, path string, value []byte) {
	held, err := h.Store.Put(r.Context(), path, value)
	if h.writeFailed(w, path, err) {
		return
	}
	if !held.Exists {
		h.logger().Info("operator secret created", "path", path, "bytes", len(value))
		writeResult(w, http.StatusCreated, PutResponse{Path: path, Created: true})
		return
	}
	h.logger().Info("operator secret replaced", "path", path, "bytes", len(value), "existing", held.Origin)
	writeResult(w, http.StatusOK, PutResponse{Path: path, Existing: held.Origin})
}

// writeFailed answers a store error and reports whether it did. Both write
// paths hold as the operator, which is quota-exempt, so the ceiling is the only
// bound that can refuse them.
func (h OperatorHandler) writeFailed(w http.ResponseWriter, path string, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrStoreFull):
		h.logger().Warn("operator secret write refused", "path", path, "error", err)
		writeError(w, http.StatusInsufficientStorage, types.ErrorCodeSecretStoreFull, "secret storage limit reached")
	case errors.Is(err, ErrCapacity):
		h.logger().Warn("operator secret write refused", "path", path, "error", err)
		writeError(w, http.StatusInsufficientStorage, types.ErrorCodeStateCapacity, capacityMessage)
	case errors.Is(err, ErrUnavailable):
		h.logger().Warn("operator secret write not committed", "path", path, "error", err)
		httputil.WriteUnavailable(w, ErrUnavailable)
	default:
		h.logger().Error("operator secret write failed", "path", path, "error", err)
		http.Error(w, "secret write failed", http.StatusInternalServerError)
	}
	return true
}

// authorize reads the body under the cap and runs the operator check against
// those exact bytes, so the token's body binding is checked against what the
// handler goes on to decode.
func (h OperatorHandler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.Authorize == nil {
		http.Error(w, "operator writes are not configured", http.StatusUnauthorized)
		return nil, false
	}
	cap := h.MaxBodyBytes
	if cap <= 0 {
		cap = DefaultMaxOperatorBodyBytes
	}
	body, ok := httputil.ReadCappedBody(w, r, cap)
	if !ok {
		return nil, false
	}
	if err := h.Authorize(r, body); err != nil {
		h.logger().Warn("operator secret write rejected", "remote", r.RemoteAddr, "reason", err)
		httputil.RefuseOperatorToken(w, err)
		return nil, false
	}
	return body, true
}

// writeResult answers with a JSON PutResponse. The CLI relies on the JSON
// Content-Type to tell an occupied-path 409 from a spent-token 409, which
// httputil.RefuseOperatorToken answers in plain text.
func writeResult(w http.ResponseWriter, status int, resp PutResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// capacityMessage answers a write refused by the HA admission cap.
const capacityMessage = "CDS state is at its snapshot capacity: writes that grow it are refused until it shrinks; retry later"
