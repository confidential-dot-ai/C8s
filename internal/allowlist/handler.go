package allowlist

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// DefaultMaxWriteBodyBytes caps a mutation body when Handler.MaxWriteBodyBytes
// is zero. One entry fits; the deployed handler raises this so a full document
// fits (see the cds router's allowlist write cap).
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// Handler holds the dependencies for allowlist HTTP handlers.
type Handler struct {
	Store           *Store
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; a non-positive value clamps to the default.
	MaxWriteBodyBytes int64
}

// WriteAuthorizer authorizes a mutation given the raw request body, so the
// check binds the token to the body's SHA-256 (defeating captured-token replay
// against a different payload). Production wires operatorauth.Verifier.Authorize.
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /allowlist: the full allowlist document as canonical
// JSON. Emits a weak ETag from the store version; a matching If-None-Match
// returns 304.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	// Every enforcer polls this route on its refresh interval and is current
	// almost every time, so settle the 304 on the single-row version read
	// rather than loading every entry under the writers' lock.
	if match := r.Header.Get("If-None-Match"); match != "" {
		if version, err := h.Store.Version(); err == nil && match == `W/"`+version+`"` {
			w.Header().Set("ETag", match)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	doc, version, err := h.Store.LoadAll()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", `W/"`+version+`"`)

	body, err := doc.Canonical()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// HandleReplaceAll handles PUT /allowlist: validate the full document and swap
// it in atomically. CDS assigns the new version.
func (h Handler) HandleReplaceAll(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	al, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.ReplaceAll(al); err != nil {
		writeStoreError(w, err)
		return
	}
	// The token that wrote a canonical whole document is the operator's
	// signature over it (docs/allowlist-and-capabilities.md). Re-uploading the
	// same document with a fresh token is a no-op write that stores it.
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if err := h.Store.SignPolicy(body, token); err != nil {
			slog.Error("store the operator signature of the allowlist", "error", err)
			http.Error(w, "allowlist replaced but its operator signature was not stored; upload it again", http.StatusInternalServerError)
			return
		}
	}

	slog.Info("allowlist replaced", "workloads", len(al.Workloads))
	w.WriteHeader(http.StatusNoContent)
}

// HandlePutWorkload handles PUT /allowlist/workloads/{name}: validate the entry
// body and upsert it under the path name. An out-of-spec name or body is 422.
func (h Handler) HandlePutWorkload(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	entry, err := pkgallowlist.ParseWorkloadJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	name := chi.URLParam(r, "name")
	if err := h.Store.PutWorkload(name, *entry); err != nil {
		if errors.Is(err, ErrInvalidWorkload) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		writeStoreError(w, err)
		return
	}

	slog.Info("allowlist workload put", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteWorkload handles DELETE /allowlist/workloads/{name}: remove the
// named entry, 404 if absent.
func (h Handler) HandleDeleteWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r); !ok {
		return
	}

	name := chi.URLParam(r, "name")
	found, err := h.Store.DeleteWorkload(name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slog.Info("allowlist workload deleted", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// WriteUnavailable answers a write the replicated store could not commit:
// 503, retryable, never 401 or 500.
func WriteUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, ErrUnavailable.Error(), http.StatusServiceUnavailable)
}

// writeStoreError answers a failed store write.
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnavailable) {
		WriteUnavailable(w)
		return
	}
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// authorize reads the body (capped) and runs the configured authorizer.
// On success returns the body for downstream decoding.
func (h Handler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	cap := h.MaxWriteBodyBytes
	if cap <= 0 {
		cap = DefaultMaxWriteBodyBytes
	}
	return h.WriteAuthorizer.ReadAuthorized(w, r, cap)
}

// ReadAuthorized reads the body, capped at maxBytes, and authorizes it. On
// failure it has answered the request; a nil authorizer refuses every write.
// Every write CDS authorizes as an allowlist write goes through it.
func (a WriteAuthorizer) ReadAuthorized(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool) {
	if a == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	body, ok := httputil.ReadCappedBody(w, r, maxBytes)
	if !ok {
		return nil, false
	}
	if err := a(r, body); err != nil {
		slog.Warn("write rejected", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "reason", err)
		if errors.Is(err, ErrTokenReused) {
			http.Error(w, err.Error(), http.StatusConflict)
			return nil, false
		}
		if errors.Is(err, ErrUnavailable) {
			WriteUnavailable(w)
			return nil, false
		}
		if errors.Is(err, ErrTokenBeforeStart) {
			http.Error(w, ErrTokenBeforeStart.Error(), http.StatusUnauthorized)
			return nil, false
		}
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

// HandleHistory handles GET /allowlist/history: every document CDS served,
// oldest first.
func (h Handler) HandleHistory(w http.ResponseWriter, _ *http.Request) {
	entries, err := h.Store.History()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Entries []HistoryEntry `json:"entries"`
	}{entries})
}

var objectHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HandleObject handles GET /allowlist/objects/sha256/{hex}: the exact bytes
// of a document in the history.
func (h Handler) HandleObject(w http.ResponseWriter, r *http.Request) {
	h.serveByDigest(w, r, "application/json", func(digest string) ([]byte, bool, error) {
		return h.Store.Object(digest)
	})
}

// HandleSignature handles GET /allowlist/objects/sha256/{hex}/signature: the
// operator write token that signed that document.
func (h Handler) HandleSignature(w http.ResponseWriter, r *http.Request) {
	h.serveByDigest(w, r, "text/plain", func(digest string) ([]byte, bool, error) {
		token, ok, err := h.Store.Signature(digest)
		return []byte(token), ok, err
	})
}

func (h Handler) serveByDigest(w http.ResponseWriter, r *http.Request, contentType string, lookup func(string) ([]byte, bool, error)) {
	hex := chi.URLParam(r, "hex")
	if !objectHex.MatchString(hex) {
		http.Error(w, "digest must be 64 lowercase hex characters", http.StatusBadRequest)
		return
	}
	body, ok, err := lookup("sha256:" + hex)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(body)
}
