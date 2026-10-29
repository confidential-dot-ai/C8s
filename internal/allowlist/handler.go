package allowlist

import (
	"bytes"
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
//
// If-Match makes the swap conditional on the version: the strong tag "N"
// matches version N, the N of the ETag W/"N" that GET serves. A refused
// precondition is 412 and changes nothing. No If-Match, or "*", swaps
// unconditionally.
func (h Handler) HandleReplaceAll(w http.ResponseWriter, r *http.Request) {
	// Before the token is spent: a precondition no version can satisfy is
	// the operator's mistake, not a write.
	version, matchable := requiredVersion(r.Header.Get("If-Match"))
	if !matchable {
		http.Error(w, `If-Match takes the strong tag "N" of version N, which the ETag W/"N" of GET /allowlist names`, http.StatusPreconditionFailed)
		return
	}

	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	al, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	write := OperatorWrite{Version: version, Signature: operatorSignature(r, al, body)}
	if write.Signature == "" {
		slog.Warn("allowlist write stores no operator signature: its body is not the document's canonical bytes",
			"remote", r.RemoteAddr)
	}
	if err := h.Store.ReplaceAll(al, write); err != nil {
		if errors.Is(err, ErrVersionMismatch) {
			http.Error(w, err.Error()+"; fetch it and apply the change again", http.StatusPreconditionFailed)
			return
		}
		slog.Error("allowlist write failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("allowlist replaced", "workloads", len(al.Workloads))
	w.WriteHeader(http.StatusNoContent)
}

// requiredVersion is the allowlist version an If-Match header requires, empty
// when there is no header: that write is unconditional. Only the strong tag
// "N" of a version can match, since If-Match compares strongly (RFC 9110
// 13.1.1), so a weak tag or any other form is not matchable.
func requiredVersion(ifMatch string) (version string, matchable bool) {
	if ifMatch == "" {
		return "", true
	}
	version, ok := strings.CutPrefix(ifMatch, `"`)
	if !ok {
		return "", false
	}
	version, ok = strings.CutSuffix(version, `"`)
	if !ok || version == "" {
		return "", false
	}
	return version, true
}

// operatorSignature is the write token of a body that is the document's
// canonical bytes: the operator's signature over what verifiers fetch
// (docs/allowlist-and-capabilities.md). Any other body signs nothing.
func operatorSignature(r *http.Request, al *pkgallowlist.Allowlist, body []byte) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !isCanonicalDocument(al, body) {
		return ""
	}
	return token
}

// isCanonicalDocument reports whether body is exactly al's canonical bytes,
// the bytes GET /allowlist serves and a verifier fetches.
func isCanonicalDocument(al *pkgallowlist.Allowlist, body []byte) bool {
	canonical, err := al.Canonical()
	return err == nil && bytes.Equal(canonical, body)
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
		httputil.RefuseOperatorToken(w, err)
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
