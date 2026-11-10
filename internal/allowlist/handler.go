package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/server"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// DefaultMaxWriteBodyBytes caps a mutation body when Handler.MaxWriteBodyBytes
// is zero. One entry fits; the deployed handler raises this so a full document
// fits (see the cds router's allowlist write cap).
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// Handler holds the dependencies for allowlist HTTP handlers.
type Handler struct {
	Allowlist       *Handle
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; a non-positive value clamps to the default.
	MaxWriteBodyBytes int64
}

// WriteAuthorizer authorizes a mutation given the raw request body, so the
// check binds the token to the body's SHA-256 (defeating captured-token replay
// against a different payload). Production wires operatorauth.Verifier.Authorize.
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /allowlist: the document the store serves, tagged
// with its digest and carrying its version. With pkgallowlist.NodeQuery it is
// the allowlist in effect on nodes. An If-None-Match naming exactly that tag
// returns 304.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body []byte
	var version string
	var err error
	if r.URL.RawQuery == pkgallowlist.NodeQuery {
		body, version, err = h.Allowlist.InEffect(time.Now())
	} else {
		body, version, err = h.Allowlist.Served()
	}
	if err != nil {
		readFailed(w, err)
		return
	}
	tag := pkgallowlist.EntityTag(objectDigest(body))
	w.Header().Set("ETag", tag)
	w.Header().Set(pkgallowlist.VersionHeader, version)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// HandleReplaceAll handles PUT /allowlist: validate the full document and swap
// it in atomically. CDS assigns the new version.
//
// If-Match makes the swap conditional on the version: the strong tag "N"
// matches version N, the version GET serves in its VersionHeader. A refused
// precondition, including "*", is 412 and changes nothing. No If-Match swaps
// unconditionally.
func (h Handler) HandleReplaceAll(w http.ResponseWriter, r *http.Request) {
	// Before the token is spent: a precondition no version can satisfy is
	// the operator's mistake, not a write.
	version, matchable := requiredVersion(r.Header.Get("If-Match"))
	if !matchable {
		http.Error(w, `If-Match takes the strong tag "N" of version N, which GET /allowlist names in `+pkgallowlist.VersionHeader, http.StatusPreconditionFailed)
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
	if err := h.Allowlist.ReplaceAll(al, write); err != nil {
		if errors.Is(err, ErrVersionMismatch) {
			http.Error(w, err.Error()+"; fetch it and apply the change again", http.StatusPreconditionFailed)
			return
		}
		WriteFailed(w, err)
		return
	}

	server.LogAfterCommit(
		r.Context(),
		slog.Default(),
		"allowlist replaced",
		"workloads",
		len(al.Workloads),
	)
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
		if refusedByTheStore(err) {
			WriteFailed(w, err)
			return nil, false
		}
		httputil.RefuseOperatorToken(w, err)
		return nil, false
	}
	return body, true
}

// WriteFailed answers a write the allowlist store refused or could not take,
// the route manifest's included. The 503 is retryable at another replica; the
// 507s clear when the state shrinks.
func WriteFailed(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnavailable):
		slog.Warn("allowlist write not taken", "err", err)
		httputil.WriteUnavailable(w, ErrUnavailable)
	case errors.Is(err, ErrCapacity):
		slog.Warn("allowlist write refused: the replicated state is at its snapshot capacity", "err", err)
		http.Error(w, ErrCapacity.Error(), http.StatusInsufficientStorage)
	case errors.Is(err, ErrStoreFull):
		slog.Error("allowlist write refused: the store has no room left", "err", err)
		http.Error(w, ErrStoreFull.Error(), http.StatusInsufficientStorage)
	default:
		slog.Error("allowlist write failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// refusedByTheStore reports an error of the store rather than of the token.
func refusedByTheStore(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrCapacity) || errors.Is(err, ErrStoreFull)
}

func readFailed(w http.ResponseWriter, err error) {
	if IsLocalStoreFault(err) {
		slog.Warn("allowlist read failed on the local store", "err", err)
		httputil.WriteUnavailable(w, ErrUnavailable)
		return
	}
	slog.Error("allowlist read failed", "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// HandleHistory handles GET /allowlist/history: every document CDS served,
// oldest first, and the host privilege the allowlist declared.
func (h Handler) HandleHistory(w http.ResponseWriter, _ *http.Request) {
	history, err := h.Allowlist.History()
	if err != nil {
		readFailed(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

var objectHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HandleObject handles GET /allowlist/objects/sha256/{hex}: the exact bytes
// of a document in the history.
func (h Handler) HandleObject(w http.ResponseWriter, r *http.Request) {
	h.serveByDigest(w, r, "application/json", func(digest string) ([]byte, bool, error) {
		return h.Allowlist.Object(digest)
	})
}

// HandleSignature handles GET /allowlist/objects/sha256/{hex}/signature: the
// operator write token that signed that document.
func (h Handler) HandleSignature(w http.ResponseWriter, r *http.Request) {
	h.serveByDigest(w, r, "text/plain", func(digest string) ([]byte, bool, error) {
		token, ok, err := h.Allowlist.Signature(digest)
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
		readFailed(w, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(body)
}
