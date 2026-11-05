package cds

import (
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type atomicOperatorCommitter interface {
	WriteOperator(cdsha.OperatorCommand) (cdsha.OperatorResult, error)
}

// This handler is installed only by the measured pilot option. The existing
// request gate, rate limiter and body cap still surround every operator route.
// Shared mutable state stays in the backend's bounded per-cluster WAL actor.
type atomicOperatorHandler struct {
	commit   atomicOperatorCommitter
	verifier operatorauth.Verifier
	floor    func() time.Time
	skew     time.Duration
}

func (h atomicOperatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/allowlist" {
		if _, ok := allowlist.OperatorVersion(r.Header.Get("If-Match")); !ok {
			http.Error(w, allowlist.InvalidOperatorVersion, http.StatusPreconditionFailed)
			return
		}
	}
	body, ok := httputil.ReadCappedBody(w, r, allowlistWriteBodyCap)
	if !ok {
		return
	}
	defer clear(body)
	iat, err := h.verifier.AuthorizeIssuedAt(r, body)
	if err == nil && iat.Before(earliestIssue(h.floor(), h.skew)) {
		err = operatorauth.ErrTokenBeforeStart
	}
	if err != nil {
		httputil.RefuseOperatorToken(w, err)
		return
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	cmd := cdsha.OperatorCommand{Token: token, Path: r.URL.Path, IfMatch: r.Header.Get("If-Match"), Body: body, AtMS: time.Now().UnixMilli()}
	if raw := r.URL.EscapedPath(); raw != cmd.Path {
		cmd.EscapedPath = raw
	}
	result, err := h.commit.WriteOperator(cmd)
	if err != nil {
		// No receipt means no acknowledgement, even if durable commit may
		// already have happened. A caller cannot reuse a spent token.
		httputil.RefuseOperatorToken(w, operatorauth.ErrTokenNotRecorded)
		return
	}
	if result.NoStore {
		w.Header().Set("Cache-Control", "no-store")
	}
	if result.JSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.Code)
		_, _ = w.Write(result.Body)
	} else if result.Code >= 400 {
		http.Error(w, string(result.Body), result.Code)
	} else {
		w.WriteHeader(result.Code)
	}
}
