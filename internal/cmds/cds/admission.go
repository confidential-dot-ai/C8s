package cds

import (
	"context"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// Each CDS process serves one measured cluster. These budgets belong to that
// process, never to an unauthenticated caller-supplied cluster ID. Revocation
// and recovery retain their own capacity during issuance or renewal bursts.
// Limits count active AND queued requests; they are pilot defaults, not an SLO.
type requestAdmission struct{ workload, control *requestgate.Gate }

func newRequestAdmission(ctx context.Context) *requestAdmission {
	workload, err := requestgate.New(ctx, 32, 128)
	if err != nil {
		panic(err)
	} // Compile-time constants satisfy the bounds.
	control, err := requestgate.New(ctx, 4, 32)
	if err != nil {
		panic(err)
	}
	return &requestAdmission{workload: workload, control: control}
}

func (a *requestAdmission) Close() { a.workload.Close(); a.control.Close() }

// Wrap OUTSIDE the backend's freshness gate: queued work must confirm a fresh
// watermark after admission, not before it waits. Forwarded WAL commands use
// the existing authenticated, byte-bounded peer mailbox to avoid a cycle where
// all client permits wait on peer work that needs one of those same permits.
func (a *requestAdmission) Handler(next http.Handler) http.Handler {
	workload, control := a.workload.Handler(next), a.control.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz"):
			next.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == cdsobject.ForwardPath:
			next.ServeHTTP(w, r)
		case isControlRequest(r):
			control.ServeHTTP(w, r)
		default:
			workload.ServeHTTP(w, r)
		}
	})
}

func isControlRequest(r *http.Request) bool {
	if r.Method == http.MethodPut {
		return r.URL.Path == "/allowlist" || r.URL.Path == routes.Path || strings.HasPrefix(r.URL.Path, "/secrets/")
	}
	if r.Method == http.MethodPost {
		return r.URL.Path == "/ha/decrees" || r.URL.Path == objectProvisionPath
	}
	return false
}
