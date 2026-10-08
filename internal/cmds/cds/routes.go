package cds

import (
	"crypto/ecdsa"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/server"
)

// dependencies bundles everything the cds router needs.
type dependencies struct {
	AttestHandler     AttestHandler
	AllowlistHandler  allowlist.Handler
	ReadyFn           attestation.ReadinessFunc
	CACertPEM         []byte
	OperatorKeysPEM   []byte                // pinned operator public keys; empty = /operator-keys 404s
	MeasurementsDoc   []byte                // reference values being enforced, as served at /measurements
	RateLimiter       *issuer.IPRateLimiter // per-source-IP limiter for attestation endpoints
	ChallengeLimiter  *issuer.IPRateLimiter // /authenticate's own, so it cannot spend the map above
	MaxRequestSize    int64                 // applied to write endpoints; must be > 0
	SecretsHandler    *secrets.Handler      // nil leaves /secrets unrouted (--secrets off)
	SecretsChallenges *attestation.ChallengeStore
	SecretsOperator   *secrets.OperatorHandler // operator-supplied values; routed with SecretsHandler
	SecretsExplain    *secrets.ExplainHandler  // release diagnostic; routed with SecretsHandler
	StateKey          *ecdsa.PrivateKey        // signs /.well-known/c8s/state; the mesh CA key
}

func newRouter(deps dependencies) http.Handler {
	if deps.MaxRequestSize <= 0 {
		panic("cds: dependencies.MaxRequestSize must be positive")
	}
	if deps.RateLimiter == nil {
		panic("cds: dependencies.RateLimiter must be set")
	}
	if deps.ChallengeLimiter == nil {
		panic("cds: dependencies.ChallengeLimiter must be set")
	}
	if deps.ChallengeLimiter == deps.RateLimiter {
		panic("cds: dependencies.ChallengeLimiter must be a limiter of its own, not the attestation one")
	}
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/readyz", attestation.HandleReadyz(deps.ReadyFn))
	r.Method(http.MethodGet, "/metrics", promhttp.Handler())

	r.Method(http.MethodPost, "/authenticate", deps.challengeProtected(attestation.HandleAuthenticate(deps.AttestHandler.Challenges)))
	r.Method(http.MethodPost, "/attest", deps.protected(http.HandlerFunc(deps.AttestHandler.HandleAttest)))

	// GET is unauthenticated (RA-TLS integrity only); every mutation goes
	// through allowlistWrite (operator-JWT auth in the handler + rate limit +
	// 1 MiB body cap).
	r.Get("/allowlist", deps.AllowlistHandler.HandleList)
	r.Method(http.MethodPut, "/allowlist", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleReplaceAll)))
	r.Method(http.MethodPut, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandlePutWorkload)))
	r.Method(http.MethodDelete, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleDeleteWorkload)))

	store := deps.AllowlistHandler.Store
	r.Get(wellKnown+"/objects/sha256/{hex}", handleObject(store))
	r.Get(wellKnown+"/allowlist/latest", handleLatest(store))
	// Unmetered like GET /allowlist: routers read the state every second and
	// once per attest-pq, which a per-node budget shared with /attest cannot
	// carry. nginx meters the public route.
	r.Get(wellKnown+"/state", handleState(store, deps.StateKey, false))
	r.Method(http.MethodPost, wellKnown+"/state/challenge", capBody(deps.MaxRequestSize, handleState(store, deps.StateKey, true)))

	// GET and POST are the workload's, authenticated by mesh leaf and sandbox
	// token. PUT is the operator's, on allowlistWrite so it carries the same
	// body-bound operator token an allowlist mutation does.
	if deps.SecretsHandler != nil {
		if deps.SecretsOperator == nil || deps.SecretsExplain == nil {
			panic("cds: dependencies.SecretsOperator and SecretsExplain must be set alongside SecretsHandler")
		}
		r.Method(http.MethodPost, secrets.ChallengeRoute, deps.perSandbox(attestation.HandleAuthenticate(deps.SecretsChallenges)))
		r.Method(http.MethodGet, secrets.Route, deps.perSandbox(deps.SecretsHandler))
		r.Method(http.MethodPost, secrets.Route, deps.perSandbox(deps.SecretsHandler))
		r.Method(http.MethodPut, secrets.Route, deps.allowlistWrite(deps.SecretsOperator))
		r.Method(http.MethodGet, secrets.ExplainRoute, deps.allowlistWrite(deps.SecretsExplain))
	}

	r.Get("/ca", handleCA(deps.CACertPEM))
	r.Get("/operator-keys", handleOperatorKeys(deps.OperatorKeysPEM))
	r.Get("/measurements", handleMeasurements(deps.MeasurementsDoc))

	return r
}

// allowlistWriteBodyCap bounds an allowlist mutation body. A workload document
// dwarfs a digest line, so it is far larger than MaxRequestSize.
const allowlistWriteBodyCap int64 = 1 << 20

// protected wraps a write handler with per-source-IP rate limiting and the
// request-body cap. Its routes verify evidence or a token before they answer,
// so a junk write costs up to one ECDSA verify per pinned key.
func (deps dependencies) protected(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(deps.MaxRequestSize, next))
}

// challengeProtected meters /authenticate in a limiter of its own, so a
// challenge and the /attest that redeems it are charged separately and the
// challenge keys do not spend the map the other routes are metered in.
//
// Its key is the source address, which for a pod is the node's: pods reach
// CDS through a NodePort and the host-network mesh proxy. One pod can spend
// the budget its co-tenants share — as it already can on /attest, which the
// challenge is only useful with — and pods on a node share a trust domain.
func (deps dependencies) challengeProtected(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.ChallengeLimiter, capBody(deps.MaxRequestSize, next))
}

// allowlistWrite is protected with the larger allowlist body cap. Its callers
// are operators reaching CDS directly, so the source address is the caller.
func (deps dependencies) allowlistWrite(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(allowlistWriteBodyCap, next))
}

// perSandbox rate-limits by the caller's attested sandbox instead of its
// address. The workload secret routes are the ones pods reach through a
// NodePort and the mesh proxy, where the address is the node's rather than the
// pod's — see secrets.RateKey.
func (deps dependencies) perSandbox(next http.Handler) http.Handler {
	return issuer.RateLimitBy(deps.RateLimiter, secrets.RateKey, capBody(deps.MaxRequestSize, next))
}

func capBody(max int64, next http.Handler) http.Handler {
	return http.MaxBytesHandler(next, max)
}

func handleCA(caCertPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCertPEM)
	}
}

// handleOperatorKeys serves the pinned operator public-key bundle (public
// material, like /ca) so `c8s verify` can report which keys may mutate the
// allowlist. 404 when allowlist writes are disabled (no pinned keys).
// handleMeasurements serves the reference values this CDS is enforcing. An
// empty set is served, not 404'd: "admitting any measurement" is the state a
// verifier most needs to be told about.
func handleMeasurements(doc []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if len(doc) == 0 {
			http.Error(w, "measurements unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(doc)
	}
}

func handleOperatorKeys(operatorKeysPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if len(operatorKeysPEM) == 0 {
			http.Error(w, "no operator keys configured (allowlist writes disabled)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(operatorKeysPEM)
	}
}
