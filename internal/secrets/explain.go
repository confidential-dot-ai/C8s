package secrets

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// ExplainRoute answers what a sandbox would be released and why. It is a
// sibling of Route rather than a path under it: chi prefers a literal segment
// over a wildcard, so "/secrets/explain/..." would make a secret stored at
// /explain/... unreachable.
const ExplainRoute = "/secrets-explain/{sandboxID}"

// ReportedContainer is one container the inventory named, and whether the
// release path drops it as one the node's measured base binds a platform role
// to.
type ReportedContainer struct {
	Env      *pkgallowlist.EnvObservation `json:"env,omitempty"`
	Mounts   []pkgallowlist.ObservedMount `json:"mounts"`
	Digest   string                       `json:"digest"`
	Argv     []string                     `json:"argv"`
	Injected bool                         `json:"injected"`
}

// EntryVerdict is one workload entry measured against the candidate set.
type EntryVerdict struct {
	Name string `json:"name"`
	// Foreign is what the sandbox runs that this entry does not declare.
	Foreign []ReportedContainer `json:"foreign,omitempty"`
	// MissingMains is the main containers this entry declares that nothing
	// running satisfies.
	MissingMains []MissingContainer `json:"missingMains,omitempty"`
	Matches      bool               `json:"matches"`
	// HasGrant reports whether a matching entry would release anything.
	HasGrant bool `json:"hasGrant"`
}

// MissingContainer names a declared main the sandbox is not running.
type MissingContainer struct {
	Digest string `json:"digest"`
	Image  string `json:"image,omitempty"`
}

// ExplainResponse is the whole decision, in the order it is made.
type ExplainResponse struct {
	SandboxID     string              `json:"sandboxID"`
	InventoryHost string              `json:"inventoryHost,omitempty"`
	Reported      []ReportedContainer `json:"reported,omitempty"`
	Candidates    []ReportedContainer `json:"candidates,omitempty"`
	Entries       []EntryVerdict      `json:"entries,omitempty"`
	// Match names the single entry that describes the candidate set.
	Match string `json:"match,omitempty"`
	// Grant is that entry's secret grant. Paths only; a value never appears
	// here.
	Grant *pkgallowlist.SecretsPolicy `json:"grant,omitempty"`
	// Refusal states why nothing is released, in the terms the release path
	// uses. Empty when a grant resolved.
	Refusal string `json:"refusal,omitempty"`
}

// ExplainHandler serves ExplainRoute.
//
// Release denials are opaque to the workload by design and the input that
// decides them — what the sandbox is running — is visible only to CDS, so
// without this a wedged pod is diagnosable only from CDS logs.
//
// It answers to the operator key, not to a sandbox token: the caller is asking
// about someone else's pod, which no workload may do.
type ExplainHandler struct {
	Inventory      inventorySource
	Bindings       bindingSource
	Policy         policySource
	InventoryHosts workloadclaims.InventoryHosts

	// Authorize is operatorauth.Verifier.Authorize. Nil rejects every request.
	Authorize func(r *http.Request, body []byte) error

	Logger *slog.Logger
}

func (h ExplainHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h ExplainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Authorize == nil {
		http.Error(w, "operator writes are not configured", http.StatusUnauthorized)
		return
	}
	// The read has no body; the token still binds the method and the sandbox ID
	// in the path.
	if err := h.Authorize(r, nil); err != nil {
		h.logger().Warn("secret explain rejected", "remote", r.RemoteAddr, "reason", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sandboxID := chi.URLParam(r, "sandboxID")
	if err := armtls.ValidateSandboxID(sandboxID); err != nil {
		http.Error(w, "invalid sandbox ID", http.StatusBadRequest)
		return
	}

	resp := h.explain(r.Context(), sandboxID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// explain walks the release decision in order and stops at the first thing that
// would refuse, so the answer names the earliest cause rather than a downstream
// symptom of it.
func (h ExplainHandler) explain(ctx context.Context, sandboxID string) ExplainResponse {
	resp := ExplainResponse{SandboxID: sandboxID}

	if h.Bindings == nil || h.Inventory == nil {
		resp.Refusal = "secrets are not configured to reach an inventory"
		return resp
	}
	host, ok := h.Bindings.Lookup(sandboxID)
	if !ok {
		resp.Refusal = "no inventory is bound to this sandbox: it has not attested since CDS started, or a second inventory claimed the ID"
		return resp
	}
	if h.InventoryHosts == nil || !h.InventoryHosts.Contains(host) {
		resp.InventoryHost = host
		resp.Refusal = "the bound inventory is outside the node addresses the callback is bounded to"
		return resp
	}
	resp.InventoryHost = host

	al, err := h.Policy.Allowlist()
	if err != nil {
		resp.Refusal = "the allowlist could not be loaded"
		return resp
	}
	sandbox, err := h.Inventory.FetchSandbox(ctx, host, sandboxID)
	if err != nil {
		resp.Refusal = "the bound inventory did not answer for this sandbox"
		return resp
	}
	reported, err := sandbox.RequireContainers()
	if err != nil {
		resp.Refusal = "the inventory reports no per-container detail: it predates argv reporting and cannot be used for release"
		return resp
	}

	for _, c := range reported {
		platform := c.Role != ""
		entry := ReportedContainer{
			Digest:   c.Digest,
			Argv:     c.Argv,
			Env:      c.Env,
			Mounts:   c.Mounts,
			Injected: platform,
		}
		resp.Reported = append(resp.Reported, entry)
		if platform {
			continue
		}
		resp.Candidates = append(resp.Candidates, entry)
	}
	candidates := WorkloadContainers(reported)
	if len(candidates) == 0 {
		resp.Refusal = "every container the sandbox reports is a platform-injected one, so there is nothing to match"
		return resp
	}

	var matched []string
	for _, name := range sortedNames(al.Workloads) {
		d := al.Workloads[name].Diff(candidates)
		v := EntryVerdict{
			Name:     name,
			Matches:  d.Describes(),
			HasGrant: al.Workloads[name].Secrets != nil,
		}
		for _, f := range d.Foreign {
			v.Foreign = append(v.Foreign, ReportedContainer{Digest: f.Digest, Argv: f.Argv, Env: f.Env, Mounts: f.Mounts})
		}
		for _, m := range d.MissingMains {
			v.MissingMains = append(v.MissingMains, MissingContainer{Digest: m.Digest.String(), Image: m.Image})
		}
		resp.Entries = append(resp.Entries, v)
		if v.Matches {
			matched = append(matched, name)
		}
	}

	switch {
	case len(matched) == 0:
		resp.Refusal = "no entry describes the candidate set"
	case len(matched) > 1:
		resp.Refusal = "more than one entry describes the candidate set, so the match is ambiguous"
	default:
		resp.Match = matched[0]
		grant := al.Workloads[matched[0]].Secrets
		if grant == nil {
			resp.Refusal = "the matching entry carries no secret grant"
			return resp
		}
		if !al.Workloads[matched[0]].ArgvPinned() {
			resp.Refusal = "the matching entry leaves a container's argv unconstrained; a grant requires every command and args policy to be exact or deny"
			return resp
		}
		resp.Grant = grant
	}
	return resp
}

// sortedNames keeps the verdict list stable across calls.
func sortedNames(m map[string]pkgallowlist.Workload) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
