package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// explainHarness reuses the release harness's allowlist and inventory, so the
// diagnostic is exercised against the same policy the handler decides on.
type explainHarness struct {
	h       ExplainHandler
	inv     *fakeInventory
	authErr error
}

func newExplainHarness(t *testing.T) *explainHarness {
	t.Helper()
	rel := newHarness(t)
	eh := &explainHarness{inv: rel.inv}
	eh.h = ExplainHandler{
		Inventory:      rel.h.Inventory,
		Bindings:       rel.h.Bindings,
		Policy:         rel.h.Policy,
		InventoryHosts: rel.h.InventoryHosts,
		Authorize:      func(*http.Request, []byte) error { return eh.authErr },
	}
	return eh
}

// serve routes through chi so the {sandboxID} parameter is populated the way
// the real router populates it.
func (eh *explainHarness) serve(sandboxID string) (*httptest.ResponseRecorder, ExplainResponse) {
	r := chi.NewRouter()
	r.Method(http.MethodGet, ExplainRoute, eh.h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/secrets-explain/"+sandboxID, nil))
	var resp ExplainResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func TestExplainResolvesTheGrant(t *testing.T) {
	eh := newExplainHarness(t)
	w, resp := eh.serve(testSandbox)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
	}
	if resp.Match != "api" || resp.Grant == nil {
		t.Fatalf("resp = %+v, want a resolved grant for api", resp)
	}
	if resp.Refusal != "" {
		t.Fatalf("a resolved grant must carry no refusal, got %q", resp.Refusal)
	}
	if resp.InventoryHost != testHost {
		t.Fatalf("inventory = %q, want the bound host", resp.InventoryHost)
	}
}

// The injected sidecar is reported but marked, and does not reach the candidate
// set — the operator has to be able to see why it is excluded.
func TestExplainMarksInjectedContainers(t *testing.T) {
	eh := newExplainHarness(t)
	_, resp := eh.serve(testSandbox)

	if len(resp.Reported) != 3 || len(resp.Candidates) != 2 {
		t.Fatalf("reported=%d candidates=%d, want 3 and 2", len(resp.Reported), len(resp.Candidates))
	}
	var injected int
	for _, c := range resp.Reported {
		if c.Injected {
			injected++
			if c.Digest != testInjected {
				t.Fatalf("the wrong container was dropped: %s", c.Digest)
			}
		}
	}
	if injected != 1 {
		t.Fatalf("injected = %d, want 1", injected)
	}
	if resp.Candidates[0].Digest != testAppImg || resp.Candidates[1].Digest != testAppImg2 {
		t.Fatalf("candidates = %+v, want the two app images", resp.Candidates)
	}
}

// The near-miss case the command exists for: a pod runs an undeclared image, so
// the entry fails the subset check and the diagnostic names the culprit.
func TestExplainNamesTheForeignContainer(t *testing.T) {
	eh := newExplainHarness(t)
	eh.inv.containers = append(eh.inv.containers,
		workloadclaims.SandboxContainer{Digest: testOther, Argv: []string{"sh", "-c", "sleep 1"}})

	_, resp := eh.serve(testSandbox)
	if resp.Match != "" || resp.Grant != nil {
		t.Fatalf("an undeclared image must refuse, got %+v", resp)
	}
	if !strings.Contains(resp.Refusal, "no entry describes") {
		t.Fatalf("refusal = %q", resp.Refusal)
	}
	var found bool
	for _, e := range resp.Entries {
		if e.Name != "api" {
			continue
		}
		if e.Matches {
			t.Fatal("api must not match once a foreign image is running")
		}
		for _, f := range e.Foreign {
			if f.Digest == testOther {
				found = true
				if len(f.Argv) == 0 {
					t.Fatal("the foreign container's argv is what identifies it")
				}
			}
		}
	}
	if !found {
		t.Fatal("the foreign digest was not named in the entry's diff")
	}
}

// A container the reporting node binds no role to is a workload container, so
// it must land in candidates rather than being silently dropped.
func TestExplainDoesNotDropAContainerWithoutARole(t *testing.T) {
	eh := newExplainHarness(t)
	eh.inv.containers = append(eh.inv.containers,
		workloadclaims.SandboxContainer{Digest: testInjected, Argv: []string{"sh", "-c", "cat /run/c8s/secrets/DB"}})

	_, resp := eh.serve(testSandbox)
	for _, c := range resp.Reported {
		if c.Digest == testInjected && len(c.Argv) > 0 && c.Argv[0] == "sh" && c.Injected {
			t.Fatal("an any-argv image running a shell was dropped as injected")
		}
	}
	if resp.Match != "" {
		t.Fatalf("it must break the match, got %q", resp.Match)
	}
}

// A matching entry whose grant is refused for an unconstrained argv names that
// as the refusal, with no grant in the answer.
func TestExplainNamesUnpinnedGrant(t *testing.T) {
	eh := newExplainHarness(t)
	al, _ := eh.h.Policy.Allowlist()
	api := al.Workloads["api"]
	api.Containers[0].Args = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	al.Workloads["api"] = api
	eh.h.Policy = fakePolicy{al: al}

	_, resp := eh.serve(testSandbox)
	if resp.Match != "api" {
		t.Fatalf("match = %q, want api", resp.Match)
	}
	if resp.Grant != nil || !strings.Contains(resp.Refusal, "unconstrained") {
		t.Fatalf("refusal = %q, grant = %v; want the unpinned argv named and no grant", resp.Refusal, resp.Grant)
	}
}

// Declared mains that are not running are the other half of the diff.
func TestExplainNamesAMissingMain(t *testing.T) {
	eh := newExplainHarness(t)
	eh.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testInjected, Argv: []string{"get-cert", "--san=x"}, Role: roleCredentials},
		{Digest: testOther, Argv: []string{"sh"}},
	}

	_, resp := eh.serve(testSandbox)
	for _, e := range resp.Entries {
		if e.Name != "api" {
			continue
		}
		if len(e.MissingMains) != 2 || e.MissingMains[0].Digest != testAppImg || e.MissingMains[1].Digest != testAppImg2 {
			t.Fatalf("missing mains = %+v, want both app images", e.MissingMains)
		}
	}
}

// Every refusal the release path can reach has to be nameable here, or the
// command answers the easy cases only.
func TestExplainReportsEarlyRefusals(t *testing.T) {
	t.Run("no binding", func(t *testing.T) {
		eh := newExplainHarness(t)
		eh.h.Bindings = fakeBindings{}
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "no inventory is bound") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
	t.Run("host outside the bound", func(t *testing.T) {
		eh := newExplainHarness(t)
		eh.h.Bindings = fakeBindings{host: "192.168.1.1"}
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "outside the node addresses") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
	// A CDS whose bound never resolved must refuse rather than dereference it.
	t.Run("no bound at all", func(t *testing.T) {
		eh := newExplainHarness(t)
		eh.h.InventoryHosts = nil
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "outside the node addresses") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
	t.Run("inventory unreachable", func(t *testing.T) {
		eh := newExplainHarness(t)
		eh.inv.err = fmt.Errorf("connection refused")
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "did not answer") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
	t.Run("only injected containers", func(t *testing.T) {
		eh := newExplainHarness(t)
		eh.inv.containers = []workloadclaims.SandboxContainer{
			{Digest: testInjected, Argv: []string{"get-cert"}, Role: roleCredentials},
		}
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "platform-injected") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
	t.Run("matching entry has no grant", func(t *testing.T) {
		eh := newExplainHarness(t)
		al, _ := eh.h.Policy.Allowlist()
		entry := al.Workloads["api"]
		entry.Secrets = nil
		al.Workloads["api"] = entry
		_, resp := eh.serve(testSandbox)
		if resp.Match != "api" || !strings.Contains(resp.Refusal, "no secret grant") {
			t.Fatalf("match=%q refusal=%q", resp.Match, resp.Refusal)
		}
	})
	t.Run("ambiguous match", func(t *testing.T) {
		eh := newExplainHarness(t)
		al, _ := eh.h.Policy.Allowlist()
		al.Workloads["api-copy"] = al.Workloads["api"]
		_, resp := eh.serve(testSandbox)
		if !strings.Contains(resp.Refusal, "ambiguous") {
			t.Fatalf("refusal = %q", resp.Refusal)
		}
	})
}

// The report describes someone else's pod, so it answers only to the operator
// key — never to a sandbox token, and never to nothing at all.
func TestExplainRequiresOperatorAuth(t *testing.T) {
	eh := newExplainHarness(t)
	eh.authErr = fmt.Errorf("no token")
	w, _ := eh.serve(testSandbox)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	unconfigured := ExplainHandler{}
	r := chi.NewRouter()
	r.Method(http.MethodGet, ExplainRoute, unconfigured)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets-explain/"+testSandbox, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d with no authorizer, want 401", rec.Code)
	}
}

// The ID is bounded by the same rule CDS applies when it stamps one on a leaf,
// so the diagnostic accepts exactly the IDs that can exist and refuses the rest
// before dialling anything.
func TestExplainRejectsAMalformedSandboxID(t *testing.T) {
	for _, tc := range []struct{ name, id string }{
		{"out of character class", "sandbox!id"},
		{"over the length bound", strings.Repeat("a", 129)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eh := newExplainHarness(t)
			w, _ := eh.serve(tc.id)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
		})
	}
}

// A value must never reach this report; it carries paths only.
func TestExplainCarriesNoSecretValues(t *testing.T) {
	eh := newExplainHarness(t)
	w, resp := eh.serve(testSandbox)
	if resp.Grant == nil {
		t.Fatal("expected a grant")
	}
	for _, p := range append(append([]string{}, resp.Grant.Read...), resp.Grant.Write...) {
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("grant entry %q is not a path", p)
		}
	}
	if strings.Contains(w.Body.String(), "value") {
		t.Fatalf("the report mentions a value: %s", w.Body)
	}
}

// The diagnostic is the release decision, not a second opinion on it: whatever
// the handler resolves, MatchWorkload must resolve the same way.
func TestExplainAgreesWithTheMatcher(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running []workloadclaims.SandboxContainer
	}{
		{"match", []workloadclaims.SandboxContainer{
			{Digest: testAppImg, Argv: []string{"/serve"}},
			{Digest: testAppImg2, Argv: []string{"/metrics"}},
			{Digest: testInjected, Argv: []string{"get-cert"}, Role: roleCredentials},
		}},
		{"foreign image", []workloadclaims.SandboxContainer{
			{Digest: testAppImg, Argv: []string{"/serve"}},
			{Digest: testOther, Argv: []string{"sh"}},
		}},
		{"wrong argv", []workloadclaims.SandboxContainer{
			{Digest: testAppImg, Argv: []string{"/bin/sh"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eh := newExplainHarness(t)
			eh.inv.containers = tc.running
			_, resp := eh.serve(testSandbox)

			al, _ := eh.h.Policy.Allowlist()
			reported, _ := eh.inv.FetchSandbox(context.Background(), "", testSandbox)
			candidates := WorkloadContainers(reported.Containers)
			name, _, err := al.MatchWorkload(candidates)
			if err != nil {
				name = ""
			}
			if resp.Match != name {
				t.Fatalf("explain says %q, the matcher says %q", resp.Match, name)
			}
		})
	}
}
