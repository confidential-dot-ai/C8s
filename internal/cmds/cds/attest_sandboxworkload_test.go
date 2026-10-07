package cds

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	wlDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wlDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	wlDigestC = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeStore is an allowlistGate over named workload entries plus a set of
// digests each admitted by its own any-argv entry (the shape the chart seeds
// for a platform image).
type fakeStore struct {
	anyArgv   map[string]bool
	workloads map[string]pkgallowlist.Workload
}

// anyArgvStore admits the given digests under any argv, one entry each.
func anyArgvStore(digests ...string) fakeStore {
	f := make(map[string]bool, len(digests))
	for _, d := range digests {
		f[d] = true
	}
	return fakeStore{anyArgv: f}
}

func (s fakeStore) Contains(d types.Digest) (bool, error) {
	for _, w := range s.allWorkloads() {
		for _, cd := range w.Digests() {
			if cd.String() == d.String() {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s fakeStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: s.allWorkloads()}, "1", nil
}

// allWorkloads is the named entries plus one "any-<hex12>" entry per anyArgv
// digest.
func (s fakeStore) allWorkloads() map[string]pkgallowlist.Workload {
	out := make(map[string]pkgallowlist.Workload, len(s.workloads)+len(s.anyArgv))
	maps.Copy(out, s.workloads)
	for d := range s.anyArgv {
		digest, err := types.ParseDigest(d)
		if err != nil {
			panic(err)
		}
		out["any-"+digest.Hex()[:12]] = pkgallowlist.Workload{Containers: []pkgallowlist.Container{{
			Digest:  digest,
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		}}}
	}
	return out
}

func wlDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

// workloadEntry builds a named entry whose init/main containers are the given
// digests.
func workloadEntry(t *testing.T, initDigests, mainDigests []string) pkgallowlist.Workload {
	t.Helper()
	var w pkgallowlist.Workload
	for _, d := range initDigests {
		w.InitContainers = append(w.InitContainers, pkgallowlist.Container{Digest: wlDigest(t, d)})
	}
	for _, d := range mainDigests {
		w.Containers = append(w.Containers, pkgallowlist.Container{Digest: wlDigest(t, d)})
	}
	return w
}

// A sandbox running only images admitted under any argv is issued a leaf. The
// requester sent no image list: everything checked here came from the inventory
// the token named.
func TestAttest_SandboxWorkload_AllowsFloorOnlySandbox(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = anyArgvStore(wlDigestA, wlDigestB)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// An image the inventory reports but the allowlist does not admit blocks
// issuance — the gate now runs on every token-bearing request, including the
// first one, where a self-reported claim used to be empty.
func TestAttest_SandboxWorkload_RejectsUnallowlistedImage(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// An inventory that does not know the sandbox is fail-closed: CDS cannot
// establish what the pod runs, which is exactly when it must not issue.
func TestAttest_SandboxWorkload_UnreachableInventoryFailsClosed(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{}, key: signer.PublicKey()} // knows no sandbox

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// An inventory reporting an empty sandbox is fail-closed. "No containers" is
// not "nothing to check": looping over it would pass the gate vacuously, and a
// sandbox always runs at least the sidecar that is asking.
func TestAttest_SandboxWorkload_EmptySandboxFailsClosed(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// Without a store or a callback client CDS cannot check what the sandbox runs,
// so a token-bearing request is refused rather than issued unchecked.
func TestAttest_SandboxWorkload_RejectsWhenGateUnwired(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire func(h *AttestHandler)
	}{
		{"no allowlist store", func(h *AttestHandler) { h.AllowlistStore = nil }},
		{"no digests client", func(h *AttestHandler) { h.SandboxDigests = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, stub.URL())
			tc.wire(&h)

			csrPEM, _ := generateCSR(t)
			challenge := issueChallenge(t, h)
			w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

// Issuance happens at arbitrary points in the pod lifecycle, and in most of
// them the running set is a strict subset of what the pod declares. Every one
// of these must still get a certificate: gating on the whole declared set would
// deny ordinary states, and permanently so once completed init containers are
// reaped (the running set never equals init+main again).
func TestAttest_SandboxWorkload_PartialLifecycleStatesIssue(t *testing.T) {
	store := fakeStore{
		anyArgv: map[string]bool{wlDigestC: true}, // the injected c8s-cert sidecar
		workloads: map[string]pkgallowlist.Workload{
			"api": workloadEntry(t, []string{wlDigestA}, []string{wlDigestB}),
		},
	}

	for _, tc := range []struct {
		name    string
		running []string
	}{
		{"only the injected sidecar (first issuance)", []string{wlDigestC}},
		{"user init container running", []string{wlDigestC, wlDigestA}},
		{"init done, main coming up", []string{wlDigestC, wlDigestB}},
		{"fully started", []string{wlDigestC, wlDigestA, wlDigestB}},
		{"a container transiently evicted while restarting", []string{wlDigestA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, stub.URL())
			h.AllowlistStore = store
			h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: tc.running}, key: signer.PublicKey()}

			csrPEM, _ := generateCSR(t)
			challenge := issueChallenge(t, h)
			w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

// Relaxing the whole-set match must not relax membership: an image no entry
// admits still blocks issuance, in every lifecycle state.
func TestAttest_SandboxWorkload_MembershipStillBitesMidLifecycle(t *testing.T) {
	store := fakeStore{
		anyArgv:   map[string]bool{wlDigestC: true},
		workloads: map[string]pkgallowlist.Workload{"api": workloadEntry(t, []string{wlDigestA}, nil)},
	}
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestC, wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// A request with no sandbox token is issued without a sandbox ID and without
// the workload gate: it gets a leaf no workload authorizer will accept.
func TestAttest_SandboxWorkload_NoTokenSkipsGate(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, stub.URL())
	h.AllowlistStore = anyArgvStore() // admits nothing
	h.SandboxDigests = fakeDigests{digests: map[string][]string{}}

	csrPEM, _ := generateCSR(t)
	w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// Dev mode: an empty measurement allowlist must not disable sandbox identity.
// CDS still verifies the token and still gates on the inventory's answer — it
// just accepts any armTLS-attested inventory rather than a pinned one, matching
// what an empty allowlist already means for /attest itself. Losing the whole
// flow here would break issuance for every workload on an unpinned cluster.
func TestAttest_SandboxWorkload_UnpinnedMeasurementsStillIssue(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.Measurements = nil // dev: --measurements empty
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	id, err := armtls.SandboxIDFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if id != testSandboxID {
		t.Fatalf("sandbox ID = %q, want %q", id, testSandboxID)
	}
}

// The allowlist gate still bites on an unpinned cluster: dropping the
// measurement pin must not also drop the image check.
func TestAttest_SandboxWorkload_UnpinnedStillEnforcesAllowlist(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.Measurements = nil
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// errStore fails every allowlist lookup, forcing the fail-closed branch.
type errStore struct{}

func (errStore) Contains(types.Digest) (bool, error) {
	return false, errors.New("store unavailable")
}

func (errStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	return nil, "", errors.New("store unavailable")
}

// A store that cannot answer must not yield an unnamed-but-issued leaf: the
// membership gate and the stamp both depend on that snapshot, so losing it has
// to fail issuance rather than silently downgrade to no workload.
func TestResolveSandboxWorkload_FailsClosedOnStoreError(t *testing.T) {
	h := AttestHandler{
		AllowlistStore: errStore{},
		SandboxDigests: fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA}}},
	}
	_, err := h.resolveSandboxWorkload(context.Background(), workloadclaims.VerifiedSandbox{
		SandboxID:     testSandboxID,
		InventoryHost: testInventoryHost,
	})
	if err == nil {
		t.Fatal("expected error when the allowlist store fails")
	}
}
