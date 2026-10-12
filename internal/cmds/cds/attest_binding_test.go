package cds

import (
	"net/http"
	"testing"
)

// recordingBinder captures what issuance binds, so a test can tell a written
// binding from a skipped one.
type recordingBinder struct {
	calls  [][2]string
	refuse bool
}

func (r *recordingBinder) Record(sandboxID, inventoryHost string) bool {
	r.calls = append(r.calls, [2]string{sandboxID, inventoryHost})
	return !r.refuse
}

// A successful issuance binds the sandbox to the inventory that vouched for it,
// so the secrets path later asks that same inventory rather than one a
// requester names.
func TestAttest_BindsSandboxToInventoryOnSuccess(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	binder := &recordingBinder{}
	h.SandboxBindings = binder
	csrPEM := sandboxCSR(t)

	challenge := issueChallenge(t, h)
	if w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID)); w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	if len(binder.calls) != 1 {
		t.Fatalf("Record called %d times, want 1", len(binder.calls))
	}
	if binder.calls[0][0] != testSandboxID {
		t.Fatalf("bound sandbox = %q, want %q", binder.calls[0][0], testSandboxID)
	}
	if binder.calls[0][1] == "" {
		t.Fatal("bound an empty inventory host")
	}
}

// A conflicting binding must not cost the pod its certificate: get-cert has no
// token-less retry, so denying here would let one pre-claim wedge a pod for a
// whole certificate lifetime. The refusal lands on the secrets path instead.
func TestAttest_ConflictingBindingStillIssues(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.SandboxBindings = &recordingBinder{refuse: true}
	csrPEM := sandboxCSR(t)

	challenge := issueChallenge(t, h)
	if w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID)); w.Code != http.StatusOK {
		t.Fatalf("a refused binding blocked issuance: status %d, body=%s", w.Code, w.Body.String())
	}
}

// A request carrying no sandbox token gets no binding — there is no sandbox to
// bind, and issuance is unchanged.
func TestAttest_NoTokenBindsNothing(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, stub.URL())
	binder := &recordingBinder{}
	h.SandboxBindings = binder
	// No token, so the CSR names the leaf itself.
	csrPEM, _ := generateCSR(t)

	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	if len(binder.calls) != 0 {
		t.Fatalf("Record called %d times for a token-less request, want 0", len(binder.calls))
	}
}

// A request that fails a later gate must not leave a binding behind: otherwise
// a requester that never obtains a certificate could still claim a sandbox ID.
func TestAttest_FailedIssuanceBindsNothing(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	binder := &recordingBinder{}
	h.SandboxBindings = binder
	// Pin a measurement the stub does not report, so the request fails after
	// the sandbox token has been verified.
	h.Measurements = map[string]bool{"00": true}
	csrPEM := sandboxCSR(t)

	challenge := issueChallenge(t, h)
	if w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID)); w.Code == http.StatusOK {
		t.Fatal("expected the measurement gate to refuse issuance")
	}
	if len(binder.calls) != 0 {
		t.Fatalf("Record called %d times for a failed issuance, want 0", len(binder.calls))
	}
}
