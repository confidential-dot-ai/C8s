package workloadclaims

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// fakeWarmer fails the first failures calls, then succeeds, counting every call.
type fakeWarmer struct {
	failures int
	calls    int
	err      error
}

func (f *fakeWarmer) WarmUp(context.Context) error {
	f.calls++
	if f.calls <= f.failures {
		return f.err
	}
	return nil
}

func TestWarmUpCertRetriesPastATransientFailure(t *testing.T) {
	// The real trigger: the attestation-api socket does not exist yet, which
	// fails instantly, so the old single attempt aborted CDS startup.
	w := &fakeWarmer{failures: 3, err: fs.ErrNotExist}
	ctx, cancel := context.WithTimeout(context.Background(), 10*warmUpInterval)
	defer cancel()

	if err := warmUpCert(ctx, w); err != nil {
		t.Fatalf("want success once the socket appears, got %v", err)
	}
	if w.calls != 4 {
		t.Fatalf("want 4 calls (3 failures then success), got %d", w.calls)
	}
}

func TestWarmUpCertSucceedsWithoutRetryingWhenTheSocketIsReady(t *testing.T) {
	w := &fakeWarmer{}
	if err := warmUpCert(context.Background(), w); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.calls != 1 {
		t.Fatalf("a ready peer must cost exactly one call, got %d", w.calls)
	}
}

func TestWarmUpCertGivesUpWhenTheBudgetIsSpent(t *testing.T) {
	// Never succeeds: the call must return rather than block forever, and must
	// surface the provisioning failure, not a bare context error.
	sentinel := fs.ErrNotExist
	w := &fakeWarmer{failures: 1 << 30, err: sentinel}
	ctx, cancel := context.WithTimeout(context.Background(), 3*warmUpInterval)
	defer cancel()

	start := time.Now()
	err := warmUpCert(ctx, w)
	if err == nil {
		t.Fatal("want failure once the budget is spent")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the provisioning failure surfaced, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 30*warmUpInterval {
		t.Fatalf("gave up far too late: %v", elapsed)
	}
	if w.calls < 2 {
		t.Fatalf("want more than one attempt inside the budget, got %d", w.calls)
	}
}

// A live peer that answers and refuses must fail closed immediately, not after
// the budget: this is the invariant TestRun_ARMTLSWarmupFailureFailsClosed
// encodes, and the reason the retry cannot be unconditional.
func TestWarmUpCertDoesNotRetryARefusingPeer(t *testing.T) {
	w := &fakeWarmer{failures: 1 << 30, err: errors.New("API error (500): no evidence for you")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*warmUpInterval)
	defer cancel()

	start := time.Now()
	if err := warmUpCert(ctx, w); err == nil {
		t.Fatal("want failure")
	}
	if w.calls != 1 {
		t.Fatalf("a refusing peer must cost exactly one attempt, got %d", w.calls)
	}
	if elapsed := time.Since(start); elapsed >= warmUpInterval {
		t.Fatalf("returned after %v, want immediately", elapsed)
	}
}

// The retry predicate reads an error produced by the real code path, not one
// hand-built here: if any wrapper between the lstat and warmUpCert stops using
// %w, this fails rather than the retry silently never firing again.
func TestPeerNotUpYetMatchesARealMissingSocketError(t *testing.T) {
	missing := "unix://" + t.TempDir() + "/attestation-api.sock"

	_, err := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), missing)(
		context.Background(), hexReportData())
	if err == nil {
		t.Fatal("want an error for a socket that does not exist")
	}
	if !peerNotUpYet(err) {
		t.Fatalf("peerNotUpYet must recognise a missing verifier socket; chain was: %v", err)
	}
}

// MakeSNPARMTLSAttestFunc hex-decodes customData and slices 48 bytes off it.
func hexReportData() string {
	const b = "ab"
	out := ""
	for range 48 {
		out += b
	}
	return out
}
