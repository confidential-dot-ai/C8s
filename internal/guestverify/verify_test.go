package guestverify

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestVerifyEvidenceErrors(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))

	t.Run("bad envelope JSON", func(t *testing.T) {
		_, err := verifyEvidence([]byte("not json"), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "parse evidence envelope") {
			t.Fatalf("want parse error, got %v", err)
		}
	})

	t.Run("empty evidence object", func(t *testing.T) {
		_, err := verifyEvidence([]byte(`{"platform":"tdx"}`), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "no evidence object") {
			t.Fatalf("want empty-evidence error, got %v", err)
		}
	})

	// The envelope shape is single-wrap on both gates; a double-wrapped
	// envelope must fail loudly rather than reach the verifier as evidence it
	// misparses or ignores.
	t.Run("double-wrapped envelope", func(t *testing.T) {
		stubVerify(t, verifiedResultFor(exp), nil) // must not be reached
		double := `{"platform":"tdx","evidence":` + tdxEnvelope + `}`
		_, err := verifyEvidence([]byte(double), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "double-wrapped") {
			t.Fatalf("want double-wrap rejection, got %v", err)
		}
	})

	t.Run("verifier error", func(t *testing.T) {
		stubVerify(t, nil, fmt.Errorf("boom"))
		_, err := verifyEvidence([]byte(tdxEnvelope), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "verify evidence: boom") {
			t.Fatalf("want wrapped verifier error, got %v", err)
		}
	})

	t.Run("signature invalid", func(t *testing.T) {
		res := verifiedResultFor(exp)
		res.SignatureValid = false
		stubVerify(t, res, nil)
		_, err := verifyEvidence([]byte(tdxEnvelope), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "quote signature invalid") {
			t.Fatalf("want signature error, got %v", err)
		}
	})
}

func TestCheckMeasuredIdentityNoRTMR3Claim(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	res := verifiedResultFor(exp)
	res.Claims.PlatformData["rtmr_3"] = ""
	err := exp.checkIdentity(res)
	if err == nil || !strings.Contains(err.Error(), "no rtmr_3") {
		t.Fatalf("want no-rtmr_3 error, got %v", err)
	}
}

// --workload-image extends the expected RTMR[3] from the operator-key seed in
// the given (first-extend) order; tags never pass, and order changes the
// register.
func TestPolicyForWorkloadImages(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	digA := "sha256:" + strings.Repeat("aa", 32)
	digB := "ghcr.io/acme/api@sha256:" + strings.Repeat("bb", 32)

	bare, err := PolicyFor(manifest, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := bare.workloadDigests; len(got) != 0 {
		t.Errorf("workloadDigests = %v, want none so the expected register is the bare operator-key seed", got)
	}

	chained, err := PolicyFor(manifest, pub, []string{digA, digB})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{digA, "sha256:" + strings.Repeat("bb", 32)}
	if got := chained.workloadDigests; !slices.Equal(got, want) {
		t.Errorf("workloadDigests = %v, want %v (canonicalized, in first-extend order)", got, want)
	}

	reversed, err := PolicyFor(manifest, pub, []string{digB, digA})
	if err != nil {
		t.Fatal(err)
	}
	if got := reversed.workloadDigests; slices.Equal(got, want) {
		t.Error("extend order must reach the chain unchanged — the register is ordered")
	}

	for _, bad := range []string{"nginx:latest", "ghcr.io/acme/api:v1", "sha256:" + strings.Repeat("AB", 32)} {
		if _, err := PolicyFor(manifest, pub, []string{bad}); err == nil {
			t.Errorf("PolicyFor accepted non-canonical workload image %q", bad)
		}
	}
}

// The node's measurer extends each image once, so repeating one here would
// extend the EXPECTED register an extra time and build a gate no node can ever
// satisfy — a permanently red, silently wrong policy. It has to be a usage
// error, including when the two spellings differ but the digest does not.
func TestPolicyForRejectsDuplicateWorkloadImages(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	dig := "sha256:" + strings.Repeat("aa", 32)

	for _, tc := range []struct {
		name string
		refs []string
	}{
		{"identical refs", []string{dig, dig}},
		{"same digest, different spelling", []string{dig, "ghcr.io/acme/api@" + dig}},
		{"repeat separated by another image", []string{dig, "sha256:" + strings.Repeat("bb", 32), dig}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PolicyFor(manifest, pub, tc.refs); err == nil {
				t.Fatal("a repeated workload image must be rejected, not silently doubled into the chain")
			}
		})
	}

	// Sanity: the single-occurrence policy this rejection protects is exactly
	// the one a node with that image can satisfy.
	single, err := PolicyFor(manifest, pub, []string{dig})
	if err != nil {
		t.Fatal(err)
	}
	if got := single.workloadDigests; !slices.Equal(got, []string{dig}) {
		t.Errorf("workloadDigests = %v, want [%s]", got, dig)
	}
}

// A node that measured allowlist policies after its workloads binds the
// operator key once a prefix of its reported list replays the quote's
// register; a node that measured none keeps today's check.
func TestCheckIdentityReplaysMeasuredPolicies(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	exp.workloadDigests = []string{"sha256:" + strings.Repeat("a", 64)}
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	quote := func(policies ...string) *policyList {
		return &policyList{list: policies}
	}
	overCap := []string{p}
	for len(overCap) <= armtls.MaxRuntimeExtensions {
		overCap = append(overCap, q)
	}
	for _, tc := range []struct {
		name        string
		noWorkloads bool     // the quote lacks the workload chain
		measured    []string // extended after the workloads in the quote
		policies    *policyList
		wantErr     bool
	}{
		{name: "no policies measured, no list", wantErr: false},
		{name: "no policies measured, list ahead", policies: quote(p)},
		{name: "list matches", measured: []string{p, q}, policies: quote(p, q)},
		{name: "list ahead of the quote", measured: []string{p}, policies: quote(p, q)},
		{name: "list does not replay", measured: []string{p}, policies: quote(q), wantErr: true},
		{name: "measured without a list", measured: []string{p}, wantErr: true},
		{name: "measured, empty list", measured: []string{p}, policies: quote(), wantErr: true},
		{name: "replaying list over the cap", measured: []string{p}, policies: quote(overCap...), wantErr: true},
		{name: "non-canonical entry", measured: []string{p}, policies: quote(strings.ToUpper(p)), wantErr: true},
		{name: "invalid entry past the replaying prefix", measured: []string{p}, policies: quote(p, "not-a-digest"), wantErr: true},
		{name: "workload chain missing", noWorkloads: true, measured: []string{p}, policies: quote(p), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := verifiedResultFor(exp)
			extended := tc.measured
			if !tc.noWorkloads {
				extended = append(slices.Clone(exp.workloadDigests), tc.measured...)
			}
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), extended)
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			e := exp
			e.policies = tc.policies
			err := e.checkIdentity(res)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkIdentity = %v, want error %v", err, tc.wantErr)
			}
			// Only Run knows where the list came from, so the error gives no advice.
			if err != nil && strings.Contains(err.Error(), "--attest-url") {
				t.Errorf("checkIdentity = %v, want no advice about --attest-url", err)
			}
		})
	}
}

// TestPolicyForSeedMatchesGuestConvention checks the gate accepts the same
// bare-seed value the guest measures at launch:
// RTMR[3] = SHA384(0x00*48 || SHA384(pubkey)), derived here by hand rather
// than through the library the gate itself uses.
func TestPolicyForSeedMatchesGuestConvention(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMFk...\n-----END PUBLIC KEY-----\n")
	exp, err := PolicyFor(writeTestManifest(t, tdxManifest()), pub, nil)
	if err != nil {
		t.Fatal(err)
	}

	keyDigest := sha512.Sum384(pub)
	want := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	res := verifiedResultFor(exp)
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(want[:])
	if err := exp.checkIdentity(res); err != nil {
		t.Errorf("a node reporting the hand-derived seed RTMR[3] %x was refused: %v", want, err)
	}
}
