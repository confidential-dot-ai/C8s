package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorKeypair writes an ECDSA operator keypair to disk and returns the
// public-key path, the private-key paths (SEC1 and PKCS#8), and the exact
// public-key file bytes. Exact matters: the initrd hashes the pubkey file
// verbatim, so those bytes — not a re-encoding of the key they carry — are the
// input to the seed.
func operatorKeypair(t *testing.T) (pubPath string, keyPaths []string, pubPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath = filepath.Join(dir, "operator.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"operator.sec1.key": {Type: "EC PRIVATE KEY", Bytes: sec1},
		"operator.p8.key":   {Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		keyPaths = append(keyPaths, p)
	}
	return pubPath, keyPaths, pubPEM
}

// operatorSeed recomputes the register an initrd leaves behind —
// SHA-384(0x00*48 ‖ SHA-384(pubkey)) — straight from the convention documented
// in the runtimemeasure package, deliberately WITHOUT calling the helper the code under
// test calls. Comparing that helper against itself would pin nothing; this is
// the arithmetic an operator would otherwise have to do by hand, which is the
// chore --operator-pkey exists to remove.
func operatorSeed(pubPEM []byte) []byte {
	inner := sha512.Sum384(pubPEM)
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(inner[:])
	return h.Sum(nil)
}

// --operator-pkey derives the RTMR[3] pin the operator would otherwise compute
// by hand, and lands it in the same slot --expected-rtmr3 fills, so the whole
// enforcement path downstream is unchanged.
func TestOperatorPkeyDerivesTheRTMR3Pin(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	want := operatorSeed(pubPEM)

	cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
	plan := mustPlan(t, cfg)
	if !bytes.Equal(plan.pins.rtmr3, want) {
		t.Fatalf("derived RTMR[3] = %x, want the bare operator-key seed %x", plan.pins.rtmr3, want)
	}

	// The hex an operator computes by hand and the key file must be two ways of
	// saying the same thing.
	byHand := mustPlan(t, config{imageManifest: writeTestManifest(t), expectedRTMR3Hex: hex.EncodeToString(want)})
	if !bytes.Equal(byHand.pins.rtmr3, plan.pins.rtmr3) {
		t.Errorf("--expected-rtmr3 %x and --operator-pkey %x must agree", byHand.pins.rtmr3, plan.pins.rtmr3)
	}

	// End to end: a node reporting the seed verifies and the verdict says which
	// register it enforced.
	seedHex := hex.EncodeToString(want)
	rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": seedHex}
	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
	if !oc.Verified {
		t.Fatalf("a node reporting the derived seed must verify: %s", oc.Error)
	}
	if len(oc.RTMRsPinned) != 3 || oc.RTMRsPinned[2] != "3:"+seedHex {
		t.Errorf("RTMRsPinned = %v, want RTMR[3] reported as %s", oc.RTMRsPinned, seedHex)
	}
}

// The derived pin inherits every rule --expected-rtmr3 already carries: it is
// the same slot, so a wrong or absent claim fails closed and a non-TDX platform
// is a policy error rather than an ignored flag.
func TestOperatorPkeyPinEnforcedLikeExpectedRTMR3(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
	plan := mustPlan(t, cfg)

	t.Run("a different key's register fails", func(t *testing.T) {
		otherPub, _, _ := operatorKeypair(t)
		other := mustPlan(t, config{imageManifest: writeTestManifest(t), operatorPubkey: otherPub})
		rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": hex.EncodeToString(other.pins.rtmr3)}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "RTMR[3]") {
			t.Errorf("a node launched to trust another key must fail: %+v", oc)
		}
	})

	t.Run("an absent claim fails closed", func(t *testing.T) {
		rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "carry no rtmr_3") {
			t.Errorf("an unreportable register must fail closed: %+v", oc)
		}
	})

	t.Run("SNP evidence is a policy error", func(t *testing.T) {
		snpLaunch := strings.Repeat("ab", 48)
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims:         teetypes.Claims{LaunchDigest: snpLaunch},
		}
		oc := newOutcome(cfg, &evidence{platform: "snp"}, result, nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "--operator-pkey") {
			t.Errorf("SNP has no runtime measurement registers; the pin must be a named policy error: %+v", oc)
		}
	})

	// Unrelated to the seed but worth stating once: the derivation hashes the
	// pubkey file verbatim, so a byte the operator "cleaned up" is a different
	// key as far as the register is concerned.
	t.Run("the file bytes are hashed verbatim", func(t *testing.T) {
		trimmed := filepath.Join(t.TempDir(), "operator.pub")
		if err := os.WriteFile(trimmed, bytes.TrimRight(pubPEM, "\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		other := mustPlan(t, config{imageManifest: writeTestManifest(t), operatorPubkey: trimmed})
		if bytes.Equal(other.pins.rtmr3, plan.pins.rtmr3) {
			t.Error("a stripped trailing newline must change the seed — the initrd hashed the file, armor and all")
		}
	})
}

func TestOperatorPkeyFlagErrors(t *testing.T) {
	pubPath, keyPaths, pubPEM := operatorKeypair(t)
	manifest := writeTestManifest(t)
	dir := t.TempDir()

	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notPEM := write("garbage.pub", []byte("ssh-ed25519 AAAA... operator@laptop\n"))
	certPEM := write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}}))
	badDER := write("bad.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not DER")}))

	cases := []struct {
		name string
		cfg  config
		want []string
	}{
		// Both flags write one RTMR[3] slot; two different expected values mean
		// the operator gets a verdict on neither.
		{"mutually exclusive with --expected-rtmr3",
			config{imageManifest: manifest, operatorPubkey: pubPath, expectedRTMR3Hex: testRTMR3},
			[]string{"--expected-rtmr3", "--operator-pkey", "name the register once"}},
		// Same rule as --expected-rtmr3, from one check: the host stages the
		// operator key, so it can reproduce this register under any image.
		{"requires --image-manifest",
			config{operatorPubkey: pubPath},
			[]string{"--operator-pkey requires --image-manifest"}},
		{"missing file",
			config{imageManifest: manifest, operatorPubkey: filepath.Join(dir, "absent.pub")},
			[]string{"read --operator-pkey"}},
		{"not PEM at all",
			config{imageManifest: manifest, operatorPubkey: notPEM},
			[]string{"--operator-pkey", "not PEM"}},
		{"a PEM that is not a key",
			config{imageManifest: manifest, operatorPubkey: certPEM},
			[]string{"CERTIFICATE", `want "PUBLIC KEY"`}},
		{"a PUBLIC KEY block with unparseable DER",
			config{imageManifest: manifest, operatorPubkey: badDER},
			[]string{"not a parseable PKIX public key"}},
	}
	// The private half by mistake: everything hashes to something, so without a
	// check this would be a pin no node can match, reported as an RTMR[3]
	// mismatch that reads like a compromised node.
	for _, keyPath := range keyPaths {
		cases = append(cases, struct {
			name string
			cfg  config
			want []string
		}{
			"private key passed by mistake (" + filepath.Base(keyPath) + ")",
			config{imageManifest: manifest, operatorPubkey: keyPath},
			[]string{"PRIVATE KEY", "PUBLIC key", "openssl ec -pubout"},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPolicy(tc.cfg)
			if err == nil {
				t.Fatal("want a usage error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			var out, errOut strings.Builder
			if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage {
				t.Errorf("run code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
			}
		})
	}

	// The pin itself is fine — only the combinations above are refused.
	if plan := mustPlan(t, config{imageManifest: manifest, operatorPubkey: pubPath}); !bytes.Equal(plan.pins.rtmr3, operatorSeed(pubPEM)) {
		t.Error("the valid case must still resolve the derived pin")
	}
}

// With --operator-pkey, RTMR[3] may be the seed followed by a prefix of the
// policies the node reports it measured; that prefix is the node's history.
func TestOperatorPkeyReplaysMeasuredPolicies(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	plan := mustPlan(t, config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath})
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pubPEM), []string{p})
	claims := matchingRTMRs()
	claims["rtmr_3"] = hex.EncodeToString(reg[:])
	for _, tc := range []struct {
		name     string
		measured []string
		history  []string
		ok       bool
	}{
		{"list ahead of the quote", []string{p, q}, []string{p}, true},
		{"list that does not replay", []string{q}, nil, false},
		{"no list", nil, nil, false},
	} {
		pins := plan.pins
		pins.measured = tc.measured
		var oc Outcome
		if ok := applyRTMRPins(&oc, pins, tdxResult(testMRTD, claims)); ok != tc.ok || !slices.Equal(oc.MeasuredPolicies, tc.history) {
			t.Errorf("%s: applyRTMRPins = %v (history %v, error %q), want %v with history %v", tc.name, ok, oc.MeasuredPolicies, oc.Error, tc.ok, tc.history)
		}
	}

	state := &types.RolloutState{Bound: []string{p}, Lease: 30}
	oc := Outcome{Verified: true, MeasuredPolicies: []string{q, p}}
	applyPinPolicy(&oc, config{pinPolicies: []string{p}}, &evidence{fresh: true, rollout: state})
	if oc.Verified || !strings.Contains(oc.Error, "policy_history_not_pinned") {
		t.Fatalf("history outside the pins: verified=%v error=%q, want policy_history_not_pinned", oc.Verified, oc.Error)
	}
}
