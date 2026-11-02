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
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// operatorKeypair writes an ECDSA operator keypair to disk and returns the
// public-key path, the private-key paths (SEC1 and PKCS#8), and the exact
// public-key file bytes. Exact matters: the launcher hashes the pubkey file
// verbatim, so those bytes — not a re-encoding of the key they carry — are the
// input to the launch binding.
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

// operatorBinding recomputes the MRCONFIGID a launcher sets, SHA-384(pubkey),
// deliberately WITHOUT calling the helper the code under test calls: comparing
// that helper against itself would pin nothing.
func operatorBinding(pubPEM []byte) []byte {
	d := sha512.Sum384(pubPEM)
	return d[:]
}

// operatorResult is the test image's result for a guest launched with binding
// in MRCONFIGID and rtmr3 in RTMR[3].
func operatorResult(binding []byte, rtmr3 string) *teetypes.VerificationResult {
	r := tdxResult(testMRTD, map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": rtmr3})
	r.Claims.InitData = binding
	return r
}

var zeroRTMR = strings.Repeat("00", 48)

// --operator-pkey pins the launch binding: MRCONFIGID must commit the key file
// and RTMR[3], the runtime log, must be zero.
func TestOperatorPkeyPinsTheLaunchBinding(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
	plan := mustPlan(t, cfg)
	if !bytes.Equal(plan.pins.anchor, pubPEM) || plan.pins.rtmr3 != nil {
		t.Fatalf("pins = anchor %q, rtmr3 %x; want the key file as the anchor and no RTMR[3] pin", plan.pins.anchor, plan.pins.rtmr3)
	}

	oc := newOutcome(cfg, &evidence{platform: "tdx"}, operatorResult(operatorBinding(pubPEM), zeroRTMR), nil, plan)
	if !oc.Verified {
		t.Fatalf("a node launched for the key must verify: %s", oc.Error)
	}
	if _, pinned := pinnedRegister(oc, 3); pinned {
		t.Errorf("RTMRsPinned = %v, want no RTMR[3] pin: --operator-pkey replays the runtime log", oc.RTMRsPinned)
	}
	if note := initDataNote(plan); note != "verified: matches --operator-pkey" {
		t.Errorf("init-data note = %q, want the --operator-pkey binding", note)
	}
}

// A by-hand RTMR[3] pin is the runtime log, never the operator-key binding:
// it neither verifies MRCONFIGID nor replays a policy history.
func TestManualRTMR3PinIsNotTheOperatorKey(t *testing.T) {
	cfg := config{imageManifest: writeTestManifest(t), rtmrs: []string{"3=" + testRTMR3}}
	plan := mustPlan(t, cfg)
	if plan.pins.anchor != nil {
		t.Fatal("a by-hand RTMR[3] pin must not bind an operator key")
	}
	ev := &evidence{platform: "tdx", measured: []string{testPolicyP}}
	oc := newOutcome(cfg, ev, operatorResult(make([]byte, 48), testRTMR3), nil, plan)
	if len(oc.MeasuredPolicies) != 0 || initDataNote(plan) != "not pinned: the digest the evidence commits, compared against nothing (pass --init-data to pin it)" {
		t.Errorf("verdict = history %v, init-data note %q; want no history and an unpinned MRCONFIGID", oc.MeasuredPolicies, initDataNote(plan))
	}
	oc = newOutcome(cfg, ev, operatorResult(make([]byte, 48), zeroRTMR), nil, plan)
	if oc.Verified || !strings.Contains(oc.Error, "RTMR[3] (runtime log)") || strings.Contains(oc.Error, "operator") {
		t.Errorf("mismatch = %q; want it labelled the runtime log, not an operator key", oc.Error)
	}
}

// Every way the evidence can fail the launch binding fails closed, and a
// non-TDX platform is a policy error rather than an ignored flag.
func TestOperatorPkeyPinFailsClosed(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
	plan := mustPlan(t, cfg)
	_, _, otherPEM := operatorKeypair(t)
	extended := runtimemeasure.Extend(runtimemeasure.Zero, runtimemeasure.Event(testPolicyP))

	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
		want   string
	}{
		{"another key's binding", operatorResult(operatorBinding(otherPEM), zeroRTMR), "MRCONFIGID"},
		{"keyless launch", operatorResult(make([]byte, 48), zeroRTMR), "MRCONFIGID"},
		{"an unlisted runtime extension", operatorResult(operatorBinding(pubPEM), hex.EncodeToString(extended[:])), "runtime log differs"},
		{"an absent RTMR[3] claim", operatorResult(operatorBinding(pubPEM), ""), "carry no rtmr_3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := newOutcome(cfg, &evidence{platform: "tdx"}, tc.result, nil, plan)
			if oc.Verified || !strings.Contains(oc.Error, tc.want) {
				t.Errorf("verdict = verified %v, error %q; want a failure naming %q", oc.Verified, oc.Error, tc.want)
			}
		})
	}

	t.Run("a binding mismatch names no policy history", func(t *testing.T) {
		ev := &evidence{platform: "tdx", measured: []string{testPolicyP}}
		oc := newOutcome(cfg, ev, operatorResult(operatorBinding(otherPEM), zeroRTMR), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "MRCONFIGID") || strings.Contains(oc.Error, "no prefix of the") {
			t.Errorf("error = %q; want the MRCONFIGID mismatch alone", oc.Error)
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
			t.Errorf("the pin must be a named policy error on SNP: %+v", oc)
		}
	})

	// The launcher hashes the pubkey file verbatim, so a byte the operator
	// "cleaned up" is a different key as far as MRCONFIGID is concerned.
	t.Run("the file bytes are hashed verbatim", func(t *testing.T) {
		trimmed := filepath.Join(t.TempDir(), "operator.pub")
		if err := os.WriteFile(trimmed, bytes.TrimRight(pubPEM, "\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		trimmedCfg := config{imageManifest: writeTestManifest(t), operatorPubkey: trimmed}
		oc := newOutcome(trimmedCfg, &evidence{platform: "tdx"}, operatorResult(operatorBinding(pubPEM), zeroRTMR), nil, mustPlan(t, trimmedCfg))
		if oc.Verified {
			t.Error("a stripped trailing newline must change the binding — the launcher hashed the file, armor and all")
		}
	})
}

// --operator-pkey and an RTMR[3] pin check different things, the launch
// binding with its replayed log and the exact register, so both apply.
func TestOperatorPkeyWithRTMR3PinChecksBoth(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	_, _, otherPEM := operatorKeypair(t)
	reg := runtimemeasure.FromDigests([]string{testPolicyP})
	logged := hex.EncodeToString(reg[:])
	cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath, rtmrs: []string{"3=" + logged}}
	plan := mustPlan(t, cfg)
	ev := &evidence{platform: "tdx", measured: []string{testPolicyP}}

	oc := newOutcome(cfg, ev, operatorResult(operatorBinding(pubPEM), logged), nil, plan)
	if v, _ := pinnedRegister(oc, 3); !oc.Verified || v != logged || !slices.Equal(oc.MeasuredPolicies, ev.measured) {
		t.Fatalf("verdict = verified %v (%s), RTMR[3] pin %q, history %v; want both checks passed", oc.Verified, oc.Error, v, oc.MeasuredPolicies)
	}
	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
		want   string
	}{
		{"another key", operatorResult(operatorBinding(otherPEM), logged), "MRCONFIGID"},
		{"another runtime log", operatorResult(operatorBinding(pubPEM), zeroRTMR), "RTMR[3] (runtime log) is"},
	} {
		if oc := newOutcome(cfg, ev, tc.result, nil, plan); oc.Verified || !strings.Contains(oc.Error, tc.want) {
			t.Errorf("%s: verdict = verified %v, error %q; want a failure naming %q", tc.name, oc.Verified, oc.Error, tc.want)
		}
	}
}

// pinnedRegister returns the value RTMRsPinned records for register idx.
func pinnedRegister(oc Outcome, idx int) (string, bool) {
	for _, p := range oc.RTMRsPinned {
		if n, v, _ := strings.Cut(p, ":"); n == strconv.Itoa(idx) {
			return v, true
		}
	}
	return "", false
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
		// Same rule as --expected-rtmr3, from one check: the host stages the
		// operator key, so it can reproduce this binding under any image.
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
	// check this would be a pin no node can match, reported as an MRCONFIGID
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
	if plan := mustPlan(t, config{imageManifest: manifest, operatorPubkey: pubPath}); !bytes.Equal(plan.pins.anchor, pubPEM) {
		t.Error("the valid case must still resolve the pin")
	}
}
