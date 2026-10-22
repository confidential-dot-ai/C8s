package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The Genoa fixture's HOST_DATA is 32 zero bytes.
var (
	genoaInitDataPin = strings.Repeat("00", 32)
	wrongInitDataPin = strings.Repeat("ab", 32)
)

// finalOutcome runs verifyEvidence's post-verification sequence: newOutcome,
// the verdict policies, then applyInitDataNote on the final verdict.
func finalOutcome(cfg config, ev *evidence, result *teetypes.VerificationResult, plan *verifyPlan) Outcome {
	oc := newOutcome(cfg, ev, result, nil, plan)
	applyVerdictPolicies(&oc, cfg, ev, nil, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	applyInitDataNote(&oc, result, plan)
	return oc
}

// --init-data parses into the plan exactly once, as 32 bytes; anything else
// is a usage error naming the flag.
func TestBuildPolicy_InitDataFlag(t *testing.T) {
	t.Run("valid digest", func(t *testing.T) {
		plan := mustPlan(t, config{initDataHex: genoaInitDataPin})
		if len(plan.initDataHash) != 32 {
			t.Fatalf("initDataHash = %d bytes, want 32", len(plan.initDataHash))
		}
	})
	t.Run("unset means unpinned", func(t *testing.T) {
		if plan := mustPlan(t, config{}); plan.initDataHash != nil {
			t.Fatalf("initDataHash = %x, want nil", plan.initDataHash)
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		if _, err := buildPolicy(config{initDataHex: strings.Repeat("00", 31)}); err == nil || !strings.Contains(err.Error(), "--init-data") {
			t.Fatalf("err = %v, want a --init-data length error", err)
		}
	})
	t.Run("not hex", func(t *testing.T) {
		if _, err := buildPolicy(config{initDataHex: "zz" + strings.Repeat("00", 31)}); err == nil || !strings.Contains(err.Error(), "--init-data") {
			t.Fatalf("err = %v, want a --init-data hex error", err)
		}
	})
	t.Run("odd-length hex", func(t *testing.T) {
		if _, err := buildPolicy(config{initDataHex: strings.Repeat("0", 63)}); err == nil || !strings.Contains(err.Error(), "--init-data") {
			t.Fatalf("err = %v, want a --init-data error", err)
		}
	})
	t.Run("uppercase hex accepted", func(t *testing.T) {
		plan := mustPlan(t, config{initDataHex: strings.ToUpper(wrongInitDataPin)})
		if len(plan.initDataHash) != 32 {
			t.Fatalf("initDataHash = %d bytes, want 32 (uppercase hex must decode)", len(plan.initDataHash))
		}
	})
}

// The pin rides the plan into the engine: evidence committing the pinned
// digest verifies and the verdict says the digest was compared against
// --init-data, in text and in the JSON a machine gate reads.
func TestVerifyEvidence_InitDataPinMatch(t *testing.T) {
	cfg := config{initDataHex: genoaInitDataPin}
	plan := mustPlan(t, cfg)

	var out, errOut bytes.Buffer
	code := verifyEvidence(context.Background(), cfg, plan, genoaFileEvidence(t), nil, operatorKeysReport{}, measurementsReport{}, &out, &errOut)
	if code != exitVerified {
		t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitVerified, out.String(), errOut.String())
	}
	text := out.String()
	for _, want := range []string{"✓ VERIFIED", "init-data:    " + genoaInitDataPin, "verified: matches --init-data"} {
		if !strings.Contains(text, want) {
			t.Errorf("verdict missing %q:\n%s", want, text)
		}
	}

	jsonCfg := config{initDataHex: genoaInitDataPin, output: "json"}
	var jout, jerr bytes.Buffer
	if code := verifyEvidence(context.Background(), jsonCfg, mustPlan(t, jsonCfg), genoaFileEvidence(t), nil, operatorKeysReport{}, measurementsReport{}, &jout, &jerr); code != exitVerified {
		t.Fatalf("json exit = %d, want %d; output:\n%s%s", code, exitVerified, jout.String(), jerr.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(jout.Bytes(), &parsed); err != nil {
		t.Fatalf("json render: %v", err)
	}
	if parsed["init_data"] != genoaInitDataPin {
		t.Errorf("init_data = %v, want the pinned digest", parsed["init_data"])
	}
	if note, _ := parsed["init_data_note"].(string); !strings.Contains(note, "matches --init-data") {
		t.Errorf("init_data_note = %v, want the matched note", parsed["init_data_note"])
	}
}

// A "verified"-worded note must never ride a failed verdict, whichever check
// fails: --measurements fails inside newOutcome; --mesh-ca and --operator-keys
// fail in applyVerdictPolicies, past newOutcome. On every path
// both renderers must agree — the JSON must not carry an init-data field the
// text hides. Regression for the JSON honesty leak (#76).
func TestVerifyEvidence_InitDataNoteAbsentOnFailedVerdict(t *testing.T) {
	// --operator-keys resolves a pinned digest, so the served set (never
	// fetched for a --from-file target) can be compared: it fails in
	// applySandboxPolicy, past newOutcome.
	pubPEM, _ := operatorPubPEM(t)
	keysPath := filepath.Join(t.TempDir(), "op.pub")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cfg  config
		ev   func(*testing.T) *evidence
	}{
		{
			name: "measurements (in newOutcome)",
			cfg:  config{initDataHex: genoaInitDataPin, measurements: []string{strings.Repeat("11", 48)}},
			ev:   genoaFileEvidence,
		},
		{
			name: "mesh-ca leaf-less (applyVerdictPolicies)",
			cfg:  config{initDataHex: genoaInitDataPin, meshCA: writeMeshCAPEM(t, mintEndpointIdentity(t).ca)},
			ev:   genoaFileEvidence,
		},
		{
			name: "operator-keys uncheckable (applyVerdictPolicies)",
			cfg:  config{initDataHex: genoaInitDataPin, operatorKeys: keysPath},
			ev:   genoaFileEvidence,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// operatorKeysReport{note:...} stands in for a --from-file target
			// where the served set was never fetched.
			opKeys := operatorKeysReport{}
			if tc.cfg.operatorKeys != "" {
				opKeys.note = "kind is not cds"
			}

			jsonCfg := tc.cfg
			jsonCfg.output = "json"
			var jout, jerr bytes.Buffer
			if code := verifyEvidence(context.Background(), jsonCfg, mustPlan(t, jsonCfg), tc.ev(t), nil, opKeys, measurementsReport{}, &jout, &jerr); code != exitFailed {
				t.Fatalf("json exit = %d, want %d; output:\n%s%s", code, exitFailed, jout.String(), jerr.String())
			}
			var parsed map[string]any
			if err := json.Unmarshal(jout.Bytes(), &parsed); err != nil {
				t.Fatalf("json render: %v", err)
			}
			if parsed["verified"] != false {
				t.Errorf("verified = %v, want false", parsed["verified"])
			}
			if v, ok := parsed["init_data"]; ok {
				t.Errorf("a failed verdict must not carry init_data: %v", v)
			}
			if v, ok := parsed["init_data_note"]; ok {
				t.Errorf("a failed verdict must not carry a verified-sounding init_data_note: %v", v)
			}

			textCfg := tc.cfg
			textCfg.output = "text"
			var tout, terr bytes.Buffer
			verifyEvidence(context.Background(), textCfg, mustPlan(t, textCfg), tc.ev(t), nil, opKeys, measurementsReport{}, &tout, &terr)
			if text := tout.String(); strings.Contains(text, "init-data:") || strings.Contains(text, "matches --init-data") {
				t.Errorf("a failed verdict must render no init-data line:\n%s", text)
			}
		})
	}
}

// A PARTIAL verdict is not a failure: the init-data pin was verified, and the
// verdict is partial for an unrelated property (here an unattested front
// door). The note is honest, so it rides — in text and JSON alike, the same
// surfaces that must agree to hide it on a hard failure.
func TestVerifyEvidence_InitDataNoteRidesPartialVerdict(t *testing.T) {
	makeEv := func(t *testing.T) *evidence {
		ev := genoaFileEvidence(t)
		ev.frontDoor = frontDoorOther
		return ev
	}

	jsonCfg := config{initDataHex: genoaInitDataPin, output: "json"}
	var jout, jerr bytes.Buffer
	if code := verifyEvidence(context.Background(), jsonCfg, mustPlan(t, jsonCfg), makeEv(t), nil, operatorKeysReport{}, measurementsReport{}, &jout, &jerr); code != exitPartial {
		t.Fatalf("json exit = %d, want %d; output:\n%s%s", code, exitPartial, jout.String(), jerr.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(jout.Bytes(), &parsed); err != nil {
		t.Fatalf("json render: %v", err)
	}
	if parsed["partial"] != true {
		t.Errorf("partial = %v, want true", parsed["partial"])
	}
	if parsed["init_data"] != genoaInitDataPin {
		t.Errorf("init_data = %v, want the pinned digest on a partial verdict", parsed["init_data"])
	}
	if note, _ := parsed["init_data_note"].(string); !strings.Contains(note, "matches --init-data") {
		t.Errorf("init_data_note = %v, want the matched note", parsed["init_data_note"])
	}

	textCfg := config{initDataHex: genoaInitDataPin, output: "text"}
	var tout, terr bytes.Buffer
	verifyEvidence(context.Background(), textCfg, mustPlan(t, textCfg), makeEv(t), nil, operatorKeysReport{}, measurementsReport{}, &tout, &terr)
	text := tout.String()
	for _, want := range []string{"~ PARTIALLY VERIFIED", "init-data:    " + genoaInitDataPin, "matches --init-data"} {
		if !strings.Contains(text, want) {
			t.Errorf("partial verdict missing %q:\n%s", want, text)
		}
	}
}

// The issue's negative test: a guest whose init-data does not match the pin
// is refused by the relying party — a failed verdict (exit 2), not a partial
// one, and the refusal names the field that failed.
func TestVerifyEvidence_InitDataPinMismatchIsRefused(t *testing.T) {
	cfg := config{initDataHex: wrongInitDataPin}
	plan := mustPlan(t, cfg)

	var out, errOut bytes.Buffer
	code := verifyEvidence(context.Background(), cfg, plan, genoaFileEvidence(t), nil, operatorKeysReport{}, measurementsReport{}, &out, &errOut)
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitFailed, out.String(), errOut.String())
	}
	text := out.String()
	if !strings.Contains(text, "✗ NOT VERIFIED") || !strings.Contains(text, "HOST_DATA") {
		t.Errorf("mismatch must render a failed verdict naming HOST_DATA:\n%s", text)
	}
	if strings.Contains(text, "✓ VERIFIED") || strings.Contains(text, "PARTIALLY") {
		t.Errorf("a refused pin must never read as any kind of verified:\n%s", text)
	}
}

// Honesty for the unpinned case: the committed digest is reported — it is
// verified evidence — but the verdict must say it was compared against
// nothing, in text and JSON alike.
func TestVerifyEvidence_InitDataUnpinnedIsLabelled(t *testing.T) {
	cfg := config{output: "json"}
	plan := mustPlan(t, config{})

	var out, errOut bytes.Buffer
	code := verifyEvidence(context.Background(), cfg, plan, genoaFileEvidence(t), nil, operatorKeysReport{}, measurementsReport{}, &out, &errOut)
	if code != exitVerified {
		t.Fatalf("exit = %d, want %d; output:\n%s", code, exitVerified, out.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("json render: %v", err)
	}
	if parsed["verified"] != true {
		t.Errorf("verified = %v, want true", parsed["verified"])
	}
	if parsed["init_data"] != genoaInitDataPin {
		t.Errorf("init_data = %v, want the fixture's HOST_DATA", parsed["init_data"])
	}
	note, _ := parsed["init_data_note"].(string)
	if !strings.Contains(note, "not pinned") {
		t.Errorf("init_data_note = %q, want it to say the digest is unpinned", note)
	}
	if strings.Contains(note, "verified") {
		t.Errorf("an unpinned digest must not carry the word verified: %q", note)
	}
}

// applyInitDataNote is the single source of truth for the init-data fields: a
// plan carrying --init-data takes the pinned note, an unpinned plan the
// unpinned one, and a hard failure (oc.Error set) carries neither — the gate
// that keeps JSON and text from disagreeing. On az-* the claim is the inner
// report's HOST_DATA, not the field the pin binds (PCR[8]), so it is not
// rendered as init-data even when pinned.
func TestApplyInitDataNote(t *testing.T) {
	result := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: "ab" + strings.Repeat("00", 47), InitData: make([]byte, 32)},
	}
	ev := &evidence{platform: "snp", source: "test"}

	pinned := finalOutcome(config{}, ev, result, &verifyPlan{policy: &armtls.VerifyPolicy{}, initDataHash: make([]byte, 32)})
	if !strings.Contains(pinned.InitDataNote, "matches --init-data") {
		t.Errorf("pinned note = %q", pinned.InitDataNote)
	}
	unpinned := finalOutcome(config{}, ev, result, &verifyPlan{policy: &armtls.VerifyPolicy{}})
	if !strings.Contains(unpinned.InitDataNote, "not pinned") {
		t.Errorf("unpinned note = %q", unpinned.InitDataNote)
	}

	// A hard failure past newOutcome (here a pre-set oc.Error) carries no note,
	// even with a matching pin — the leak the gate closes.
	failed := Outcome{Platform: "snp", Error: "a later policy failed"}
	applyInitDataNote(&failed, result, &verifyPlan{policy: &armtls.VerifyPolicy{}, initDataHash: make([]byte, 32)})
	if failed.InitData != "" || failed.InitDataNote != "" {
		t.Errorf("a failed verdict must carry no init-data fields, got %q / %q", failed.InitData, failed.InitDataNote)
	}

	azResult := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformAzSNP,
		Claims:         teetypes.Claims{LaunchDigest: "ab" + strings.Repeat("00", 47), InitData: make([]byte, 32)},
	}
	azEv := &evidence{platform: "az-snp", source: "test"}
	azPinned := finalOutcome(config{}, azEv, azResult, &verifyPlan{policy: &armtls.VerifyPolicy{}, initDataHash: make([]byte, 32)})
	if azPinned.InitData != "" {
		t.Errorf("az verdict must not render the inner HOST_DATA as init-data, got %q", azPinned.InitData)
	}
	if !strings.Contains(azPinned.InitDataNote, "PCR[8]") {
		t.Errorf("a pinned az verdict must report the enforced PCR[8] pin, got %q", azPinned.InitDataNote)
	}
	var azOut bytes.Buffer
	renderText(config{}, azPinned, &azOut)
	if rendered := azOut.String(); !strings.Contains(rendered, "init-data:") || !strings.Contains(rendered, "PCR[8]") ||
		strings.Contains(rendered, "init-data:    "+strings.Repeat("00", 32)) {
		t.Errorf("az render must show the PCR[8] pin, never the inner HOST_DATA:\n%s", rendered)
	}

	// The az note leaks identically on a failed verdict without the gate.
	azFailed := Outcome{Platform: "az-snp", Error: "a later policy failed"}
	applyInitDataNote(&azFailed, azResult, &verifyPlan{policy: &armtls.VerifyPolicy{}, initDataHash: make([]byte, 32)})
	if azFailed.InitDataNote != "" {
		t.Errorf("a failed az verdict must carry no init-data note, got %q", azFailed.InitDataNote)
	}

	azUnpinned := finalOutcome(config{}, azEv, azResult, &verifyPlan{policy: &armtls.VerifyPolicy{}})
	if azUnpinned.InitData != "" || azUnpinned.InitDataNote != "" {
		t.Errorf("an unpinned az verdict renders no init-data line, got %q / %q", azUnpinned.InitData, azUnpinned.InitDataNote)
	}
}
