package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func buildAttestLBJSON(t *testing.T, id *endpointIdentity, mode string, nonce, servingLeafDER []byte) []byte {
	t.Helper()
	transcript, err := overenc.LBTranscriptHash(types.FrontDoorMode(mode), nonce, servingLeafDER, id.leaf.Raw, id.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	servingHash := sha256.Sum256(servingLeafDER)
	body := map[string]any{
		"version":             types.BindingAttestLB,
		"platform":            "tdx",
		"nonce":               base64.RawURLEncoding.EncodeToString(nonce),
		"evidence":            map[string]any{"quote": "tdx-evidence"},
		"cds_cert_pem":        id.chainPEM,
		"front_door_mode":     mode,
		"identity_proof":      id.proofJSON(t, transcript),
		"serving_leaf_sha256": base64.RawURLEncoding.EncodeToString(servingHash[:]),
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEvidenceFromAttestLBBindsExactTranscript(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x8a}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw
	body := buildAttestLBJSON(t, mesh, "cds", nonce, serving)

	ev, err := evidenceFromAttestLBJSON(body, nonce, serving, "saved receipt")
	if err != nil {
		t.Fatal(err)
	}
	want, err := overenc.LBTranscriptHash("cds", nonce, serving, mesh.leaf.Raw, mesh.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.erd, want) {
		t.Fatalf("REPORTDATA transcript = %x, want %x", ev.erd, want)
	}
	wantHash := sha256.Sum256(serving)
	wantDigest := base64.RawURLEncoding.EncodeToString(wantHash[:])
	if ev.fresh || !ev.tlsBindingVerified || ev.servingLeafSHA256 != wantDigest {
		t.Fatalf("binding: fresh=%t verified=%t digest=%q", ev.fresh, ev.tlsBindingVerified, ev.servingLeafSHA256)
	}
	if !strings.HasPrefix(ev.bindingNote, "REPORTDATA binds the identity transcript:") {
		t.Fatalf("binding note is not public-verifier compatible: %q", ev.bindingNote)
	}

	result := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformTDX,
		Claims:         teetypes.Claims{LaunchDigest: strings.Repeat("ab", 48)},
	}
	outcome := newOutcome(config{}, ev, result, nil, &verifyPlan{policy: &ratls.VerifyPolicy{}})
	if !outcome.TLSBindingVerified || outcome.ServingLeafSHA256 != wantDigest || outcome.Fresh {
		t.Fatalf("JSON verdict fields were not preserved: %+v", outcome)
	}
}

func TestEvidenceFromAttestLBRejectsReplayAndSubstitution(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x8a}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw
	body := buildAttestLBJSON(t, mesh, "cds", nonce, serving)

	for _, tc := range []struct {
		name    string
		nonce   []byte
		serving []byte
		want    string
	}{
		{"different challenge", bytes.Repeat([]byte{0x8b}, nonceSize), serving, "does not echo"},
		{"different observed leaf", nonce, mintEndpointIdentity(t).leaf.Raw, "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evidenceFromAttestLBJSON(body, tc.nonce, tc.serving, "saved receipt")
			if err == nil || !isSecurityError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want security error containing %q", err, tc.want)
			}
		})
	}

	t.Run("front-door mode substitution", func(t *testing.T) {
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			t.Fatal(err)
		}
		object["front_door_mode"] = "acme"
		mutated, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved receipt"); err == nil || !isSecurityError(err) {
			t.Fatalf("mode substitution was accepted: %v", err)
		}
	})

	t.Run("serving-leaf digest claim substitution", func(t *testing.T) {
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			t.Fatal(err)
		}
		object["serving_leaf_sha256"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, sha256.Size))
		mutated, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved receipt"); err == nil || !isSecurityError(err) {
			t.Fatalf("serving-leaf digest substitution was accepted: %v", err)
		}
	})

	t.Run("host-visible webpki mode", func(t *testing.T) {
		webPKI := buildAttestLBJSON(t, mesh, "webpki", nonce, serving)
		if _, err := evidenceFromAttestLBJSON(webPKI, nonce, serving, "saved receipt"); err == nil || !isSecurityError(err) {
			t.Fatalf("webpki attest-lb was accepted: %v", err)
		}
	})
}

func TestAttestLBRejectsWrongShape(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x22}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw

	t.Run("attest-pq version", func(t *testing.T) {
		var object map[string]any
		if err := json.Unmarshal(buildAttestLBJSON(t, mesh, "cds", nonce, serving), &object); err != nil {
			t.Fatal(err)
		}
		object["version"] = types.BindingAttestPQ
		mutated, _ := json.Marshal(object)
		if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved receipt"); err == nil {
			t.Fatal("attest-pq response was accepted as attest-lb")
		}
	})

	t.Run("session key", func(t *testing.T) {
		var object map[string]any
		if err := json.Unmarshal(buildAttestLBJSON(t, mesh, "cds", nonce, serving), &object); err != nil {
			t.Fatal(err)
		}
		object["session_pubkey"] = map[string]string{"x25519": "AA"}
		mutated, _ := json.Marshal(object)
		if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved receipt"); err == nil {
			t.Fatal("attest-lb response with a session key was accepted")
		}
	})
}

func TestValidateAttestLBConfigRequiresOfflineObservedInputs(t *testing.T) {
	valid := config{
		kind: "workload", mode: "attest-lb", fromFile: "receipt.json",
		observedServingCert: "leaf.der",
		attestationNonce:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, nonceSize)),
	}
	if err := validateAttestLBConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.kind = "lb" },
		func(c *config) { c.fromFile = "" },
		func(c *config) { c.url = "https://example.test" },
		func(c *config) { c.observedServingCert = "" },
		func(c *config) { c.attestationNonce = "" },
		func(c *config) { c.attestationNonce = "AA" },
		func(c *config) { c.expectedRDHex = "01" },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateAttestLBConfig(candidate); err == nil {
			t.Fatalf("invalid config passed: %+v", candidate)
		}
	}
}

func TestParseObservedServingCertificateAcceptsOneDEROrPEM(t *testing.T) {
	der := mintEndpointIdentity(t).leaf.Raw
	for _, value := range [][]byte{
		der,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	} {
		got, err := parseObservedServingCertificate(value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, der) {
			t.Fatal("parsed certificate DER changed")
		}
	}
}

func TestAttestLBRejectsXWingSessionFields(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x22}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw
	for _, field := range []string{"xwing_ek", "xwing_ct", "session_id"} {
		t.Run(field, func(t *testing.T) {
			var object map[string]any
			if err := json.Unmarshal(buildAttestLBJSON(t, mesh, "acme", nonce, serving), &object); err != nil {
				t.Fatal(err)
			}
			object[field] = "AA"
			mutated, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved receipt"); err == nil {
				t.Fatal("accepted session field on attest-lb")
			}
		})
	}
}
