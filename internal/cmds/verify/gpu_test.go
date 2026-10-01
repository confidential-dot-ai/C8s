package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyNvidiaGPUReportsSignedIdentities(t *testing.T) {
	nonce := strings.Repeat("ab", 48)
	path := writeTestGPUVerifier(t, `{
"signature_valid":true,"report_data_match":true,
"claims":{"nvidia_gpu":{"overall_ok":true,"nonce_binding_ok":true,
"devices":[{"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"},{"ueid":"switch-a","arch":"LS10","hwmodel":"LS10 NVSwitch"}]}}}`)
	got, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce: nonce, nvidiaGPURequired: true,
		attestationCLIPath: path, attestationCLISHA256: testGPUVerifierDigest(t, path),
	}, &evidence{platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"BLACKWELL"},{"arch":"LS10"}]}`),
		gpuAttested: gpuEvidenceCollected, erd: mustTestHex(t, nonce)})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Verified || !got.NonceBindingOK || len(got.GPUDeviceUEIDs) != 1 || len(got.SwitchDeviceUEIDs) != 1 {
		t.Fatalf("GPU verdict = %+v", got)
	}
}

func TestValidateNvidiaGPUConfig(t *testing.T) {
	if err := validateNvidiaGPUConfig(config{nvidiaGPURequired: true}); err == nil {
		t.Fatal("required without nonce passed")
	}
	if err := validateNvidiaGPUConfig(config{nvidiaGPUUserNonce: strings.Repeat("ab", 16), nvidiaGPUExpectedArchs: []string{"AMPERE"}}); err == nil {
		t.Fatal("unsupported architecture passed")
	}
	if err := validateNvidiaGPUConfig(config{nvidiaGPUUserNonce: strings.Repeat("ab", 16), attestationCLISHA256: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
}

func writeTestGPUVerifier(t *testing.T, result string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attestation-cli")
	script := "#!/bin/sh\nset -eu\nif [ \"$1\" = \"--version\" ]; then echo 'attestation-cli 0.5.0'; exit 0; fi\n[ \"$1\" = \"verify\" ]\ncat >/dev/null\nprintf '%s\\n' '" + result + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testGPUVerifierDigest(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func mustTestHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyNvidiaGPURejectsUnverifiedEvidence(t *testing.T) {
	nonce := strings.Repeat("ab", 48)
	cases := []struct{ name, result string }{
		{"CPU signature", `{"signature_valid":false,"report_data_match":true}`},
		{"CPU binding", `{"signature_valid":true,"report_data_match":false}`},
		{"GPU signature", `{"signature_valid":true,"report_data_match":true,"claims":{"nvidia_gpu":{"overall_ok":false,"nonce_binding_ok":true}}}`},
		{"GPU nonce", `{"signature_valid":true,"report_data_match":true,"claims":{"nvidia_gpu":{"overall_ok":true,"nonce_binding_ok":false}}}`},
		{"no device", `{"signature_valid":true,"report_data_match":true,"claims":{"nvidia_gpu":{"overall_ok":true,"nonce_binding_ok":true,"devices":[]}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestGPUVerifier(t, tc.result)
			_, err := verifyNvidiaGPU(context.Background(), config{nvidiaGPUUserNonce: nonce, nvidiaGPURequired: true, attestationCLIPath: path, attestationCLISHA256: testGPUVerifierDigest(t, path)}, &evidence{platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`), nvidiaGPU: json.RawMessage(`{"devices":[]}`), gpuAttested: gpuEvidenceCollected, erd: mustTestHex(t, nonce)})
			if err == nil {
				t.Fatal("accepted unverified GPU evidence")
			}
		})
	}
}
