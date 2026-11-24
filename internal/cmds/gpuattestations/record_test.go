package gpuattestations

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
)

const (
	boot1  = "10000000-0000-4000-8000-000000000001"
	boot2  = "20000000-0000-4000-8000-000000000002"
	nonce  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	device = `{"arch":"BLACKWELL","uuid":"gpu-cert:20a10293438724bdca006e5809f716e7","cert_chain_b64":"Y2VydA==","evidence_b64":"cmVwb3J0"}`
	bundle = `{"devices":[` + device + `],"binding":{"kind":"concat","algo":"sha256"}}`
)

func noGPU(boot string) string {
	return fmt.Sprintf(`{"status":"no_gpu","boot_id":%q}`, boot)
}

func cpuFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../localverify/testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return string(env.Evidence)
}

func withGPU(boot, platform, evidence string) string {
	return fmt.Sprintf(`{"status":"attested","boot_id":%q,"platform":%q,"nonce":%q,"evidence":%s,"nvidia_gpu":%s,"collateral":{"cert":"def"}}`, boot, platform, nonce, evidence, bundle)
}

func TestWorkerRecord(t *testing.T) {
	snp := cpuFixture(t, "snp-evidence-genoa")
	tdx := cpuFixture(t, "tdx-evidence")
	switchDevice := strings.Replace(device, "BLACKWELL", "LS10", 1)
	for _, tc := range []struct{ platform, cpu, devices string }{
		{"snp", snp, device},
		{"tdx", tdx, device + "," + switchDevice},
	} {
		raw := strings.Replace(withGPU(boot1, tc.platform, tc.cpu), device, tc.devices, 1)
		r, ok := decodeRecord([]byte(raw))
		if !ok || string(r.Evidence) != tc.cpu || string(r.NVIDIAGPU) != strings.Replace(bundle, device, tc.devices, 1) {
			t.Fatal("valid CPU and device evidence must be preserved")
		}
	}
	valid := withGPU(boot1, "snp", snp)
	for _, body := range []string{
		noGPU("abc"),
		strings.Replace(valid, nonce, "AA==", 1),
		withGPU(boot1, "other", snp),
		withGPU(boot1, "tdx", snp),
		withGPU(boot1, "snp", tdx),
		withGPU(boot1, "snp", `{}`),
		withGPU(boot1, "snp", `{"attestation_report":"invalid!"}`),
		withGPU(boot1, "tdx", `{"quote":"AA=="}`),
		strings.Replace(valid, device, "", 1),
		strings.Replace(valid, device, "null", 1),
		strings.Replace(valid, device, switchDevice, 1),
		strings.Replace(valid, "gpu-cert:20a10293438724bdca006e5809f716e7", "", 1),
		strings.Replace(valid, "Y2VydA==", "?", 1),
		strings.Replace(valid, "cmVwb3J0", "", 1),
		strings.Replace(valid, `"kind":"concat"`, `"kind":""`, 1),
		strings.Replace(valid, `{"cert":"def"}`, "null", 1),
		strings.Replace(valid, "attested", "no_gpu", 1),
		strings.Replace(noGPU(boot1), `"no_gpu"`, `"no_gpu","status":"no_gpu"`, 1),
	} {
		if _, ok := decodeRecord([]byte(body)); ok {
			t.Fatalf("accepted invalid record %.120s", body)
		}
	}
}

func TestCPUOnlyRecord(t *testing.T) {
	cpuOnly := noGPU(boot1)
	if r, ok := decodeRecord([]byte(cpuOnly)); !ok || r.Status != "no_gpu" || r.BootID != boot1 {
		t.Fatal("CPU-only boot evidence lost")
	}
	for _, field := range []string{`"nonce":"x"`, `"platform":"snp"`, `"evidence":{}`, `"nvidia_gpu":{}`, `"collateral":{}`} {
		mixed := strings.TrimSuffix(cpuOnly, "}") + "," + field + "}"
		if _, ok := decodeRecord([]byte(mixed)); ok {
			t.Fatalf("CPU-only record accepted %s", field)
		}
	}
}

func TestMinimumTDXQuoteSize(t *testing.T) {
	for _, size := range []int{tdxabi.QuoteMinSize - 1, tdxabi.QuoteMinSize} {
		quote := base64.StdEncoding.EncodeToString(make([]byte, size))
		evidence := json.RawMessage(fmt.Sprintf(`{"quote":%q}`, quote))
		if hasCPUEvidence("tdx", evidence) != (size == tdxabi.QuoteMinSize) {
			t.Fatalf("unexpected structural check for a %d-byte quote", size)
		}
	}
}
