package gpuattestations

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	snpabi "github.com/google/go-sev-guest/abi"
	tdxabi "github.com/google/go-tdx-guest/abi"
	sigsjson "sigs.k8s.io/json"
)

type record struct {
	Status     string          `json:"status"`
	BootID     string          `json:"boot_id,omitempty"`
	Nonce      string          `json:"nonce,omitempty"`
	Platform   string          `json:"platform,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	NVIDIAGPU  json.RawMessage `json:"nvidia_gpu,omitempty"`
	Collateral json.RawMessage `json:"collateral,omitempty"`
}

var kernelBootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func decodeRecord(body []byte) (record, bool) {
	var r record
	strict, err := sigsjson.UnmarshalStrict(body, &r)
	if err != nil || len(strict) != 0 || !kernelBootID.MatchString(r.BootID) {
		return record{}, false
	}
	switch r.Status {
	case "no_gpu":
		if r.Nonce == "" && r.Platform == "" && r.Evidence == nil && r.NVIDIAGPU == nil && r.Collateral == nil {
			return r, true
		}
	case "attested":
		nonce, err := base64.StdEncoding.Strict().DecodeString(r.Nonce)
		if err != nil || len(nonce) != 32 || base64.StdEncoding.EncodeToString(nonce) != r.Nonce {
			break
		}
		if r.Collateral != nil && r.Collateral[0] != '{' {
			break
		}
		if hasCPUEvidence(r.Platform, r.Evidence) && hasGPUEvidence(r.NVIDIAGPU) {
			return r, true
		}
	}
	return record{}, false
}

func hasCPUEvidence(platform string, raw json.RawMessage) bool {
	var cpu struct {
		Report string `json:"attestation_report"`
		Quote  string `json:"quote"`
	}
	if err := json.Unmarshal(raw, &cpu); err != nil {
		return false
	}
	switch platform {
	case "snp":
		return decodedSize(cpu.Report) == snpabi.ReportSize
	case "tdx":
		return decodedSize(cpu.Quote) >= tdxabi.QuoteMinSize
	default:
		return false
	}
}

func decodedSize(value string) int {
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return 0
	}
	return len(data)
}

func hasGPUEvidence(raw json.RawMessage) bool {
	var gpu struct {
		Binding struct {
			Kind string `json:"kind"`
		} `json:"binding"`
		Devices []struct {
			Arch   string `json:"arch"`
			UUID   string `json:"uuid"`
			Report string `json:"evidence_b64"`
			Chain  string `json:"cert_chain_b64"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(raw, &gpu); err != nil || gpu.Binding.Kind == "" {
		return false
	}
	hasGPU := false
	for _, device := range gpu.Devices {
		if device.Arch == "" || strings.TrimSpace(device.UUID) == "" || decodedSize(device.Report) == 0 || decodedSize(device.Chain) == 0 {
			return false
		}
		if device.Arch != "LS10" {
			hasGPU = true
		}
	}
	return hasGPU
}
