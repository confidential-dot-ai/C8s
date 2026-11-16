// mock-attestation is a fake attestation-api for integration testing: the
// networked counterpart of internal/mockapi. /attest answers synthetic
// SEV-SNP reports binding the requested REPORTDATA and the HOST_DATA the
// environment names; /verify checks the REPORTDATA binding and refuses
// mismatches with the real api's 422 verification_failed shape. Speaks the
// production wire types (pkg/types). No real TEE — use only in test
// environments.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SNP report layout (AMD SEV-SNP ABI): the fields the synthetic report
// carries. MEASUREMENT names the launch identity it reports, and a lane's
// CDS or node pin names the same value.
const (
	snpReportSize     = 1184
	reportDataOffset  = 0x50
	reportDataSize    = 64
	measurementOffset = 0x90
	measurementSize   = 48
	hostDataOffset    = 0xC0
	hostDataSize      = 32
)

// noHostData is the HOST_DATA of a guest whose launcher committed nothing.
var noHostData [hostDataSize]byte

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8400"
	}

	hostData, err := parseHostData(os.Getenv("HOST_DATA"))
	if err != nil {
		slog.Error("invalid HOST_DATA", "error", err)
		os.Exit(1)
	}
	measurement, err := parseMeasurement(os.Getenv("MEASUREMENT"))
	if err != nil {
		slog.Error("invalid MEASUREMENT", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", attestHandler(measurement, hostData))
	mux.HandleFunc("POST /verify", handleVerify)
	mux.HandleFunc("GET /health", handleHealth)

	slog.Info("mock attestation-api starting", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// attestHandler answers synthetic reports carrying the guest image's launch
// measurement and the launch file its launcher committed, and binding the
// requested REPORTDATA.
func attestHandler(measurement, hostData []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeDecodeError(w, err)
			return
		}

		platform := req.Platform
		if platform == "" || platform == remote.PlatformAuto {
			platform = teetypes.PlatformSNP
		}
		slog.Info("mock attest called", "platform", platform)

		report := make([]byte, snpReportSize)
		report[0] = 0x02    // report version 2
		report[0x0A] = 0x03 // SMT-allowed policy
		copy(report[reportDataOffset:reportDataOffset+reportDataSize], req.ReportData)
		copy(report[measurementOffset:measurementOffset+measurementSize], measurement)
		copy(report[hostDataOffset:hostDataOffset+hostDataSize], hostData)

		evidence, _ := json.Marshal(map[string]string{
			"attestation_report": base64.StdEncoding.EncodeToString(report),
		})
		writeJSON(w, remote.AttestResponse{
			Platform: platform,
			Evidence: evidence,
		})
	}
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	var req remote.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeDecodeError(w, err)
		return
	}

	report, err := extractSNPReport(req.Evidence)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, err.Error())
		return
	}

	// The evidence carries no real signature chain; the only verdict the mock
	// can meaningfully enforce is the REPORTDATA binding, requested via
	// params.expected_report_data. No expectation is the api's no-check shape
	// (report_data_match: null).
	var match *bool
	if req.Params != nil && len(req.Params.ExpectedReportData) > 0 {
		expected := make([]byte, reportDataSize)
		copy(expected, req.Params.ExpectedReportData)
		m := string(report[reportDataOffset:reportDataOffset+reportDataSize]) == string(expected)
		if !m {
			writeError(w, http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "REPORTDATA does not match expected value")
			return
		}
		match = &m
	}

	writeJSON(w, remote.VerifyResponse{
		Result: teetypes.VerificationResult{
			Platform:        req.Platform,
			SignatureValid:  true,
			ReportDataMatch: match,
			Claims: teetypes.Claims{
				LaunchDigest: hex.EncodeToString(report[measurementOffset : measurementOffset+measurementSize]),
				InitData:     hostDataClaim(report),
			},
		},
	})
}

// hostDataClaim is the launch binding the report carries, and none when the
// launcher committed nothing: an all-zero HOST_DATA binds no launch file.
func hostDataClaim(report []byte) []byte {
	hostData := report[hostDataOffset : hostDataOffset+hostDataSize]
	if bytes.Equal(hostData, noHostData[:]) {
		return nil
	}
	return hostData
}

// parseHostData decodes the hex HOST_DATA the environment names. A value of
// the wrong width is refused rather than padded: a guest bound to a truncated
// digest is bound to nothing an operator wrote.
func parseHostData(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%q is not hex: %s", value, err)
	}
	if len(raw) != hostDataSize {
		return nil, fmt.Errorf("%q is %d bytes, want %d", value, len(raw), hostDataSize)
	}
	return raw, nil
}

// parseMeasurement decodes the hex launch measurement the environment names;
// an empty value is the all-zero measurement. A value of the wrong width is
// refused rather than padded: a pin naming it would name no guest.
func parseMeasurement(value string) ([]byte, error) {
	if value == "" {
		return make([]byte, measurementSize), nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%q is not hex: %s", value, err)
	}
	if len(raw) != measurementSize {
		return nil, fmt.Errorf("%q is %d bytes, want %d", value, len(raw), measurementSize)
	}
	return raw, nil
}

// extractSNPReport pulls the raw report out of an SNP evidence envelope and
// checks it is the shape the mock issues.
func extractSNPReport(evidence json.RawMessage) ([]byte, error) {
	var envelope struct {
		AttestationReport string `json:"attestation_report"`
	}
	if err := json.Unmarshal(evidence, &envelope); err != nil {
		return nil, fmt.Errorf("evidence is not an SNP envelope: %s", err)
	}
	report, err := base64.StdEncoding.DecodeString(envelope.AttestationReport)
	if err != nil {
		return nil, fmt.Errorf("attestation_report is not valid base64: %s", err)
	}
	if len(report) != snpReportSize || report[0] != 0x02 {
		return nil, fmt.Errorf("not a version-2 SNP report (%d bytes)", len(report))
	}
	return report, nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	platform := teetypes.PlatformSNP
	writeJSON(w, remote.HealthResponse{Status: "ok", Platform: &platform})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(remote.ErrorResponse{Error: code, Message: message})
}

// writeDecodeError mirrors the attestation-api's axum Json rejection: 400 for a
// body that is not valid JSON, 422 for one that does not fit the target type,
// both text/plain with no error code.
func writeDecodeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	msg := "Failed to parse the request body as JSON: " + err.Error()
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		status = http.StatusUnprocessableEntity
		msg = "Failed to deserialize the JSON body into the target type: " + err.Error()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}
