// mock-attestation is a fake attestation-api for integration testing: the
// networked counterpart of internal/mockapi. /attest answers synthetic
// SEV-SNP reports binding the requested REPORTDATA and the HOST_DATA the
// environment names; /verify checks the REPORTDATA binding and refuses
// mismatches with the real api's 422 verification_failed shape. Speaks the
// production wire types (pkg/types). It listens where its --config's
// server.bind says, as the real api does, else on $PORT. No real TEE — use
// only in test environments.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
)

// SNP report layout (AMD SEV-SNP ABI): the fields the synthetic report
// carries. MEASUREMENT names the launch identity it reports, and a lane's
// Trust Authority or node pin names the same value.
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
	configPath := flag.String("config", "", "attestation-api config file whose server.bind, socket_mode and socket_group to honour")
	flag.Parse()

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

	listener, err := listen(*configPath, os.Getenv("PORT"))
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
	slog.Info("mock attestation-api starting", "addr", listener.Addr())
	if err := http.Serve(listener, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// serverConfig is the part of the attestation-api config the mock honours.
type serverConfig struct {
	Server struct {
		Bind        string `toml:"bind"`
		SocketMode  string `toml:"socket_mode"`
		SocketGroup *int   `toml:"socket_group"`
	} `toml:"server"`
}

// listen binds the server.bind configPath names, or :port (default 8400)
// without a config. A unix: bind gets socket_mode (default 0660) and
// socket_group, replacing whatever socket a previous run left.
func listen(configPath, port string) (net.Listener, error) {
	if configPath == "" {
		if port == "" {
			port = "8400"
		}
		return net.Listen("tcp", ":"+port)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg serverConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configPath, err)
	}
	path, ok := strings.CutPrefix(cfg.Server.Bind, "unix://")
	if !ok {
		return net.Listen("tcp", cfg.Server.Bind)
	}
	mode := uint64(0o660)
	if cfg.Server.SocketMode != "" {
		if mode, err = strconv.ParseUint(cfg.Server.SocketMode, 8, 32); err != nil {
			return nil, fmt.Errorf("socket_mode %q: %w", cfg.Server.SocketMode, err)
		}
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if cfg.Server.SocketGroup != nil {
		if err := os.Chown(path, -1, *cfg.Server.SocketGroup); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	return listener, nil
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
