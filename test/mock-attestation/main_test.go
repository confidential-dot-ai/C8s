package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
)

// TestWriteDecodeErrorShapes mirrors internal/mockapi.TestStubRejectsUndecodableBody:
// axum splits the rejection 400 for a body that is not valid JSON, 422 for one
// that does not fit the request type; both text/plain with no error code, so
// callers see UnexpectedError, not APIError. Wired into /attest and /verify.
func TestWriteDecodeErrorShapes(t *testing.T) {
	for _, ep := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/attest", attestHandler(nil, nil)},
		{"/verify", handleVerify},
	} {
		for _, tc := range []struct {
			name       string
			body       string
			wantStatus int
			wantPrefix string
		}{
			{"not valid JSON", `not json`, http.StatusBadRequest, "Failed to parse the request body as JSON"},
			{"wrong field type", `{"platform": 123}`, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type"},
		} {
			t.Run(ep.path+" "+tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				ep.handler(rec, httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(tc.body)))

				res := rec.Result()
				body, _ := io.ReadAll(res.Body)
				if res.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d (body %q)", res.StatusCode, tc.wantStatus, body)
				}
				if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
					t.Fatalf("content-type = %q, want text/plain", ct)
				}
				if !strings.HasPrefix(string(body), tc.wantPrefix) {
					t.Fatalf("body = %q, want prefix %q", body, tc.wantPrefix)
				}
				var er remote.ErrorResponse
				if json.Unmarshal(body, &er) == nil && er.Error != "" {
					t.Fatalf("decode error carried code %q, want none", er.Error)
				}
			})
		}
	}
}

// TestVerifyRefusesMismatchAndGarbage pins the /verify refusal: a report-data
// mismatch or unparseable evidence is a 422 verification_failed JSON envelope —
// the real api's shape mock-ta classifies (never a 200+false verdict).
func TestVerifyRefusesMismatchAndGarbage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence json.RawMessage
		expected []byte
	}{
		{
			name:     "report data mismatch",
			evidence: snpEvidence(t, bytes.Repeat([]byte{0xAA}, reportDataSize)),
			expected: bytes.Repeat([]byte{0xBB}, reportDataSize),
		},
		{
			name:     "garbage evidence",
			evidence: json.RawMessage(`{"attestation_report":"AAAA"}`),
			expected: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := remote.VerifyRequest{Platform: teetypes.PlatformSNP, Evidence: tc.evidence}
			if tc.expected != nil {
				req.Params = &remote.VerifyParams{ExpectedReportData: tc.expected}
			}
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			handleVerify(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))

			res := rec.Result()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (body %q)", res.StatusCode, raw)
			}
			if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
			var er remote.ErrorResponse
			if err := json.Unmarshal(raw, &er); err != nil {
				t.Fatalf("body %q is not an error envelope: %v", raw, err)
			}
			if er.Error != types.ErrorCodeVerificationFailed {
				t.Fatalf("error = %q, want %q", er.Error, types.ErrorCodeVerificationFailed)
			}
		})
	}
}

// snpEvidence builds an SNP evidence envelope carrying a version-2 report with
// the given REPORTDATA, the shape the mock's /attest issues.
func snpEvidence(t *testing.T, reportData []byte) json.RawMessage {
	t.Helper()
	report := make([]byte, snpReportSize)
	report[0] = 0x02
	copy(report[reportDataOffset:reportDataOffset+reportDataSize], reportData)
	env, err := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// The launch binding a lane configures must reach a client exactly as a real
// SNP report carries it: HOST_DATA in the report, echoed as the init-data
// claim, which is where runtimemeasure reads an SNP launch binding from.
func TestReportBindsConfiguredHostData(t *testing.T) {
	launchFile := []byte("schemaVersion: c8s-ta/v1\n")
	digest := runtimemeasure.HostData(launchFile)

	result := verify(t, attest(t, digest[:], bytes.Repeat([]byte{0x11}, reportDataSize)))

	if err := runtimemeasure.VerifyBinding(&result, launchFile, nil); err != nil {
		t.Fatalf("report does not bind the configured launch file: %v", err)
	}
}

// With no HOST_DATA the report binds no launch file, and the claim says so
// rather than reporting a 32-byte zero binding a guest could be checked
// against.
func TestReportWithoutHostDataCarriesNoBinding(t *testing.T) {
	result := verify(t, attest(t, nil, bytes.Repeat([]byte{0x11}, reportDataSize)))

	if len(result.Claims.InitData) != 0 {
		t.Errorf("init data = %x, want none", result.Claims.InitData)
	}
}

// A HOST_DATA that is not a 32-byte hex digest is refused at startup: a
// truncated or padded value binds a guest to nothing an operator wrote.
func TestParseHostDataRefusesIllFormedValues(t *testing.T) {
	for _, value := range []string{
		"zz",
		"abcd",
		strings.Repeat("ab", 31),
		strings.Repeat("ab", 33),
	} {
		if _, err := parseHostData(value); err == nil {
			t.Errorf("accepted HOST_DATA %q", value)
		}
	}
	got, err := parseHostData("")
	if err != nil || got != nil {
		t.Errorf("parseHostData(\"\") = %x, %v; want no binding", got, err)
	}
}

// reportedMeasurement is the launch identity the reports under test carry.
func reportedMeasurement(t *testing.T) []byte {
	t.Helper()
	measurement, err := parseMeasurement(strings.Repeat("cd", measurementSize))
	if err != nil {
		t.Fatal(err)
	}
	return measurement
}

// A pin names the guest image by its launch measurement, so the report
// carries the one the environment configured.
func TestReportCarriesTheConfiguredMeasurement(t *testing.T) {
	result := verify(t, attest(t, nil, bytes.Repeat([]byte{0x11}, reportDataSize)))

	measurement, err := result.Claims.LaunchMeasurement()
	if err != nil {
		t.Fatalf("launch measurement: %v", err)
	}
	if !bytes.Equal(measurement, reportedMeasurement(t)) {
		t.Errorf("launch measurement = %x, want %x", measurement, reportedMeasurement(t))
	}
}

// A measurement that is not a 48-byte hex digest is refused at startup: a pin
// naming a truncated or padded value names no guest.
func TestParseMeasurementRefusesIllFormedValues(t *testing.T) {
	for _, value := range []string{"zz", "abcd", strings.Repeat("ab", 47), strings.Repeat("ab", 49)} {
		if _, err := parseMeasurement(value); err == nil {
			t.Errorf("accepted MEASUREMENT %q", value)
		}
	}
	got, err := parseMeasurement("")
	if err != nil || !bytes.Equal(got, make([]byte, measurementSize)) {
		t.Errorf("parseMeasurement(\"\") = %x, %v; want the all-zero measurement", got, err)
	}
}

// attest asks /attest for a report binding hostData and reportData, and
// returns the evidence envelope it answers with.
func attest(t *testing.T, hostData []byte, reportData []byte) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(remote.AttestRequest{
		Platform:   teetypes.PlatformSNP,
		ReportData: reportData,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	attestHandler(reportedMeasurement(t), hostData)(rec, request)
	var resp remote.AttestResponse
	if err := json.NewDecoder(rec.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode /attest: %v", err)
	}
	return resp.Evidence
}

// verify asks /verify for the result it reports over evidence.
func verify(t *testing.T, evidence json.RawMessage) teetypes.VerificationResult {
	t.Helper()
	body, err := json.Marshal(remote.VerifyRequest{
		Platform: teetypes.PlatformSNP,
		Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handleVerify(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))
	var resp remote.VerifyResponse
	if err := json.NewDecoder(rec.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode /verify: %v", err)
	}
	return resp.Result
}

// The mock binds the socket the chart's config names, with its mode and group,
// so the chart's probes and consumers reach it as they reach the real api.
func TestListenHonoursUnixBind(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	config := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf("[server]\nbind = \"unix://%s\"\nsocket_mode = \"0640\"\nsocket_group = %d\n\n[attestation]\nenabled = true\n", sock, os.Getgid())
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// A socket a previous run left is replaced.
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := listen(config, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o640 {
		t.Fatalf("%s mode = %s, want a 0640 socket", sock, fi.Mode())
	}
	if gid := fi.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getgid() {
		t.Fatalf("%s gid = %d, want %d", sock, gid, os.Getgid())
	}
}

func TestListenWithoutConfigUsesPort(t *testing.T) {
	listener, err := listen("", "0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, ok := listener.Addr().(*net.TCPAddr); !ok {
		t.Fatalf("listen without a config bound %s, want TCP", listener.Addr())
	}
}
