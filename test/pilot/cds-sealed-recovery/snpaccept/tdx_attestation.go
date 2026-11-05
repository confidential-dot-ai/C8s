//go:build linux

package snpaccept

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func TDXAttestationAPI(h *TDXHardware, collateral IntelCollateral) http.Handler {
	gate := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			http.Error(w, "attestation backpressure", 429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var answer any
		var err error
		switch r.Method + " " + r.URL.Path {
		case "GET /health":
			answer = remote.HealthResponse{Status: "ok", Platform: teetypes.Ptr(teetypes.PlatformTDX)}
		case "POST /attest":
			var q remote.AttestRequest
			if err = decodeHTTP(w, r, &q, 1<<20); err == nil {
				if len(q.ReportData) != 48 || (q.Platform != "" && q.Platform != remote.PlatformAuto && q.Platform != teetypes.PlatformTDX) {
					err = errors.New("TDX report with 48-byte binding required")
				} else {
					var data [64]byte
					copy(data[:], q.ReportData)
					var raw []byte
					raw, err = h.Report(r.Context(), data)
					if err == nil {
						body, _ := json.Marshal(tdx.TdxEvidence{Quote: base64.StdEncoding.EncodeToString(raw)})
						answer = remote.AttestResponse{Platform: teetypes.PlatformTDX, Evidence: body}
					}
				}
			}
		case "POST /verify":
			var q remote.VerifyRequest
			if err = decodeHTTP(w, r, &q, 1<<20); err == nil {
				if q.Platform != teetypes.PlatformTDX || (q.IssueToken != nil && *q.IssueToken) {
					err = errors.New("TDX verification without token required")
				} else {
					var ev tdx.TdxEvidence
					err = json.Unmarshal(q.Evidence, &ev)
					p := teetypes.VerifyParams{}
					if q.Params != nil {
						v := q.Params
						if v.MinTcb != nil || len(v.ExpectedLaunchDigest) != 0 || (v.AllowDebug != nil && *v.AllowDebug) {
							err = errors.New("SNP-only parameters or debug forbidden")
						}
						p.ExpectedReportData = v.ExpectedReportData
						p.ExpectedInitDataHash = v.ExpectedInitDataHash
						p.ExpectedLaunchDigest = v.ExpectedMRTD
						p.ExpectedRTMRs = [][]byte{v.ExpectedRTMR0, v.ExpectedRTMR1, v.ExpectedRTMR2, v.ExpectedRTMR3}
					}
					if err == nil {
						var result *teetypes.VerificationResult
						result, err = tdx.VerifyEvidence(ev, p, tdx.Options{CheckRevocations: true, GetCollateral: true, Getter: collateral})
						if err == nil {
							answer = remote.VerifyResponse{Result: *result}
						}
					}
				}
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(remote.ErrorResponse{Error: "attestation_refused", Message: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	})
}
