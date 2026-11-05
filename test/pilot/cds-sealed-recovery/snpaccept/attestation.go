//go:build linux

package snpaccept

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Collateral is public AMD certificate/CRL data fetched by the host. The guest
// verifies signatures, embedded AMD roots and revocation itself. Missing data
// fails closed; no network or mock-verification fallback exists.
type Collateral map[string][]byte

func (c Collateral) Get(url string) ([]byte, error) {
	b, ok := c[url]
	if !ok {
		return nil, fmt.Errorf("missing AMD collateral for %s", url)
	}
	return b, nil
}
func (c Collateral) GetContext(ctx context.Context, url string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Get(url)
}

func AttestationAPI(h *Hardware, collateral Collateral) http.Handler {
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
			answer = remote.HealthResponse{Status: "ok", Platform: teetypes.Ptr(teetypes.PlatformSNP)}
		case "POST /attest":
			var q remote.AttestRequest
			if err = decodeHTTP(w, r, &q, 1<<20); err == nil {
				if len(q.ReportData) != 48 || (q.Platform != "" && q.Platform != remote.PlatformAuto && q.Platform != teetypes.PlatformSNP) {
					err = errors.New("SNP report with 48-byte binding required")
				} else {
					var data [64]byte
					copy(data[:], q.ReportData)
					var raw []byte
					raw, err = h.Report(r.Context(), data)
					if err == nil {
						body, _ := json.Marshal(snp.SnpEvidence{AttestationReport: base64.StdEncoding.EncodeToString(raw)})
						answer = remote.AttestResponse{Platform: teetypes.PlatformSNP, Evidence: body}
					}
				}
			}
		case "POST /verify":
			var q remote.VerifyRequest
			if err = decodeHTTP(w, r, &q, 1<<20); err == nil {
				if q.Platform != teetypes.PlatformSNP || (q.IssueToken != nil && *q.IssueToken) {
					err = errors.New("SNP verification without token required")
				} else {
					var ev snp.SnpEvidence
					err = json.Unmarshal(q.Evidence, &ev)
					p := teetypes.VerifyParams{}
					if q.Params != nil {
						v := q.Params
						p.ExpectedReportData = v.ExpectedReportData
						p.ExpectedInitDataHash = v.ExpectedInitDataHash
						p.ExpectedLaunchDigest = v.ExpectedLaunchDigest
						p.MinTCB = v.MinTcb
						if v.AllowDebug != nil && *v.AllowDebug {
							err = errors.New("debug forbidden")
						}
						if len(v.ExpectedMRTD)+len(v.ExpectedRTMR0)+len(v.ExpectedRTMR1)+len(v.ExpectedRTMR2)+len(v.ExpectedRTMR3) > 0 {
							err = errors.New("TDX pins cannot be enforced on SNP")
						}
					}
					if err == nil {
						var result *teetypes.VerificationResult
						result, err = snp.VerifyEvidenceContext(r.Context(), ev, p, snp.Options{CheckRevocations: true, Getter: collateral})
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
