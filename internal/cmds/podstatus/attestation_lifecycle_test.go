package podstatus

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestAttestRequiresAStableMeasurementSnapshot(t *testing.T) {
	for _, continuous := range []bool{false, true} {
		name := "one new launch converges"
		if continuous {
			name = "continuous launches exhaust retries"
		}
		t.Run(name, func(t *testing.T) {
			digests := []string{dA, dB}
			if continuous {
				digests = append(digests, "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64))
			}
			var reads, quotes atomic.Int32
			cfg := attestFixture(t, digests, digests[:1], nil, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == MeasurementsPath {
						n := min(int(reads.Add(1)), len(digests))
						writeJSON(w, Measurements{Digests: digests[:n]})
						return
					}
					if r.URL.Path == EvidencePath {
						quotes.Add(1)
					}
					next.ServeHTTP(w, r)
				})
			})
			report, client, err := Attest(t.Context(), cfg)
			if continuous {
				if err == nil || !strings.Contains(err.Error(), "measured digests kept changing") || report != nil || client != nil {
					t.Fatalf("unstable snapshot returned authority: report=%v client=%v err=%v", report, client, err)
				}
				if quotes.Load() != 3 || reads.Load() != 4 {
					t.Fatalf("retry budget: %d quotes, %d measurement reads", quotes.Load(), reads.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if !slices.Equal(report.MeasuredDigests, digests) || quotes.Load() != 2 || reads.Load() != 3 {
				t.Fatalf("snapshot did not converge: report=%+v, %d quotes, %d reads", report, quotes.Load(), reads.Load())
			}
		})
	}
}

func TestAttestRefusesAnInterruptedSnapshot(t *testing.T) {
	for _, path := range []string{EvidencePath, MeasurementsPath} {
		t.Run(path, func(t *testing.T) {
			var reads, quotes atomic.Int32
			cfg := attestFixture(t, []string{dA}, []string{dA}, nil, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == MeasurementsPath {
						reads.Add(1)
					}
					if r.URL.Path == EvidencePath {
						quotes.Add(1)
					}
					if r.URL.Path == path && (path == EvidencePath || reads.Load() > 1) {
						http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			report, client, err := Attest(t.Context(), cfg)
			if err == nil || !strings.Contains(err.Error(), "snapshot unavailable") || report != nil || client != nil {
				t.Fatalf("interrupted snapshot returned authority: report=%v client=%v err=%v", report, client, err)
			}
			if quotes.Load() != 1 {
				t.Fatalf("an unavailable snapshot retried %d quotes", quotes.Load())
			}
		})
	}
}

func TestEvidenceHandlerRefusesUnavailableAuthority(t *testing.T) {
	cert := ecdsaCert(t)
	body, err := json.Marshal(types.NonceRequest{Nonce: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		key       crypto.PublicKey
		status    int
		wantCalls int
	}{
		{"no serving key", nil, http.StatusInternalServerError, 0},
		{"invalid serving key", struct{}{}, http.StatusInternalServerError, 0},
		{"evidence backend unavailable", cert.Leaf.PublicKey, http.StatusBadGateway, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := Handler{Evidence: func(context.Context, []byte) ([]byte, error) {
				calls++
				return nil, errors.New("private backend diagnostic")
			}}
			req := httptest.NewRequest(http.MethodPost, EvidencePath, bytes.NewReader(body))
			if tc.key != nil {
				req = req.WithContext(armtls.WithServingKey(req.Context(), tc.key))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status || calls != tc.wantCalls {
				t.Fatalf("status=%d calls=%d; want status=%d calls=%d", rec.Code, calls, tc.status, tc.wantCalls)
			}
			if rec.Header().Get(BindingHeader) != "" || strings.Contains(rec.Body.String(), "private backend diagnostic") {
				t.Fatalf("failed evidence advertised a binding or leaked backend detail: %v %s", rec.Header(), rec.Body)
			}
		})
	}
}

func TestStatusHandlerRefusesUnreadableSources(t *testing.T) {
	h := Handler{Journal: t.TempDir(), Pods: func(context.Context) ([]byte, error) { return []byte("{"), nil }}
	if rec := serve(h, http.MethodGet, MeasurementsPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable journal returned measurements: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusNotFound {
		t.Fatalf("malformed kubelet response returned a pod: %d %s", rec.Code, rec.Body)
	}
}
