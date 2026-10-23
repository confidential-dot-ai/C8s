package cdsha

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// fakeAttestationAPI emulates /attest and /verify for one TDX "node": the
// evidence it issues carries the report_data verbatim, and /verify echoes it
// back in the claims. It only checks that the Verify request carries the same
// evidence, so the test exercises the client wiring and claim mapping.
type fakeAttestationAPI struct {
	rtmr   [4]string
	mrtd   string
	broken bool // report an invalid signature
}

func (f *fakeAttestationAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", func(w http.ResponseWriter, r *http.Request) {
		var req remote.AttestRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ev, _ := json.Marshal(map[string]string{"quote": hex.EncodeToString(req.ReportData)})
		_ = json.NewEncoder(w).Encode(remote.AttestResponse{Platform: teetypes.PlatformTDX, Evidence: ev})
	})
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req remote.VerifyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		var ev struct{ Quote string }
		_ = json.Unmarshal(req.Evidence, &ev)
		rd, _ := hex.DecodeString(ev.Quote)
		rd = append(rd, make([]byte, 64-len(rd))...)
		res := teetypes.VerificationResult{
			SignatureValid: !f.broken,
			Platform:       teetypes.PlatformTDX,
			Claims: teetypes.Claims{
				LaunchDigest: f.mrtd,
				ReportData:   rd,
				PlatformData: map[string]any{"rtmr_0": f.rtmr[0], "rtmr_1": f.rtmr[1], "rtmr_2": f.rtmr[2], "rtmr_3": f.rtmr[3]},
			},
		}
		_ = json.NewEncoder(w).Encode(remote.VerifyResponse{Result: res})
	})
	return mux
}

func TestNodeAttestorRoundTrip(t *testing.T) {
	f := &fakeAttestationAPI{mrtd: digest(1), rtmr: [4]string{digest(0xa0), digest(2), digest(3), digest(0x33)}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	att := NewNodeAttestor(srv.URL, 2*time.Second)

	rd := PeerBinding("tenant-a", []byte("spki"))
	ev, err := att.Evidence(rd)
	if err != nil {
		t.Fatal(err)
	}
	c, err := att.Verify(ev)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReportData != rd {
		t.Fatal("report_data not carried through")
	}
	// Measurement excludes RTMR0 (VM shape); anchor is RTMR3.
	if want := strings.Join([]string{digest(1), digest(2), digest(3)}, ":"); c.Measurement != want {
		t.Fatalf("measurement %s", c.Measurement)
	}
	if c.Anchor != digest(0x33) {
		t.Fatalf("anchor %s", c.Anchor)
	}
	// A verdict with an invalid signature is refused before any claim is read.
	f.broken = true
	if _, err := att.Verify(ev); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := att.Verify([]byte("{")); err == nil {
		t.Fatal("evidence that is not JSON verified")
	}
}
