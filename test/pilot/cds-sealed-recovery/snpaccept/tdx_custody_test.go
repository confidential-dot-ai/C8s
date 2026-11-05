//go:build linux

package snpaccept

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func TestTDXGrantBindsFamilyAndIsConsumedOnce(t *testing.T) {
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	for _, change := range []bool{false, true} {
		r, err := newCustodyRecipient()
		if err != nil {
			t.Fatal(err)
		}
		r.request.Family = "tdx"
		r.request.Report = []byte("channel test only, not a verified quote")
		original := custodyBinding(r.request)
		wrap := bytes.Repeat([]byte{7}, 32)
		g, err := sealCustody(r.request, signer, wrap)
		if err != nil {
			t.Fatal(err)
		}
		if change {
			r.request.Family = ""
			if custodyBinding(r.request) == original {
				t.Fatal("family is not attested")
			}
		}
		s, w, err := r.Open(*g, public)
		defer clear(s)
		defer clear(w)
		if change && err == nil {
			t.Fatal("cross-platform grant substitution accepted")
		}
		if !change && (err != nil || !bytes.Equal(w, wrap) || !bytes.Equal(s, signer)) {
			t.Fatalf("TDX channel: %v", err)
		}
		if _, _, err = r.Open(*g, public); err == nil {
			t.Fatal("TDX recipient replay accepted")
		}
	}
}

func TestTDXCustodyRequiresBakedIndependentPins(t *testing.T) {
	if _, err := (&Hardware{}).DelegateTDX(t.Context(), Parameters{}, nil, &CustodyRequest{Family: "tdx"}, nil); err == nil {
		t.Fatal("custody without a baked TDX policy accepted")
	}
	if err := VerifyTDXCustody(&CustodyRequest{Family: "tdx"}, []byte("launch"), nil, IntelCollateral{}); err == nil {
		t.Fatal("unattested recipient accepted")
	}
	if err := checkCustodyRequest(&CustodyRequest{Family: "tdx"}); err == nil {
		t.Fatal("TDX recipient reached SNP verifier")
	}
}

func TestTDXAPIDoesNotAcceptRelaxedOrSNPParameters(t *testing.T) {
	handler := TDXAttestationAPI(nil, IntelCollateral{})
	for _, params := range []*remote.VerifyParams{
		{AllowDebug: teetypes.Ptr(true)},
		{ExpectedLaunchDigest: bytes.Repeat([]byte{1}, 48)},
		{MinTcb: &teetypes.SnpTcb{}},
	} {
		body, _ := json.Marshal(remote.VerifyRequest{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"AA=="}`), Params: params})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))
		if w.Code != 400 || !bytes.Contains(w.Body.Bytes(), []byte("SNP-only parameters or debug forbidden")) {
			t.Fatalf("unsupported policy reached verifier: %d %s", w.Code, w.Body)
		}
	}
}
