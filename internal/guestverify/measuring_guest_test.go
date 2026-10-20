package guestverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// attestedTDXServer serves a self-signed armTLS leaf whose TDX attestation
// lists extensions as its runtime extensions.
func attestedTDXServer(t *testing.T, extensions []string, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeTDX, Report: []byte(tdxEnvelope), RuntimeExtensions: extensions}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	return srv
}

// A pod CVM extends RTMR[3] after boot, so fresh evidence from it binds the
// launch key once the register replays the key's seed followed by a prefix
// of the measured list the guest claims. A list the register does not
// explain, or a register the list does not reach, fails.
func TestVerifyFreshEvidenceAcceptsReplayingPrefix(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	exp, err := PolicyFor(manifest, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	d3 := "sha256:" + strings.Repeat("3", 64)
	reportData := make([]byte, 64)
	for i := range reportData {
		reportData[i] = byte(i)
	}
	for _, tc := range []struct {
		name     string
		measured []string // extended into the quote's register
		claimed  []string
		wantErr  string
	}{
		{name: "list matches", measured: []string{d1, d2}, claimed: []string{d1, d2}},
		{name: "list ahead of the quote", measured: []string{d1, d2}, claimed: []string{d1, d2, d3}},
		{name: "nothing measured, nothing claimed", measured: nil, claimed: nil},
		{name: "nothing measured, list ahead", measured: nil, claimed: []string{d1}},
		{name: "list short of the register", measured: []string{d1, d2}, claimed: []string{d1}, wantErr: "measured policies"},
		{name: "list does not replay", measured: []string{d1}, claimed: []string{d2}, wantErr: "measured policies"},
		{name: "measured, nothing claimed", measured: []string{d1}, claimed: nil, wantErr: "RTMR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := VerifyEnvelope
			t.Cleanup(func() { VerifyEnvelope = orig })
			VerifyEnvelope = func(_ []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
				if string(params.ExpectedReportData) != string(reportData) {
					t.Errorf("ExpectedReportData = %x, want the caller's report data", params.ExpectedReportData)
				}
				res := verifiedResultFor(exp)
				reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), tc.measured)
				res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
				return res, nil
			}
			envelope := []byte(`{"platform":"tdx","evidence":{"quote":"AA=="}}`)
			res, err := VerifyFreshEvidence(manifest, pub, envelope, reportData, tc.claimed)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyFreshEvidence = %v, want success", err)
				}
				if res == nil || res.Platform != teetypes.PlatformTDX {
					t.Fatalf("result = %+v, want the verified TDX result", res)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("VerifyFreshEvidence = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// The measuring-guest client binds the launch key through the leaf's own
// list: a leaf whose list replays its quote's register opens the channel, a
// leaf that lists nothing while the register has moved does not.
func TestNewMeasuringGuestClientReplaysTheLeafList(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	exp, err := PolicyFor(manifest, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name    string
		leaf    []string
		wantErr string
	}{
		{name: "leaf list replays", leaf: []string{d1, d2}},
		{name: "leaf list ahead of the quote", leaf: []string{d1, d2, "sha256:" + strings.Repeat("3", 64)}},
		{name: "leaf lists nothing", wantErr: "measured policies"},
		{name: "leaf list does not replay", leaf: []string{d2}, wantErr: "measured policies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := VerifyEnvelope
			t.Cleanup(func() { VerifyEnvelope = orig })
			VerifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
				res := verifiedResultFor(exp)
				reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), []string{d1, d2})
				res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
				return res, nil
			}
			srv := attestedTDXServer(t, tc.leaf, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"digests":[]}`))
			}))
			t.Cleanup(srv.Close)
			client, err := NewMeasuringGuestClient(manifest, pub, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Get(srv.URL + "/v1/measurements")
			if err == nil {
				resp.Body.Close()
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("dial = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("dial = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
	if _, err := NewMeasuringGuestClient(filepath.Join(t.TempDir(), "absent.json"), pub, time.Second); err == nil || !strings.Contains(err.Error(), "--image-manifest") {
		t.Fatalf("missing manifest: %v", err)
	}
}
