package guestverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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

// The measuring-guest client binds the launch key through the
// leaf's own list: a leaf whose list replays its quote's register opens the
// channel, a leaf that lists nothing while the register has moved does not.
func TestClientReplaysTheLeafList(t *testing.T) {
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
			client := NewClient(exp.WithMeasuredPolicies(nil), 5*time.Second)
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
}
