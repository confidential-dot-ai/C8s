package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestPodCDSPullAuthenticatesServerIdentity(t *testing.T) {
	fixture, err := os.ReadFile("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	identities, err := refvalues.Parse(fixture)
	if err != nil {
		t.Fatal(err)
	}
	server, podKey := identities.Images[0], identities.Images[1].Anchor
	// CDS staging emits only the server identity, independently of the Pod key.
	identities.Images = identities.Images[:1]
	pins, err := refvalues.Format(identities)
	if err != nil {
		t.Fatal(err)
	}
	pinsPath := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(pinsPath, pins, 0o600); err != nil {
		t.Fatal(err)
	}

	key, reportData, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := armtls.CreateAttestedCert(key, &armtls.Attestation{
		Family: armtls.TEETypeTDX,
		Report: []byte(`{"platform":"tdx","evidence":{"quote":"AA=="}}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := anyAllowlist(map[string]string{pushDigestA: "served-image"})
	if err := policy.Normalize(); err != nil {
		t.Fatal(err)
	}
	body := canonicalBody(t, policy)
	var requests atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/allowlist" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"1"`)
		_, _ = w.Write(body)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	verifier := mockapi.New(t)
	pull := pullConfig{URL: srv.URL, CDSMeasurementsConfig: pinsPath, AttestationApiURL: verifier.URL(), Timeout: 5 * time.Second}

	for _, tc := range []struct {
		name          string
		anchor        []byte
		wrongImage    bool
		wrongRegister int
		wrongBinding  bool
		wantErr       error
	}{
		{name: "server", anchor: server.Anchor},
		{name: "Pod launch key", anchor: podKey, wantErr: armtls.ErrPolicyViolation},
		{name: "unrelated anchor", anchor: []byte("unrelated launch key"), wantErr: armtls.ErrPolicyViolation},
		{name: "wrong image", anchor: server.Anchor, wrongImage: true, wantErr: armtls.ErrPolicyViolation},
		{name: "wrong kernel", anchor: server.Anchor, wrongRegister: 1, wantErr: armtls.ErrPolicyViolation},
		{name: "wrong rootfs", anchor: server.Anchor, wrongRegister: 2, wantErr: armtls.ErrPolicyViolation},
		{name: "unbound certificate key", anchor: server.Anchor, wrongBinding: true, wantErr: armtls.ErrKeyBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := runtimemeasure.Seed(tc.anchor)
			verdict := mockapi.PassingVerdict(hex.EncodeToString(server.Digest))
			verdict.Claims.PlatformData = map[string]any{
				"rtmr_1": hex.EncodeToString(server.Registers[1]),
				"rtmr_2": hex.EncodeToString(server.Registers[2]),
				"rtmr_3": hex.EncodeToString(seed[:]),
			}
			if tc.wrongImage {
				verdict.Claims.LaunchDigest = hex.EncodeToString(make([]byte, sha512.Size384))
			}
			if tc.wrongRegister == 1 {
				verdict.Claims.PlatformData["rtmr_1"] = hex.EncodeToString(make([]byte, sha512.Size384))
			}
			if tc.wrongRegister == 2 {
				verdict.Claims.PlatformData["rtmr_2"] = hex.EncodeToString(make([]byte, sha512.Size384))
			}
			if tc.wrongBinding {
				verdict.ReportDataMatch = teetypes.Ptr(false)
			}
			verifier.SetVerdict(verdict)
			client, err := allowlistPullHTTPClient(pull, "tdx")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			before := requests.Load()
			verifiedBefore := len(verifier.VerifyRequests())
			served, notModified, err := allowlistclient.NewClientWithHTTP(pull.URL, client).FetchServed(context.Background(), "")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("FetchServed = %v, want %v", err, tc.wantErr)
			}
			verified := verifier.VerifyRequests()
			if len(verified) != verifiedBefore+1 {
				t.Fatalf("attestation verification calls = %d, want %d", len(verified), verifiedBefore+1)
			}
			request := verified[len(verified)-1]
			if request.Platform != teetypes.PlatformTDX || request.Params == nil || !bytes.Equal(request.Params.ExpectedReportData, reportData[:sha512.Size384]) {
				t.Fatalf("verification did not bind the CDS certificate key: %+v", request)
			}
			if tc.wantErr != nil {
				if requests.Load() != before {
					t.Fatal("unauthenticated CDS reached the allowlist handler")
				}
				return
			}
			if requests.Load() != before+1 || notModified || served.Allowlist == nil || served.ETag != `W/"1"` {
				t.Fatalf("authenticated pull returned an incomplete document: %+v, notModified=%v", served, notModified)
			}
			if got := canonicalBody(t, served.Allowlist); !bytes.Equal(got, body) {
				t.Fatalf("authenticated pull returned %s, want %s", got, body)
			}
		})
	}

	t.Run("invalid staged pins fail closed", func(t *testing.T) {
		if err := os.WriteFile(pinsPath, []byte(`{"schema_version":"1","tee":"tdx","measurements":[{"mrtd":"invalid"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := allowlistPullHTTPClient(pull, "tdx"); err == nil {
			t.Fatal("invalid staged CDS pins produced a client")
		}
	})
}
