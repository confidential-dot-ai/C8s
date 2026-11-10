package workloadclaims

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestDigestsCallbackNonMigrationOptIn(t *testing.T) {
	for name, require := range map[string]bool{
		"legacy":    false,
		"protected": true,
	} {
		t.Run(
			name,
			func(t *testing.T) {
				nodeVerifier, cdsVerifier := mockapi.New(t), mockapi.New(t)
				setMigratable := func(
					api *mockapi.Stub,
					migratable bool,
				) {
					verdict := mockapi.PassingVerdict(hex.EncodeToString(testPins().Current().Images[0].Digest))
					verdict.Claims.PlatformData = map[string]any{
						"policy": map[string]any{"migrate_ma": migratable},
					}
					api.SetVerdict(verdict)
				}
				setMigratable(nodeVerifier, false)
				setMigratable(cdsVerifier, false)
				attest := func(
					context.Context,
					string,
				) (string, error) {
					return string(mockapi.FakeSNPReport(nil)), nil
				}
				var options []bool
				if require {
					options = []bool{true}
				}
				tlsCfg, certManager, err := DigestsServerTLSConfig(
					"sev-snp",
					attest,
					cdsVerifier.URL(),
					testPins(),
					0,
					"",
					options...,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := certManager.WarmUp(t.Context()); err != nil {
					t.Fatal(err)
				}
				certificate, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					t.Fatal(err)
				}
				// Supply the attested leaf so httptest cannot insert its own PKI leaf.
				tlsCfg.Certificates = []tls.Certificate{*certificate}
				var calls atomic.Int64
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(
					w http.ResponseWriter,
					_ *http.Request,
				) {
					calls.Add(1)
					// Each request must authenticate again under the current verdict.
					w.Header().Set("Connection", "close")
					_, _ = io.WriteString(w, "{}")
				}))
				server.TLS = tlsCfg
				server.StartTLS()
				t.Cleanup(server.Close)
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				client, err := NewDigestsClient(
					ctx,
					DigestsClientConfig{
						Platform:             "sev-snp",
						AttestFunc:           attest,
						AttestationAPIURL:    nodeVerifier.URL(),
						NodeImages:           testNodeImages(),
						RequireNonMigratable: require,
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				request := func() error {
					response, err := client.http.Get(server.URL)
					if err != nil {
						return err
					}
					defer response.Body.Close()
					_, err = io.Copy(io.Discard, response.Body)
					return err
				}
				if err := request(); err != nil {
					t.Fatalf(
						"non-migratable peers failed: %v",
						err,
					)
				}
				setMigratable(nodeVerifier, true)
				err = request()
				if require && !errors.Is(err, armtls.ErrPolicyViolation) || !require && err != nil {
					t.Fatalf(
						"inventory migration verdict: %v",
						err,
					)
				}
				setMigratable(nodeVerifier, false)
				setMigratable(cdsVerifier, true)
				err = request()
				if (err != nil) != require {
					t.Fatalf(
						"CDS migration verdict: %v",
						err,
					)
				}
				wantCalls := int64(3)
				if require {
					wantCalls = 1
				}
				if calls.Load() != wantCalls {
					t.Fatalf(
						"HTTP handler ran %d times, want %d",
						calls.Load(),
						wantCalls,
					)
				}
			},
		)
	}
}
