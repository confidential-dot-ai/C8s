package getkubeconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

// The fresh gate replays the list the /attest response carries, read after
// the quote, so a node that measured a policy after its leaf was minted still
// passes; without that list it falls back to the leaf's lagging one.
func TestAttestResponseListSupersedesLeaf(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name     string
		response []string
		wantErr  bool
	}{
		{name: "response lists the new policy", response: []string{p, q}},
		{name: "response carries no list", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			res := verifiedResultFor(env.operatorPubPEM)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.operatorPubPEM), []string{p, q})
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			stubVerify(t, res, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(credrelease.AttestResponse{
					AttestationEvidence: teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)},
					RuntimeExtensions:   tc.response,
				})
			}))
			defer srv.Close()
			keyPEM, err := os.ReadFile(env.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			exp := env.exp
			exp = exp.WithMeasuredPolicies([]string{p}) // the leaf predates q

			err = attestCredentialRelease(context.Background(), srv.Client(), srv.URL, keyPEM, exp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("attestCredentialRelease = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
