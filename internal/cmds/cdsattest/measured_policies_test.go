package cdsattest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// journalingProvider appends a digest to the journal while producing evidence,
// standing in for a measure that lands between the quote and the bundle.
type journalingProvider struct {
	capturingProvider
	journal, digest string
}

func (p *journalingProvider) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	if p.journal != "" {
		f, err := os.OpenFile(p.journal, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, "", "", err
		}
		defer f.Close()
		if _, err := f.WriteString(p.digest + "\n"); err != nil {
			return nil, "", "", err
		}
	}
	return p.capturingProvider.Evidence(ctx, reportData)
}

// Both bundles carry the journal as read after the evidence, and omit it when
// no journal is configured or it cannot be read.
func TestBundlesCarryMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name       string
		configured bool
		unreadable bool
		overCap    bool
		want       []string
	}{
		{name: "configured", configured: true, want: []string{p, q}},
		{name: "unset"},
		{name: "unreadable", configured: true, unreadable: true},
		{name: "over the cap", configured: true, overCap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := writeTestMeshIdentity(t)
			journal := filepath.Join(t.TempDir(), "measured-policies")
			if err := os.WriteFile(journal, []byte(p+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			prov := &journalingProvider{journal: journal, digest: q}
			cfg := Config{
				Routes:               testRoutes(t),
				Evidence:             prov,
				FrontDoorMode:        types.FrontDoorModeCDS,
				ServingCertFile:      identity.certFile,
				MeshIdentityCertFile: identity.certFile,
				MeshIdentityKeyFile:  identity.keyFile,
				MeshIdentityCAFile:   identity.caFile,
			}
			if tc.configured {
				cfg.MeasuredPoliciesFile = journal
			}
			if tc.unreadable {
				cfg.MeasuredPoliciesFile = t.TempDir() // a directory: Read fails
			}
			if tc.overCap {
				cfg.MeasuredPoliciesFile = filepath.Join(t.TempDir(), "measured-policies")
				var full strings.Builder
				for i := range armtls.MaxRuntimeExtensions + 1 {
					fmt.Fprintf(&full, "sha256:%064x\n", i)
				}
				if err := os.WriteFile(cfg.MeasuredPoliciesFile, []byte(full.String()), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			ts := httptest.NewServer(NewServer(cfg).Handler())
			defer ts.Close()

			for _, endpoint := range []string{"attest-pq", "attest-lb"} {
				// The journal starts at p each time so both see p then q.
				if err := os.WriteFile(journal, []byte(p+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				b := fetchEndpointBundle(t, ts.URL, endpoint)
				if !slices.Equal(b.MeasuredPolicies, tc.want) {
					t.Errorf("%s measured_policies = %v, want %v", endpoint, b.MeasuredPolicies, tc.want)
				}
			}
		})
	}
}

func fetchEndpointBundle(t *testing.T, base, endpoint string) types.AttestationBundle {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if endpoint == "attest-pq" {
		ck, err := overenc.GenerateClientKey()
		if err != nil {
			t.Fatal(err)
		}
		return fetchBundle(t, base, ck, nonce)
	}
	resp, err := http.Get(base + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attest-lb status = %d, want 200", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}
