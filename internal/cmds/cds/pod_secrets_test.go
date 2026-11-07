package cds

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type staticAllowlist struct{ al *pkgallowlist.Allowlist }

func (s staticAllowlist) Allowlist() (*pkgallowlist.Allowlist, error) { return s.al, nil }

// podSecretBroker drives the real broker client against the handler.
type podSecretBroker struct {
	h       PodSecretHandler
	quoted  []byte
	lastRaw []byte
}

func (b *podSecretBroker) GenerateEvidenceContext(_ context.Context, _ string, reportData []byte) (remote.AttestResponse, error) {
	b.quoted = bytes.Clone(reportData)
	return remote.AttestResponse{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"fake"}`)}, nil
}

func (b *podSecretBroker) PostJSON(_ context.Context, path string, body []byte) ([]byte, error) {
	if path == workloadclaims.PodSecretChallengeRoute {
		c, err := b.h.Challenges.Create()
		if err != nil {
			return nil, err
		}
		return json.Marshal(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(c[:])})
	}
	b.lastRaw = body
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", w.Code, w.Body.String())
	}
	return w.Body.Bytes(), nil
}

func pinnedPodEntry(t *testing.T, grant *pkgallowlist.SecretsPolicy) pkgallowlist.Workload {
	t.Helper()
	return pkgallowlist.Workload{Secrets: grant, Containers: []pkgallowlist.Container{{
		Digest:  wlDigest(t, wlDigestA),
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/opencode"}},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
	}}}
}

func podSecretTestHandler(t *testing.T, p workloadclaims.PodClaims, grant *pkgallowlist.SecretsPolicy) (*podSecretBroker, *mockapi.Stub, secrets.Store) {
	t.Helper()
	attest, stub := podTestHandler(t, p)
	entry := pinnedPodEntry(t, grant)
	store := secrets.NewMemoryStore(16, 8, 64).Local()
	return &podSecretBroker{h: PodSecretHandler{
		Attest:     attest,
		Challenges: attestation.NewLocalChallenges(30 * time.Second),
		Store:      store,
		Policy:     staticAllowlist{&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{"user-a": entry}}},
	}}, stub, store
}

var userAGrant = &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/users/a/**"}, Write: []string{"/users/a/**"}}

// The broker's quote binds key, challenge, claims and path; CDS mints the
// value on first request, returns the same one after, and seals both to the
// bound key; the grant names the readers the guest enforces.
func TestPodSecretReleasesGrantedPathToBoundQuote(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	broker, stub, store := podSecretTestHandler(t, p, userAGrant)
	got, err := workloadclaims.ObtainPodSecretContext(context.Background(), broker, "http://attest", "/users/a/key", p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workload != "user-a" || len(got.Readers) != 1 || got.Readers[0] != wlDigestA || len(got.Value) != secrets.GeneratedValueBytes {
		t.Fatalf("got %+v", got)
	}
	stored, _ := store.Get(context.Background(), "/users/a/key")
	if !bytes.Equal(stored, got.Value) {
		t.Fatal("released value is not the stored value")
	}
	verify := stub.VerifyRequests()
	if len(verify) != 1 || !bytes.Equal(verify[0].Params.ExpectedReportData, broker.quoted[:sha512.Size384]) {
		t.Fatal("verifier did not bind the broker's quote")
	}
	again, err := workloadclaims.ObtainPodSecretContext(context.Background(), broker, "http://attest", "/users/a/key", p)
	if err != nil || !bytes.Equal(again.Value, got.Value) {
		t.Fatalf("second release: %v", err)
	}
	// A replay spends no second release.
	w := httptest.NewRecorder()
	broker.h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, workloadclaims.PodSecretRoute, bytes.NewReader(broker.lastRaw)))
	wantRefusal(t, w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
}

func TestPodSecretRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		claims workloadclaims.PodClaims
		change func(*PodSecretHandler)
	}{
		{"other user's path", "/users/b/key", podTestClaims(t, wlDigestA), nil},
		{"no grant", "/users/a/key", podTestClaims(t, wlDigestA), func(h *PodSecretHandler) {
			e := pinnedPodEntry(t, nil)
			h.Policy = staticAllowlist{&pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{"user-a": e}}}
		}},
		{"no pod authority", "/users/a/key", podTestClaims(t, wlDigestA), func(h *PodSecretHandler) { h.Attest.PodImages = nil }},
		{"wrong launch key", "/users/a/key", podTestClaims(t, wlDigestA), func(h *PodSecretHandler) { h.Attest.PodImages[0].Anchor = []byte("x") }},
		{"image outside membership", "/users/a/key", podTestClaims(t, wlDigestA), func(h *PodSecretHandler) { h.Attest.AllowlistStore = anyArgvStore(wlDigestB) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broker, _, _ := podSecretTestHandler(t, tc.claims, userAGrant)
			if tc.change != nil {
				tc.change(&broker.h)
			}
			if _, err := workloadclaims.ObtainPodSecretContext(context.Background(), broker, "http://attest", tc.path, tc.claims); err == nil {
				t.Fatal("released")
			}
		})
	}
}
