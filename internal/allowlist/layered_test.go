package allowlist_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	layerDigestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	layerDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func anyEntry(t *testing.T, label, digest string) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Label: label, Containers: []pkgallowlist.Container{{
		Digest:  d,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
	}}}
}

func doc(workloads map[string]pkgallowlist.Workload) *pkgallowlist.Allowlist {
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}
}

// The seed's entry wins a name both layers hold, a nil seed is the stored
// document, and every other entry of either layer decides.
func TestCombine(t *testing.T) {
	stored := doc(map[string]pkgallowlist.Workload{
		"app": anyEntry(t, "app", layerDigestA),
		"cds": anyEntry(t, "operator-cds", layerDigestA),
	})
	seed := doc(map[string]pkgallowlist.Workload{"cds": anyEntry(t, "seed-cds", layerDigestB)})

	if got := allowlist.Combine(stored, nil); got != stored {
		t.Errorf("Combine(stored, nil) is not stored")
	}
	got := allowlist.Combine(stored, seed)
	if len(got.Workloads) != 2 || got.Workloads["app"].Label != "app" || got.Workloads["cds"].Label != "seed-cds" {
		t.Errorf("Combine = %v, want app from the store and cds from the seed", got.Workloads)
	}
}

// GET /allowlist serves the stored document alone and names the seed layer
// in its header; the objects route serves the seed's canonical bytes by
// digest. Without a seed layer neither happens.
func TestHandlerServesSeedLayer(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stored := doc(map[string]pkgallowlist.Workload{"app": anyEntry(t, "app", layerDigestA)})
	if err := store.ReplaceAll(stored); err != nil {
		t.Fatal(err)
	}
	seed := doc(map[string]pkgallowlist.Workload{"cds": anyEntry(t, "cds", layerDigestB)})
	seedBody, err := seed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(seedBody)
	seedHex := hex.EncodeToString(sum[:])
	none, err := allowlist.NewLayered(&store, nil)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := allowlist.NewLayered(&store, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := layers.SeedDigest(); got != "sha256:"+seedHex {
		t.Fatalf("SeedDigest %s, want sha256:%s", got, seedHex)
	}
	storedBody, err := stored.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		layers *allowlist.Layered
		header string
		object bool
	}{
		{name: "no seed layer", layers: none},
		{name: "seed layer", layers: layers, header: "sha256:" + seedHex, object: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := allowlist.Handler{Store: &store, Layers: tc.layers}
			list := httptest.NewRecorder()
			h.HandleList(list, httptest.NewRequest(http.MethodGet, "/allowlist", nil))
			if got := list.Header().Get(pkgallowlist.SeedHeader); got != tc.header {
				t.Errorf("seed header %q, want %q", got, tc.header)
			}
			if !bytes.Equal(list.Body.Bytes(), storedBody) {
				t.Errorf("GET /allowlist served %s, want the stored document", list.Body.Bytes())
			}

			router := chi.NewRouter()
			router.Get("/allowlist/objects/sha256/{hex}", h.HandleObject)
			obj := httptest.NewRecorder()
			router.ServeHTTP(obj, httptest.NewRequest(http.MethodGet, "/allowlist/objects/sha256/"+seedHex, nil))
			if got := obj.Code == http.StatusOK && bytes.Equal(obj.Body.Bytes(), seedBody); got != tc.object {
				t.Errorf("seed object served = %t (status %d), want %t", got, obj.Code, tc.object)
			}
		})
	}
}
