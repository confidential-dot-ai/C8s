package allowlist_test

import (
	"testing"

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
