package cds

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The store the handlers share carries each flag to the bound it names.
func TestNewSecretsStoreCarriesEachBound(t *testing.T) {
	ctx := context.Background()
	s := newSecretsStore(config{
		secretsMaxPaths:            3,
		secretsMaxPathsPerWorkload: 2,
		secretsMaxValueBytes:       8,
	}).Local()
	api, web := secrets.WorkloadHolder("api"), secrets.WorkloadHolder("web")

	if _, _, err := s.PutIfAbsent(ctx, "/api/big", make([]byte, 9), api); err == nil {
		t.Fatal("a 9-byte value was stored under --secrets-max-value-bytes=8")
	}
	if s.Len() != 0 {
		t.Fatalf("store holds %d paths after a refused value, want 0", s.Len())
	}

	for _, p := range []string{"/api/1", "/api/2"} {
		if _, _, err := s.PutIfAbsent(ctx, p, make([]byte, 8), api); err != nil {
			t.Fatalf("put %s under a quota of 2: %v", p, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/api/3", make([]byte, 8), api); !errors.Is(err, secrets.ErrHolderQuota) {
		t.Fatalf("third path for one holder = %v, want ErrHolderQuota", err)
	}

	if _, _, err := s.PutIfAbsent(ctx, "/web/1", make([]byte, 8), web); err != nil {
		t.Fatalf("another holder's first path below the ceiling: %v", err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/web/2", make([]byte, 8), web); !errors.Is(err, secrets.ErrStoreFull) {
		t.Fatalf("fourth path across holders = %v, want ErrStoreFull", err)
	}
	// The store is now at its ceiling as well, and api is still the holder its
	// own quota answers for.
	if _, _, err := s.PutIfAbsent(ctx, "/api/4", make([]byte, 8), api); !errors.Is(err, secrets.ErrHolderQuota) {
		t.Fatalf("a holder at its quota against a full store = %v, want ErrHolderQuota", err)
	}
}

// pinnedNodeImages is the node image set a measured configuration pins. The
// gate reads how many there are, not what they pin.
func pinnedNodeImages() []remote.ImagePin {
	return []remote.ImagePin{{Name: "node"}}
}

func testInventoryHosts(t *testing.T) workloadclaims.CIDRHosts {
	t.Helper()
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	return hosts
}

// A fully-configured CDS serves /secrets with no flag to turn it on: release is
// gated on an allowlist entry carrying a grant, not on configuration.
func TestSecretsEnabledWhenSandboxIdentityWorks(t *testing.T) {
	enabled, why := secretsEnabled(pinnedNodeImages(), testInventoryHosts(t))
	if !enabled {
		t.Fatalf("secrets not served on a fully configured CDS: %s", why)
	}
}

// Each of these leaves CDS unable to establish what a sandbox runs, so it must
// not answer at all rather than answer badly.
func TestSecretsDisabledWhenItCannotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		images []remote.ImagePin
		hosts  workloadclaims.CIDRHosts
		want   string
	}{
		{"no node addresses", pinnedNodeImages(), nil, "no node addresses"},
		{"no node identities", nil, testInventoryHosts(t), "pins no node identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, why := secretsEnabled(tc.images, tc.hosts)
			if enabled {
				t.Fatal("secrets served despite the prerequisite being unmet")
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("reason %q does not mention %q", why, tc.want)
			}
		})
	}
}
