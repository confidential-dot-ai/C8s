package cds

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The shipped flag defaults must satisfy the relation CDS starts on.
func TestSecretsPathQuotaFlagIsWired(t *testing.T) {
	flags := NewCmd().Flags()
	quota := flags.Lookup("secrets-max-paths-per-workload")
	if quota == nil {
		t.Fatal("missing --secrets-max-paths-per-workload flag")
	}
	ceiling := flags.Lookup("secrets-max-paths")
	if ceiling == nil {
		t.Fatal("missing --secrets-max-paths flag")
	}
	value := flags.Lookup("secrets-max-value-bytes")
	if value == nil {
		t.Fatal("missing --secrets-max-value-bytes flag")
	}
	cfg := secretsReadyConfig()
	cfg.secretsMaxPaths = mustAtoi(t, ceiling.DefValue)
	cfg.secretsMaxPathsPerWorkload = mustAtoi(t, quota.DefValue)
	cfg.secretsMaxValueBytes = mustAtoi(t, value.DefValue)
	if err := validateSecretsConfig(cfg); err != nil {
		t.Fatalf("the shipped flag defaults refuse to start CDS: %v", err)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("flag default %q is not an int: %v", s, err)
	}
	return n
}

// The store the handlers share carries each flag to the bound it names.
func TestNewSecretsStoreCarriesEachBound(t *testing.T) {
	ctx := context.Background()
	s := newSecretsStore(config{
		secretsMaxPaths:            3,
		secretsMaxPathsPerWorkload: 2,
		secretsMaxValueBytes:       8,
	})
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

// secretsReadyConfig can serve /secrets: sandbox identity is fully configured.
func secretsReadyConfig() config {
	return config{
		armtlsPlatform:             "sev-snp",
		measurements:               []string{strings.Repeat("ab", 48)},
		inventoryCIDRs:             []string{"10.0.0.0/24"},
		secretsMaxPaths:            16,
		secretsMaxPathsPerWorkload: 8,
		secretsMaxValueBytes:       64,
		sandboxLedgerMax:           16,
	}
}

func testInventoryHosts(t *testing.T) workloadclaims.InventoryHosts {
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
	enabled, why := secretsEnabled(secretsReadyConfig(), &workloadclaims.DigestsClient{}, testInventoryHosts(t))
	if !enabled {
		t.Fatalf("secrets not served on a fully configured CDS: %s", why)
	}
}

// Each of these leaves CDS unable to establish what a sandbox runs, so it must
// not answer at all rather than answer badly.
func TestSecretsDisabledWhenItCannotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    func(*config)
		client *workloadclaims.DigestsClient
		want   string
	}{
		{"no platform", func(*config) {}, nil, "--armtls-platform"},
		{"no measurements", func(c *config) { c.measurements = nil }, &workloadclaims.DigestsClient{}, "--measurements"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsReadyConfig()
			tc.cfg(&cfg)
			enabled, why := secretsEnabled(cfg, tc.client, testInventoryHosts(t))
			if enabled {
				t.Fatal("secrets served despite the prerequisite being unmet")
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("reason %q does not mention %q", why, tc.want)
			}
		})
	}
}

// Without a bound there is nothing constraining which address the callback
// may dial.
func TestSecretsDisabledWithoutInventoryCIDRs(t *testing.T) {
	enabled, why := secretsEnabled(secretsReadyConfig(), &workloadclaims.DigestsClient{}, nil)
	if enabled || !strings.Contains(why, "no node addresses") {
		t.Fatalf("enabled=%v reason=%q", enabled, why)
	}
}

func TestSecretsSizingMustBePositive(t *testing.T) {
	for _, tc := range []struct {
		flag string
		brk  func(*config)
	}{
		{"--secrets-max-paths", func(c *config) { c.secretsMaxPaths = 0 }},
		{"--secrets-max-paths-per-workload", func(c *config) { c.secretsMaxPathsPerWorkload = 0 }},
		{"--secrets-max-value-bytes", func(c *config) { c.secretsMaxValueBytes = 0 }},
		{"--sandbox-ledger-max-entries", func(c *config) { c.sandboxLedgerMax = 0 }},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			cfg := secretsReadyConfig()
			tc.brk(&cfg)
			err := validateSecretsConfig(cfg)
			if err == nil {
				t.Fatalf("%s was accepted at zero", tc.flag)
			}
			if !strings.Contains(err.Error(), tc.flag) {
				t.Fatalf("%s at zero reported %q, want the flag named", tc.flag, err)
			}
		})
	}
	if err := validateSecretsConfig(secretsReadyConfig()); err != nil {
		t.Fatalf("valid bounds refused: %v", err)
	}
}

func TestSecretsQuotaMustStayBelowTheCeiling(t *testing.T) {
	for _, tc := range []struct {
		name  string
		quota func(ceiling int) int
	}{
		{"at the ceiling", func(ceiling int) int { return ceiling }},
		{"above the ceiling", func(ceiling int) int { return ceiling + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsReadyConfig()
			cfg.secretsMaxPathsPerWorkload = tc.quota(cfg.secretsMaxPaths)
			err := validateSecretsConfig(cfg)
			if err == nil {
				t.Fatalf("--secrets-max-paths-per-workload=%d was accepted against --secrets-max-paths=%d", cfg.secretsMaxPathsPerWorkload, cfg.secretsMaxPaths)
			}
			if want := "--secrets-max-paths-per-workload (%d) must be below --secrets-max-paths"; !strings.Contains(err.Error(), fmt.Sprintf(want, cfg.secretsMaxPathsPerWorkload)) {
				t.Fatalf("err = %q, want the quota/ceiling check", err)
			}
		})
	}
	cfg := secretsReadyConfig()
	cfg.secretsMaxPathsPerWorkload = cfg.secretsMaxPaths - 1
	if err := validateSecretsConfig(cfg); err != nil {
		t.Fatalf("a quota one below the ceiling refused: %v", err)
	}
}

// Generate always mints GeneratedValueBytes, so a smaller cap turns every
// workload's first POST into a 500 rather than refusing at startup.
func TestSecretsValueBoundHoldsAGeneratedValue(t *testing.T) {
	cfg := secretsReadyConfig()
	cfg.secretsMaxValueBytes = secrets.GeneratedValueBytes - 1
	err := validateSecretsConfig(cfg)
	if err == nil {
		t.Fatalf("--secrets-max-value-bytes=%d was accepted below a generated value", cfg.secretsMaxValueBytes)
	}
	if !strings.Contains(err.Error(), "--secrets-max-value-bytes") {
		t.Fatalf("err = %q, want the value-bytes check", err)
	}
	cfg.secretsMaxValueBytes = secrets.GeneratedValueBytes
	if err := validateSecretsConfig(cfg); err != nil {
		t.Fatalf("a cap exactly fitting a generated value refused: %v", err)
	}
}
