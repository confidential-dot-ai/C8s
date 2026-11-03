package secrets_test

import (
	"strings"
	"testing"

	store "github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestCachedPolicyReloadsSameVersionRestoreAndFailsClosedOnClose(t *testing.T) {
	open := func(name string) *store.Store {
		s, err := store.OpenInMemory()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		digest, err := types.ParseDigest("sha256:" + strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		policy := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema,
			Workloads: map[string]pkgallowlist.Workload{name: {Containers: []pkgallowlist.Container{{Digest: digest}}}}}
		if err := s.Local().ReplaceAll(policy, store.OperatorWrite{}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	original, restored := open("old-grant"), open("replacement-policy")
	before, _ := original.Version()
	after, _ := restored.Version()
	if before != after {
		t.Fatal("test requires identical persisted versions")
	}
	cached := secrets.NewCachedPolicy(original.Local())
	if _, err := cached.Allowlist(); err != nil {
		t.Fatal(err)
	}
	image, err := restored.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Restore(image, restored.Digest()); err != nil {
		t.Fatal(err)
	}
	policy, err := cached.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	if _, stale := policy.Workloads["old-grant"]; stale {
		t.Fatal("restore reused the old grant")
	}
	if _, exists := policy.Workloads["replacement-policy"]; !exists {
		t.Fatal("restored policy missing")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.Allowlist(); err == nil {
		t.Fatal("closed store served a cached grant")
	}
}
