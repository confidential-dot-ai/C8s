package secrets_test

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func BenchmarkCachedPolicyWarmRead(b *testing.B) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	policy := secrets.NewCachedPolicy(store.Local())
	if _, err := policy.Allowlist(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := policy.Allowlist(); err != nil {
				b.Error(err)
			}
		}
	})
}
