package secrets

import (
	"fmt"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

type fakeAllowlistStore struct {
	version    string
	versionErr error
	loadErr    error
	loads      int
	versions   int
}

func (f *fakeAllowlistStore) Version() (string, error) {
	f.versions++
	return f.version, f.versionErr
}

func (f *fakeAllowlistStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	f.loads++
	if f.loadErr != nil {
		return nil, "", f.loadErr
	}
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}, f.version, nil
}

// The document is loaded once and reused while the version counter holds still:
// LoadAll is a full scan plus a JSON unmarshal per entry, and every request
// needs the whole document.
func TestCachedPolicyReusesWhileVersionHolds(t *testing.T) {
	store := &fakeAllowlistStore{version: "7"}
	p := NewCachedPolicy(store)

	first, err := p.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		again, err := p.Allowlist()
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatal("a cached document was rebuilt while the version held")
		}
	}
	if store.loads != 1 {
		t.Fatalf("LoadAll called %d times, want 1", store.loads)
	}
	if store.versions != 5 {
		t.Fatalf("Version called %d times, want one per request", store.versions)
	}
}

// An operator write moves the counter, and the next request sees the new
// document.
func TestCachedPolicyReloadsOnVersionChange(t *testing.T) {
	store := &fakeAllowlistStore{version: "7"}
	p := NewCachedPolicy(store)

	first, _ := p.Allowlist()
	store.version = "8"
	second, err := p.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("a changed version did not reload the document")
	}
	if store.loads != 2 {
		t.Fatalf("LoadAll called %d times, want 2", store.loads)
	}
}

func TestCachedPolicyPropagatesErrors(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		p := NewCachedPolicy(&fakeAllowlistStore{versionErr: fmt.Errorf("boom")})
		if _, err := p.Allowlist(); err == nil {
			t.Fatal("a version error was swallowed")
		}
	})
	t.Run("load", func(t *testing.T) {
		p := NewCachedPolicy(&fakeAllowlistStore{version: "1", loadErr: fmt.Errorf("boom")})
		if _, err := p.Allowlist(); err == nil {
			t.Fatal("a load error was swallowed")
		}
	})
}
