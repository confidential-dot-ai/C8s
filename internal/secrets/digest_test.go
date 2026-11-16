package secrets

import (
	"context"
	"fmt"
	"testing"
)

func TestTheSecretDigestIsTheEntriesAndNotTheOrder(t *testing.T) {
	handles, stores, _ := replicas(2, 16, 8, 64)
	ctx := context.Background()
	holders := []Holder{WorkloadHolder("web"), WorkloadHolder("api")}
	for i := range 6 {
		path := fmt.Sprintf("/p%d", i)
		writer := handles[i%len(handles)]
		if _, _, err := writer.PutIfAbsent(ctx, path, []byte("value"), holders[i%len(holders)]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := handles[1].Put(ctx, "/p3", []byte("operator")); err != nil {
		t.Fatal(err)
	}
	want := stores[0].Digest()
	if stores[1].Digest() != want {
		t.Fatal("replicas that applied the same writes differ in their digests")
	}

	entries := stores[0].Dump()
	if DigestOf(entries) != want {
		t.Fatal("the digest of the entries differs from the digest the store keeps")
	}
	restored := NewMemoryStore(16, 8, 64)
	restored.Restore(entries)
	if restored.Digest() != want {
		t.Fatal("a restored store differs from the store the snapshot came from")
	}
}

func TestTheSecretDigestNamesValuesAndHolders(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(16, 8, 64)
	local := store.Local()
	if _, _, err := local.PutIfAbsent(ctx, "/p", []byte("value"), WorkloadHolder("web")); err != nil {
		t.Fatal(err)
	}
	seeded := store.Digest()

	if _, _, err := local.PutIfAbsent(ctx, "/p", []byte("other"), WorkloadHolder("web")); err != nil {
		t.Fatal(err)
	}
	if store.Digest() != seeded {
		t.Fatal("a path that kept its first value changed its digest")
	}
	if _, err := local.Put(ctx, "/p", []byte("other")); err != nil {
		t.Fatal(err)
	}
	charged := store.Digest()
	if charged == seeded {
		t.Fatal("an operator write that replaced both the value and its holder kept the digest")
	}

	held := NewMemoryStore(16, 8, 64)
	if _, err := held.Local().Put(ctx, "/p", []byte("other")); err != nil {
		t.Fatal(err)
	}
	if held.Digest() != charged {
		t.Fatal("stores holding one path, one value and one holder differ")
	}
}
