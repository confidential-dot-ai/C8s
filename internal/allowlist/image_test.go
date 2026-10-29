package allowlist

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A database image restores an identical store; an unsound one leaves the
// store as it was.
func TestSnapshotRoundTrip(t *testing.T) {
	store, source := openJournaledStore(t)
	for _, name := range []string{"web", "gone", "db"} {
		putEntry(t, source, name, oneContainerWorkload(mustParseDigest(t, digestA)))
	}
	deleteEntry(t, source, "gone") // a rowid gap
	token := tokenAt(t0, "snapshot")
	if err := source.ConsumeToken(token); err != nil {
		t.Fatal(err)
	}
	image, err := store.Dump()
	if err != nil {
		t.Fatal(err)
	}

	file, err := OpenStore(filepath.Join(t.TempDir(), "allowlist.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	memory, _ := openInMemoryStore(t)
	for name, fresh := range map[string]*Store{
		"memory": memory,
		"file":   file,
	} {
		generation := fresh.Generation()
		if err := fresh.Restore(image); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, want := contents(t, fresh), contents(t, store); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the restored store differs:\n%v\nvs\n%v", name, got, want)
		}
		if fresh.Generation() == generation {
			t.Fatalf("%s: the restore left cached views valid", name)
		}
		if err := fresh.Local().ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("%s: the restored store forgot a spent token", name)
		}
		before := contents(t, fresh)
		for what, image := range map[string][]byte{
			"garbage":   []byte("not a database"),
			"truncated": image[:len(image)/2],
			"bad page":  badPage(image),
		} {
			if err := fresh.Restore(image); err == nil {
				t.Errorf("%s: a %s image was restored", name, what)
			}
		}
		if !reflect.DeepEqual(contents(t, fresh), before) {
			t.Fatalf("%s: a refused image changed the store", name)
		}
	}
}

// A restored store serves the document the image held, under its version.
func TestRestoredStoreServesTheImagesDocument(t *testing.T) {
	store, source := openJournaledStore(t)
	putEntry(t, source, "web", oneContainerWorkload(mustParseDigest(t, digestA)))
	want, wantVersion, err := source.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	image, err := store.Dump()
	if err != nil {
		t.Fatal(err)
	}

	empty, fresh := openInMemoryStore(t)
	putEntry(t, fresh, "other", oneContainerWorkload(mustParseDigest(t, digestB)))
	if err := empty.Restore(image); err != nil {
		t.Fatal(err)
	}
	got, version, err := fresh.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if version != wantVersion || !reflect.DeepEqual(got, want) {
		t.Fatalf("restored %v at version %s, want %v at %s", got, version, want, wantVersion)
	}
	if _, ok := got.Workloads["other"]; ok {
		t.Fatal("an entry the restored store held survived the restore")
	}
}

// Dump leaves the store readable and writable.
func TestDumpLeavesTheStoreServing(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	putEntry(t, allowlist, "web", oneContainerWorkload(mustParseDigest(t, digestA)))
	if _, err := store.Dump(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := allowlist.LoadAll(); err != nil {
		t.Fatal(err)
	}
	if err := allowlist.ReplaceAll(
		&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema},
		OperatorWrite{},
	); err != nil {
		t.Fatal(err)
	}
}

// badPage is image with the b-tree page type of its last page overwritten.
func badPage(image []byte) []byte {
	const pageSizeAt = 16 // the database header's page-size field
	pageSize := int(binary.BigEndian.Uint16(image[pageSizeAt : pageSizeAt+2]))
	b := slices.Clone(image)
	b[len(b)-pageSize] = 0xee
	return b
}
