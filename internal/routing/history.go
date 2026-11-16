package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// historyCacheSize bounds the allowlist documents entryDocs keeps by digest.
// A leaf stamped under an older document costs one fetch.
const historyCacheSize = 16

// AllowlistHistory reads a document of the CDS's allowlist history by digest
// (GET /allowlist/objects/sha256/<hex>). The caller supplies a source that
// verifies the CDS (A1) and refuses bytes that hash to another digest.
type AllowlistHistory interface {
	Object(ctx context.Context, digest [sha256.Size]byte) (*allowlist.Allowlist, error)
}

// entryDocs holds allowlist documents by digest as the canonical JSON of each
// entry, so two documents can be compared entry by entry (B8). It is safe for
// concurrent use.
type entryDocs struct {
	src AllowlistHistory

	// fetch serializes history fetches, so a burst of dials under one
	// digest costs one.
	fetch sync.Mutex

	mu    sync.Mutex
	docs  map[string]map[string][]byte
	order []string // digests, oldest first
}

// sameEntry returns nil when entry name has the same canonical content in the
// documents whose digests are a and b. A document that cannot be fetched, or
// that lacks the entry, fails.
func (d *entryDocs) sameEntry(ctx context.Context, name string, a, b []byte) error {
	ea, err := d.entry(ctx, name, a)
	if err != nil {
		return err
	}
	eb, err := d.entry(ctx, name, b)
	if err != nil {
		return err
	}
	if !bytes.Equal(ea, eb) {
		return fmt.Errorf("entry %q differs between allowlists %x and %x", name, a, b)
	}
	return nil
}

func (d *entryDocs) entry(ctx context.Context, name string, digest []byte) ([]byte, error) {
	doc, err := d.document(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("allowlist %x: %w", digest, err)
	}
	e, ok := doc[name]
	if !ok {
		return nil, fmt.Errorf("allowlist %x has no entry %q", digest, name)
	}
	return e, nil
}

func (d *entryDocs) document(ctx context.Context, digest []byte) (map[string][]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("digest is %d bytes, want %d", len(digest), sha256.Size)
	}
	if doc := d.cached(digest); doc != nil {
		return doc, nil
	}
	d.fetch.Lock()
	defer d.fetch.Unlock()
	if doc := d.cached(digest); doc != nil {
		return doc, nil
	}
	al, err := d.src.Object(ctx, [sha256.Size]byte(digest))
	if err != nil {
		return nil, fmt.Errorf("fetch from the CDS's history: %w", err)
	}
	doc := make(map[string][]byte, len(al.Workloads))
	for name, w := range al.Workloads {
		// The canonical document marshals each entry the same way.
		b, err := json.Marshal(w)
		if err != nil {
			return nil, err
		}
		doc[name] = b
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.docs == nil {
		d.docs = map[string]map[string][]byte{}
	}
	d.docs[string(digest)] = doc
	d.order = append(d.order, string(digest))
	if len(d.order) > historyCacheSize {
		delete(d.docs, d.order[0])
		d.order = d.order[1:]
	}
	return doc, nil
}

func (d *entryDocs) cached(digest []byte) map[string][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.docs[string(digest)]
}
