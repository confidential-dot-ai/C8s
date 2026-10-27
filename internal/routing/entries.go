package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

// defaultRefreshGap is Entries.refreshGap.
const defaultRefreshGap = 5 * time.Second

// historyCacheSize bounds the allowlist documents Entries keeps by digest.
// Leaves stamped under older documents than these cost one fetch each.
const historyCacheSize = 16

// errEntryChanged fails a workload backend, or a bound session, whose
// allowlist entry the router cannot find unchanged in the current allowlist
// (B8): the entry was removed or redefined, or the stamped document is not
// available to compare.
var errEntryChanged = errors.New("routing: allowlist entry changed")

// AllowlistSource reads the allowlist CDS serves now, and the documents of
// its history by digest. The caller supplies a source that verifies the CDS
// (A1).
type AllowlistSource interface {
	FetchServed(ctx context.Context, ifNoneMatch string) (allowlistclient.Served, bool, error)
	Object(ctx context.Context, digest [sha256.Size]byte) (*allowlist.Allowlist, error)
}

// allowlistDoc is one allowlist document: its digest, the raw SHA-256 a leaf's
// matched-workload stamp carries, and the canonical JSON of each entry.
type allowlistDoc struct {
	digest  string
	entries map[string][]byte
}

func newAllowlistDoc(digest string, al *allowlist.Allowlist) (*allowlistDoc, error) {
	s := &allowlistDoc{digest: digest, entries: make(map[string][]byte, len(al.Workloads))}
	for name, w := range al.Workloads {
		// The document's canonical form marshals each entry the same way.
		b, err := json.Marshal(w)
		if err != nil {
			return nil, err
		}
		s.entries[name] = b
	}
	return s, nil
}

// Entries holds the allowlist the CDS serves now and checks allowlist
// entries against it: a leaf stamped under an older document passes while its
// entry is unchanged in the current one (B8). It is safe for concurrent use.
type Entries struct {
	src AllowlistSource
	// refreshGap is the least time between the rereads of the current
	// allowlist that a failed check triggers.
	refreshGap time.Duration

	// refresh serializes Refresh, so an older answer never replaces a newer.
	refresh sync.Mutex

	mu         sync.Mutex
	current    *allowlistDoc
	etag       string
	refreshed  time.Time     // the last Refresh attempt
	reconciled *allowlistDoc // the document Changed last compared against
	history    map[string]*allowlistDoc
	order      []string // history digests, oldest first

	// fetch serializes history fetches, so a burst of dials under one old
	// digest costs one.
	fetch sync.Mutex
}

// NewEntries returns Entries reading from src. Until the first Refresh it
// has no current allowlist and every check fails.
func NewEntries(src AllowlistSource) *Entries {
	return &Entries{src: src, refreshGap: defaultRefreshGap, history: map[string]*allowlistDoc{}}
}

// Refresh fetches the current allowlist; a failed fetch keeps the previous
// one.
func (e *Entries) Refresh(ctx context.Context) error {
	e.refresh.Lock()
	defer e.refresh.Unlock()
	e.mu.Lock()
	etag := e.etag
	e.refreshed = time.Now()
	e.mu.Unlock()
	served, notModified, err := e.src.FetchServed(ctx, etag)
	if err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	if notModified {
		return nil
	}
	digest, ok := cutSHA256(served.Digest)
	if !ok {
		return fmt.Errorf("allowlist: malformed digest %q", served.Digest)
	}
	next, err := newAllowlistDoc(digest, served.Allowlist)
	if err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current, e.etag = next, served.ETag
	e.remember(next)
	return nil
}

// Changed returns the entries the current allowlist removed or redefined
// since the document the previous call saw, none on the first call.
func (e *Entries) Changed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev, next := e.reconciled, e.current
	e.reconciled = next
	if prev == nil || next == nil || prev.digest == next.digest {
		return nil
	}
	var changed []string
	for name, old := range prev.entries {
		if cur, ok := next.entries[name]; !ok || !bytes.Equal(old, cur) {
			changed = append(changed, name)
		}
	}
	slices.Sort(changed)
	return changed
}

// Digest is the current allowlist's digest, empty before the first Refresh.
func (e *Entries) Digest() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current == nil {
		return ""
	}
	return e.current.digest
}

// Check returns nil when entry name is in the current allowlist with the
// same canonical content as in the document whose digest is stamped. When
// stamped is the current digest nothing is fetched; otherwise the stamped
// document comes from the CDS's allowlist history, and a failed fetch fails
// the check. A leaf can be stamped under a document newer than the one the
// router last read, so a failed check under another digest rereads the
// current allowlist, at most once per refreshGap, and checks again.
func (e *Entries) Check(ctx context.Context, stamped, name string) error {
	if e == nil {
		return fmt.Errorf("%w: the router reads no allowlist", errEntryChanged)
	}
	err := e.check(ctx, stamped, name)
	if err == nil || e.Digest() == stamped || !e.refreshDue() {
		return err
	}
	if rerr := e.Refresh(ctx); rerr != nil {
		return err
	}
	return e.check(ctx, stamped, name)
}

// Bound returns the canonical content of entry name in the document whose
// digest a session bound, once Check found it unchanged in the current
// allowlist (E6). A backend serving the session must match it (B8).
func (e *Entries) Bound(ctx context.Context, bound, name string) ([]byte, error) {
	if err := e.Check(ctx, bound, name); err != nil {
		return nil, err
	}
	doc, err := e.document(ctx, bound)
	if err != nil {
		return nil, fmt.Errorf("%w: allowlist %x: %w", errEntryChanged, bound, err)
	}
	return doc.entries[name], nil
}

// Matches returns nil when entry name in the document whose digest is
// stamped has the canonical content want, which Bound returned. It compares
// the two documents directly: the current allowlist does not decide it.
func (e *Entries) Matches(ctx context.Context, stamped, name string, want []byte) error {
	if e == nil {
		return fmt.Errorf("%w: the router reads no allowlist", errEntryChanged)
	}
	doc, err := e.document(ctx, stamped)
	if err != nil {
		return fmt.Errorf("%w: allowlist %x: %w", errEntryChanged, stamped, err)
	}
	if got, ok := doc.entries[name]; !ok || !bytes.Equal(got, want) {
		return fmt.Errorf("%w: entry %q under allowlist %x differs from the session's bound allowlist", errEntryChanged, name, stamped)
	}
	return nil
}

func (e *Entries) refreshDue() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.refreshed) >= e.refreshGap
}

func (e *Entries) check(ctx context.Context, stamped, name string) error {
	e.mu.Lock()
	current := e.current
	e.mu.Unlock()
	if current == nil {
		return fmt.Errorf("%w: no current allowlist from the CDS yet", errEntryChanged)
	}
	entry, ok := current.entries[name]
	if !ok {
		return fmt.Errorf("%w: entry %q is not in the current allowlist %x", errEntryChanged, name, current.digest)
	}
	if stamped == current.digest {
		return nil
	}
	old, err := e.document(ctx, stamped)
	if err != nil {
		return fmt.Errorf("%w: allowlist %x: %w", errEntryChanged, stamped, err)
	}
	if !bytes.Equal(old.entries[name], entry) {
		return fmt.Errorf("%w: entry %q under allowlist %x differs from the current allowlist %x", errEntryChanged, name, stamped, current.digest)
	}
	return nil
}

// document returns the document with digest, from the cache or the CDS.
func (e *Entries) document(ctx context.Context, digest string) (*allowlistDoc, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("digest is %d bytes, want %d", len(digest), sha256.Size)
	}
	if s := e.cached(digest); s != nil {
		return s, nil
	}
	e.fetch.Lock()
	defer e.fetch.Unlock()
	if s := e.cached(digest); s != nil {
		return s, nil
	}
	al, err := e.src.Object(ctx, [sha256.Size]byte([]byte(digest)))
	if err != nil {
		return nil, fmt.Errorf("fetch from the CDS's history: %w", err)
	}
	s, err := newAllowlistDoc(digest, al)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remember(s)
	return s, nil
}

func (e *Entries) cached(digest string) *allowlistDoc {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.history[digest]
}

// remember adds s to the history cache, evicting the oldest document beyond
// historyCacheSize. The caller holds e.mu.
func (e *Entries) remember(s *allowlistDoc) {
	if _, ok := e.history[s.digest]; ok {
		return
	}
	e.history[s.digest] = s
	e.order = append(e.order, s.digest)
	if len(e.order) > historyCacheSize {
		delete(e.history, e.order[0])
		e.order = e.order[1:]
	}
}

// cutSHA256 returns the raw digest of "sha256:<hex>".
func cutSHA256(s string) (string, bool) {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return "", false
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size {
		return "", false
	}
	return string(b), true
}
