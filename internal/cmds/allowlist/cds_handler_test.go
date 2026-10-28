package allowlist

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	cdsallowlist "github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// realCDS serves the CDS allowlist handler over a real store. race, when set,
// runs once before the first whole-document write is handled.
func realCDS(t *testing.T, pub *ecdsa.PublicKey, race func(*cdsallowlist.Store)) (*httptest.Server, *cdsallowlist.Store) {
	t.Helper()
	store, err := cdsallowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	h := cdsallowlist.Handler{
		Store:           &store,
		WriteAuthorizer: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}.Authorize,
	}
	var once sync.Once
	r := chi.NewRouter()
	r.Get("/allowlist", h.HandleList)
	r.Get("/allowlist/history", h.HandleHistory)
	r.Put("/allowlist", func(w http.ResponseWriter, req *http.Request) {
		if race != nil {
			once.Do(func() { race(&store) })
		}
		h.HandleReplaceAll(w, req)
	})
	r.Put("/allowlist/workloads/{name}", h.HandlePutWorkload)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, &store
}

// apply against the CDS handler: the served document round-trips, so the
// entries it does not name go back unchanged, and the strong If-Match it
// sends is the one CDS checks.
func TestApplyAgainstCDSHandler(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, store := realCDS(t, pub, nil)
	if err := store.PutWorkload("keep", workloadOf(t, 5)); err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{{"web"}, {"web", "api"}} {
		file := writeFile(t, "doc.json", entryMap(names...))
		if _, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
			t.Fatalf("apply %v: %v", names, err)
		}
	}
	al, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keep", "web", "api"} {
		if _, ok := al.Workloads[name]; !ok {
			t.Fatalf("entry %s missing after apply: %v", name, al.Workloads)
		}
	}
}

// The CDS handler refuses the first write with 412; apply re-reads, puts its
// entry into the newer document, and the second write keeps the racing entry.
func TestApplyAgainstCDSHandlerKeepsARacingWrite(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, store := realCDS(t, pub, func(s *cdsallowlist.Store) {
		if err := s.PutWorkload("racer", workloadOf(t, 6)); err != nil {
			t.Error(err)
		}
	})
	file := writeFile(t, "doc.json", entryMap("web"))
	_, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("apply after a racing write to another entry: %v", err)
	}
	al, _, _ := store.LoadAll()
	if _, ok := al.Workloads["racer"]; !ok {
		t.Fatal("the racing write was overwritten")
	}
	if _, ok := al.Workloads["web"]; !ok {
		t.Fatal("the applied entry is missing")
	}
}
