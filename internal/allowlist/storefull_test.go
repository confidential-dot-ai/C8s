package allowlist

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A store that fills its volume answers 507 with a reason, not a bare 500.
func TestWriteStoreErrorFullStore(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA max_page_count = 8; CREATE TABLE t (b BLOB)"); err != nil {
		t.Fatal(err)
	}
	var full error
	for i := 0; i < 100 && full == nil; i++ {
		_, full = db.Exec("INSERT INTO t VALUES (?)", make([]byte, 4096))
	}
	if full == nil || !storeFull(full) {
		t.Fatalf("SQLITE_FULL not recognised: %v", full)
	}
	for _, e := range []error{full, errors.New("apply: " + full.Error())} {
		rec := httptest.NewRecorder()
		writeStoreError(rec, e)
		if rec.Code != http.StatusInsufficientStorage || !strings.Contains(rec.Body.String(), "full") {
			t.Fatalf("%v: %d %q", e, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	writeStoreError(rec, errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("other errors: %d", rec.Code)
	}
}
