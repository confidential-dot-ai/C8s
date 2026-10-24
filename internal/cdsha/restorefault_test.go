package cdsha

import (
	"bytes"
	"database/sql"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A snapshot this replica's own database cannot take stops it, so it exits
// and rejoins instead of staying a voter that serves nothing. A snapshot
// that is itself unsound is refused without stopping the replica.
func TestRestoreStopsOnLocalStoreFault(t *testing.T) {
	_, opPub := operatorKey(t)
	src := newTestFSM(t, opPub)

	path := filepath.Join(t.TempDir(), "allowlist.db")
	al, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	dst := NewFSM(PreGenesis(testCluster, opPub), &al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8))
	dst.core.Policy = dst.LocalPolicy()

	if err := dst.Restore(io.NopCloser(bytes.NewReader([]byte("not a snapshot")))); err == nil {
		t.Fatal("unsound snapshot restored")
	}
	if reason := dst.Stuck(); reason != "" {
		t.Fatalf("an unsound snapshot stopped the replica: %s", reason)
	}

	lock, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	if err := restoreCopy(t, src, dst); err == nil {
		t.Fatal("restore into a locked database succeeded")
	}
	if reason := dst.Stuck(); !strings.Contains(reason, "restore snapshot") || !strings.Contains(reason, "local allowlist store") {
		t.Fatalf("stuck = %q, want the failed restore named", reason)
	}
}
