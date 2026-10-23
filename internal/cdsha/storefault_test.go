package cdsha

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A replica whose own database cannot take a committed entry stops
// following the log instead of marking it applied and serving without it.
// A command its content makes fail, identically at every replica, is the
// entry's answer and leaves the replica serving.
func TestApplyStopsOnLocalStoreFault(t *testing.T) {
	_, opPub := operatorKey(t)
	path := filepath.Join(t.TempDir(), "allowlist.db")
	al, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	f := NewFSM(PreGenesis(testCluster, opPub), &al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8))
	f.core.Policy = f.LocalPolicy()
	consume := func(i uint64, tok string) any {
		return applyAt(f, i, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: tok}})
	}
	const t0 = int64(1_800_000_000)

	tok := expiryToken(t0, "a")
	if r, ok := consume(1, tok).(allowlist.Result); !ok || r.Err != "" {
		t.Fatalf("consume: %#v", r)
	}
	if r, ok := consume(2, tok).(allowlist.Result); !ok || !errors.Is(r.Error(), operatorauth.ErrTokenReused) {
		t.Fatalf("replayed token: %#v, want the token_reused answer", r)
	}
	if reason := f.Stuck(); reason != "" {
		t.Fatalf("a content rejection stopped the replica: %s", reason)
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
	res := consume(3, expiryToken(t0, "b"))
	if _, ok := res.(error); !ok {
		t.Fatalf("entry the local database refused: answer %#v, want an error", res)
	}
	reason := f.Stuck()
	if !strings.Contains(reason, "log entry 3") || !strings.Contains(reason, "local allowlist store") {
		t.Fatalf("stuck = %q, want the entry and the local store named", reason)
	}
	// The database recovering does not resume a replica that skipped an entry.
	if _, err := lock.Exec(`ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	consume(4, expiryToken(t0, "c"))
	if f.Stuck() != reason {
		t.Fatalf("stuck reason changed or cleared: %q", f.Stuck())
	}
}

// A leader whose state machine is stuck certifies no reads, so while it led
// no replica could serve. It hands leadership to one that follows the log.
func TestStuckLeaderTransfersLeadership(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	old := c.leader()
	if old == nil {
		t.Fatal("no leader")
	}
	old.node.fsm.stop(errors.New("test: local store fault"))
	eventually(t, 15*time.Second, "a replica that follows the log leads and serves", func() bool {
		l := c.leader()
		if l == nil || l == old || l.node.fsm.Stuck() != "" {
			return false
		}
		for _, r := range c.live() {
			if r != old && !r.node.Serving() {
				return false
			}
		}
		return true
	})
	if old.node.Serving() {
		t.Fatal("stuck replica serves")
	}
}
