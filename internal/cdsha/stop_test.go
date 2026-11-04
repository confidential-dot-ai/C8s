package cdsha

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A committed entry this replica's own database could not take is not an
// answer its peers share: the replica stops serving and exits to rejoin with
// the cluster's state.
func TestAnEntryThisReplicasOwnStoreRefusedStopsItLocally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	al, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	r := newCluster(t).replica(
		t,
		al,
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)
	r.genesis()

	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Close() })
	holder.SetMaxOpenConns(1)
	if _, err := holder.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	res := r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:   allowlist.OpStartJournal,
			AtMS: time.Now().UnixMilli(),
		},
	})
	if res.Stop == nil {
		t.Fatalf("a write to a database this replica cannot reach answered %+v", res)
	}
	if !r.StuckLocal() {
		t.Fatalf("stuck %q, want a fault of this replica's own", r.Stuck())
	}
}

// An entry that panics stops this replica rather than the process: the same
// entry panics on every replica, and a crash would end them all, taking the
// in-memory log with them.
func TestAnEntryThatPanicsStopsTheReplica(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	// A store the replica no longer holds stands in for the bug: whatever
	// panics, the entry must stop this replica and not the process.
	r.ledger = nil
	res := r.apply(Entry{
		Kind: KindBinding,
		Binding: &sandboxledger.Command{
			SandboxID: "s",
			Host:      "h",
			AtMS:      time.Now().UnixMilli(),
		},
	})
	if res.Stop == nil || !strings.Contains(res.Stop.Error(), "panicked") {
		t.Fatalf("an entry over a ledger this replica does not hold answered %+v", res)
	}
	if r.Stuck() == "" || r.StuckLocal() {
		t.Fatalf("stuck %q, this replica's own fault %v: a panic is deterministic", r.Stuck(), r.StuckLocal())
	}
}

// A command that runs too long is slow, not skipped: the replica stops
// serving while it runs and follows the log again when it returns.
func TestAStallEndsWithItsCommand(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	r.Stall(errors.New("test: a command that already returned"))
	if r.Stuck() != "" {
		t.Fatalf("a stall outlived its command: %s", r.Stuck())
	}

	// What the replica's apply watchdog sees of a command that is still on.
	ended := r.began()
	r.Stall(errors.New("test: a slow disk"))
	if r.Stuck() == "" || !strings.Contains(r.Stuck(), "slow disk") {
		t.Fatalf("stuck %q", r.Stuck())
	}
	if r.StuckLocal() {
		t.Fatal("a stalled command counts as this replica's own fault: it would exit instead of waiting")
	}
	if r.ApplyingFor() == 0 {
		t.Fatal("no command is applying")
	}
	ended()

	r.apply(Entry{
		Kind:      KindFormat,
		SetFormat: baseFormat,
	})
	if r.Stuck() != "" {
		t.Fatalf("the stall did not end with the command: %s", r.Stuck())
	}
	if r.ApplyingFor() != 0 {
		t.Fatal("a command is still applying between commands")
	}
}

// A stall is the only stop a later one replaces: once the replica has a
// reason it cannot apply the log, that is the reason an operator is told.
func TestARealStopReplacesAStallAndStays(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	ended := r.began()
	r.Stall(errors.New("test: a slow disk"))
	ended()

	r.applyRaw([]byte("[1]"))
	if !strings.Contains(r.Stuck(), "decode log entry") || r.StuckLocal() {
		t.Fatalf("stuck %q, local %v", r.Stuck(), r.StuckLocal())
	}
	r.apply(Entry{
		Kind:      KindFormat,
		SetFormat: baseFormat,
	})
	if !strings.Contains(r.Stuck(), "decode log entry") {
		t.Fatalf("a later entry cleared the stop: %q", r.Stuck())
	}
}
