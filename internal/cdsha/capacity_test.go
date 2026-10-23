package cdsha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// setAdmit sets the admission cap's three limits for one test.
func setAdmit(t *testing.T, image, header, compressed int64) {
	t.Helper()
	si, sh, sc := admitImageBytes.Load(), admitHeaderBytes.Load(), admitCompressedBytes.Load()
	admitImageBytes.Store(image)
	admitHeaderBytes.Store(header)
	admitCompressedBytes.Store(compressed)
	t.Cleanup(func() { admitImageBytes.Store(si); admitHeaderBytes.Store(sh); admitCompressedBytes.Store(sc) })
}

const unlimited = int64(1) << 50

func putEntry(t *testing.T, name string, i int) (Entry, int) {
	t.Helper()
	w := mkWorkload(t, i)
	e := Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: name, Workload: &w}}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, len(raw)
}

func TestAdmissionCapJustUnderAndOver(t *testing.T) {
	f := newTestFSM(t, nil)
	_, image, err := f.snapshotEstimate()
	if err != nil {
		t.Fatal(err)
	}
	e, n := putEntry(t, "w", 1)
	setAdmit(t, image+int64(n), unlimited, unlimited) // exactly fits the image bound
	if err := f.admit(e, n, true); err != nil {
		t.Fatalf("a write that just fits was refused: %v", err)
	}
	setAdmit(t, image+int64(n)-1, unlimited, unlimited) // one byte over
	err = f.admit(e, n, true)
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("a write one byte over the image cap: got %v, want ErrCapacity", err)
	}
	if !strings.Contains(err.Error(), "75%") || !strings.Contains(err.Error(), "--allowlist-history-bytes") {
		t.Fatalf("the refusal does not say what to do: %v", err)
	}
	// replace_all and replace_routes grow it too.
	for _, op := range []allowlist.Op{allowlist.OpReplaceAll, allowlist.OpReplaceRoutes} {
		e := Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: op}}
		if err := f.admit(e, n, true); !errors.Is(err, ErrCapacity) {
			t.Fatalf("%s over the cap: got %v, want ErrCapacity", op, err)
		}
	}
	// With nothing to add, the state at the limit is not over it: the
	// handlers' pre-token check (CheckCapacity) refuses only past it.
	setAdmit(t, image, unlimited, unlimited)
	if err := f.capacity(false, 0, true); err != nil {
		t.Fatalf("a state exactly at the image cap reported over it: %v", err)
	}
	setAdmit(t, image-1, unlimited, unlimited)
	if err := f.capacity(false, 0, true); !errors.Is(err, ErrCapacity) {
		t.Fatalf("a state over the image cap: got %v, want ErrCapacity", err)
	}
}

// The compressed bound is judged on the last snapshot's compressed size
// plus all growth since; without a measurement, the leader uses the decoded
// size and a follower leaves the bound to the leader.
func TestAdmissionCapCompressed(t *testing.T) {
	f := newTestFSM(t, nil)
	header, image, err := f.snapshotEstimate()
	if err != nil {
		t.Fatal(err)
	}
	decoded := header + image
	e, n := putEntry(t, "w", 1)
	setAdmit(t, unlimited, unlimited, decoded+int64(n)-1)
	if err := f.admit(e, n, true); !errors.Is(err, ErrCapacity) || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("unmeasured leader over the decoded size: got %v, want a compressed refusal", err)
	}
	if err := f.admit(e, n, false); err != nil {
		t.Fatalf("an unmeasured follower was stricter than the leader: %v", err)
	}
	// A snapshot measures the state: its compressed size, not the decoded
	// one, now decides, on followers too.
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	m := f.measure.Load()
	if m == nil || m.compressed != int64(buf.Len()) || m.decoded != decoded {
		t.Fatalf("measurement %+v, want compressed %d decoded %d", m, buf.Len(), decoded)
	}
	setAdmit(t, unlimited, unlimited, m.compressed+int64(n))
	for _, leader := range []bool{true, false} {
		if err := f.admit(e, n, leader); err != nil {
			t.Fatalf("leader=%v: a write that fits the measured size was refused: %v", leader, err)
		}
	}
	// Growth since the measurement counts in full, as if incompressible.
	for i := 2; ; i++ {
		if h, im, _ := f.snapshotEstimate(); h+im > decoded {
			break
		}
		w := mkWorkload(t, i)
		applyAt(f, uint64(i), Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("g%d", i), Workload: &w}})
	}
	if err := f.admit(e, n, false); !errors.Is(err, ErrCapacity) {
		t.Fatalf("growth since the measurement not counted: %v", err)
	}
	// A failed encode records nothing.
	f2 := newTestFSM(t, nil)
	s2, _ := f2.Snapshot()
	_ = s2.Persist(&memSink{Buffer: &bytes.Buffer{}, fail: true})
	if f2.measure.Load() != nil {
		t.Fatal("a failed snapshot was measured")
	}
}

// Writes that shrink the state, or that the cluster needs at the cap, are
// admitted however full it is.
func TestAdmissionCapAdmitsShrinkingAndNeededWrites(t *testing.T) {
	f := newTestFSM(t, nil)
	setAdmit(t, 0, 0, 0) // everything is over
	for _, e := range []Entry{
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpDeleteWorkload, Name: "w"}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPruneHistory, Keep: 1}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: "t"}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpSignPolicy, Body: []byte("{}")}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpSeed}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpStartJournal}},
		{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "h"}},
		{Kind: KindRenewCA, RenewCA: &RenewCAEntry{}},
		{Kind: KindDecree, Decree: &DecreeEntry{}},
	} {
		if err := f.admit(e, 1<<20, true); err != nil {
			t.Errorf("%s %v refused at the cap: %v", e.Kind, e.Allowlist, err)
		}
	}
}

func TestAdmissionCapSecrets(t *testing.T) {
	f := newTestFSM(t, nil)
	if _, err := f.secrets.Put(context.Background(), "a", []byte("12345678")); err != nil {
		t.Fatal(err)
	}
	header, _, err := f.snapshotEstimate()
	if err != nil {
		t.Fatal(err)
	}
	put := func(op secrets.Op, path, value string) error {
		e := Entry{Kind: KindSecret, Secret: &secrets.Command{Op: op, Path: path, Value: []byte(value)}}
		return f.admit(e, 100, true)
	}
	setAdmit(t, unlimited, header, unlimited) // the header is exactly at its cap
	if err := put(secrets.OpPut, "b", "x"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("a new path over the header cap: got %v, want ErrCapacity", err)
	}
	if err := put(secrets.OpPut, "a", "87654321"); err != nil {
		t.Fatalf("an overwrite of the same size was refused: %v", err)
	}
	if err := put(secrets.OpPut, "a", "1"); err != nil {
		t.Fatalf("an overwrite with a smaller value was refused: %v", err)
	}
	if err := put(secrets.OpPutIfAbsent, "a", "a longer value than before"); err != nil {
		t.Fatalf("put_if_absent on a held path (a no-op) was refused: %v", err)
	}
	if err := put(secrets.OpPut, "a", "a longer value than before"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("an overwrite that grows the value: got %v, want ErrCapacity", err)
	}
	// The compressed cap applies to secrets too; the image cap does not.
	setAdmit(t, 0, unlimited, 0)
	if err := put(secrets.OpPut, "b", "x"); !errors.Is(err, ErrCapacity) || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("a new path over the compressed cap: got %v, want ErrCapacity", err)
	}
	setAdmit(t, 0, unlimited, unlimited)
	if err := put(secrets.OpPut, "b", "x"); err != nil {
		t.Fatalf("a secret refused on the allowlist image cap: %v", err)
	}
}

// The estimate is an upper bound on what a snapshot holds.
func TestSnapshotEstimateBoundsTheSnapshot(t *testing.T) {
	f := newTestFSM(t, nil)
	for i := range 200 {
		w := mkWorkload(t, i)
		applyAt(f, uint64(i+1), Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("w%d", i), Workload: &w}})
	}
	if _, err := f.secrets.Put(context.Background(), "p/\"quoted\"", []byte("value\x00\xff")); err != nil {
		t.Fatal(err)
	}
	f.ledger.Record("sandbox", "host")
	header, image, err := f.snapshotEstimate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sn := s.(*fsmSnapshot).sn
	h, err := json.Marshal(sn)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(h)) > header || int64(len(sn.Allowlist)) > image {
		t.Fatalf("estimate header %d image %d is below the snapshot's header %d image %d", header, image, len(h), len(sn.Allowlist))
	}
}

// The cap is judged before proposing, never in Apply: Apply must decide
// alike on every replica, and the estimate is each replica's own.
func TestAdmissionCapIsNotJudgedInApply(t *testing.T) {
	f := newTestFSM(t, nil)
	setAdmit(t, 0, 0, 0)
	e, _ := putEntry(t, "w", 1)
	res := applyAt(f, 1, e)
	if r, ok := res.(allowlist.Result); !ok || r.Error() != nil {
		t.Fatalf("Apply refused a committed write: %v", res)
	}
	if ok, err := f.allowlist.Contains(mkWorkload(t, 1).Containers[0].Digest); err != nil || !ok {
		t.Fatalf("committed write not applied: %v %v", ok, err)
	}
}

func TestBackupDelay(t *testing.T) {
	base := time.Second
	for _, c := range []struct {
		fails int
		want  time.Duration
	}{{0, base}, {1, 2 * base}, {2, 4 * base}, {3, 8 * base}, {4, 16 * base}, {5, 16 * base}, {100, 16 * base}} {
		if got := backupDelay(base, c.fails); got != c.want {
			t.Errorf("backupDelay(%v, %d) = %v, want %v", base, c.fails, got, c.want)
		}
	}
	if !tooLarge(errors.New("failed to persist snapshot: "+errSnapshotTooLarge.Error())) || !tooLarge(errors.New("snapshot exceeds compressed size limit")) {
		t.Fatal("size failures not recognised through Raft's wrapping")
	}
	if tooLarge(errors.New("nothing new to snapshot")) {
		t.Fatal("an unrelated failure counted as a size failure")
	}
}

// A cluster driven to the cap keeps serving reads and storing backups, and
// refuses growth with ErrCapacity (507 at the handlers), not as
// unavailable (503), through a follower and through the leader.
func TestClusterRefusesGrowthAtCapacity(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
		}
	}
	_, image, err := l.node.fsm.snapshotEstimate()
	if err != nil {
		t.Fatal(err)
	}
	setAdmit(t, image+256<<10, admitHeaderBytes.Load(), unlimited)
	var refused error
	written := 0
	for i := 0; i < 5000 && refused == nil; i++ {
		if refused = f.al.PutWorkload(fmt.Sprintf("w%d", i), mkWorkload(t, i)); refused == nil {
			written++
		}
	}
	if refused == nil {
		t.Fatal("5000 writes never reached the cap")
	}
	t.Logf("cap reached after %d writes: %v", written, refused)
	if !errors.Is(refused, allowlist.ErrCapacity) || !errors.Is(refused, ErrCapacity) || errors.Is(refused, allowlist.ErrUnavailable) {
		t.Fatalf("follower refusal is not a capacity refusal: %v", refused)
	}
	// From here every growing write is over the cap on every replica,
	// whatever each one's page layout.
	setAdmit(t, 1, admitHeaderBytes.Load(), unlimited)
	if err := l.al.PutWorkload("via-leader", mkWorkload(t, 9999)); !errors.Is(err, allowlist.ErrCapacity) || errors.Is(err, allowlist.ErrUnavailable) {
		t.Fatalf("leader: got %v, want a capacity refusal", err)
	}
	// The leader re-checks forwarded writes: a proposer that did not check
	// (older or lagging) is refused too, and the follower rebuilds the
	// sentinel from the text.
	e, _ := putEntry(t, "forwarded", 9998)
	raw, _ := json.Marshal(e)
	resp, err := f.node.call(f.node.leaderHostPort(), testTiming.Apply, controlRequest{Op: ctlApply, Entry: raw})
	if err != nil || !errors.Is(capacityErr(resp.Err), ErrCapacity) {
		t.Fatalf("leader took a forwarded write past the cap: %v %+v", err, resp)
	}
	// Secrets: a new path is refused as capacity; an overwrite that does not
	// grow the value is taken.
	if _, err := f.sec.Put(context.Background(), "s/new", []byte("v")); err != nil {
		t.Fatalf("a secret refused on the allowlist image cap: %v", err)
	}
	// The compressed bound: the leader judges it (with its measurement or
	// the decoded size), so a follower without a snapshot cannot bypass it.
	setAdmit(t, unlimited, admitHeaderBytes.Load(), 1)
	if _, err := f.sec.Put(context.Background(), "s/new2", []byte("v")); !errors.Is(err, secrets.ErrCapacity) || errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("secret growth over the compressed cap: got %v, want secrets.ErrCapacity", err)
	}
	if err := f.node.CheckCapacity(false); !errors.Is(err, ErrCapacity) && f.node.fsm.measure.Load() != nil {
		t.Fatalf("CheckCapacity on a measured follower over the cap: %v", err)
	}
	if err := l.node.CheckCapacity(false); !errors.Is(err, ErrCapacity) {
		t.Fatalf("CheckCapacity on the leader over the cap: %v", err)
	}
	setAdmit(t, 1, admitHeaderBytes.Load(), unlimited)
	// Reads keep working everywhere, and every replica holds the same state.
	want, _, err := l.al.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "reads on "+r.name, func() bool {
			got, _, err := r.al.LoadAll()
			return err == nil && len(got.Workloads) == len(want.Workloads) && r.node.Status().Serving
		})
	}
	// Shrinking writes are taken at the cap.
	if found, err := f.al.DeleteWorkload("w0"); err != nil || !found {
		t.Fatalf("delete at the cap: %v %v", found, err)
	}
	// Backups keep being stored: one at or past the delete's index.
	idx := l.node.fsm.AppliedIndex()
	eventually(t, 10*time.Second, "backup after the refusals", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.Index >= idx
	})
	if st := l.node.Status(); st.BackupError != "" {
		t.Fatalf("backups report an error at the cap: %s", st.BackupError)
	}
}

var attemptsRE = regexp.MustCompile(`\((\d+) attempts\)`)

// A state over a snapshot size bound fails every backup. The attempts back
// off instead of dumping the whole state every interval, each is reported
// (Status.BackupError), and backups resume once the state shrinks.
func TestBackupBacksOffOnOversizedState(t *testing.T) {
	setAdmit(t, admitImageBytes.Load(), unlimited, admitCompressedBytes.Load()) // let the header past its cap
	c := newCluster(t, 1)
	c.secretLimits = [3]int{5000, 8, 4096}
	c.genesis("n0")
	l := c.leader()
	eventually(t, 10*time.Second, "first backup", func() bool { _, ok := c.backups.get(); return ok })
	// About 17 MiB of base64 values in the snapshot header: over its 16 MiB.
	v := make([]byte, 4096)
	for i := range 3200 {
		_, _ = rand.Read(v)
		if _, err := l.sec.MemoryStore.Put(context.Background(), "big/"+strconv.Itoa(i), v); err != nil {
			t.Fatal(err)
		}
	}
	// A replicated write, so the state is not backed up yet.
	if err := l.al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	attempts := func() int {
		m := attemptsRE.FindStringSubmatch(l.node.Status().BackupError)
		if m == nil {
			return 0
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	eventually(t, 10*time.Second, "backup failure reported", func() bool { return attempts() > 0 })
	// Once the back-off is at its cap (four failures: 3 s with attempts of
	// up to 0.5 s each), count the attempts in the next 7 s. At the cap of
	// 16 x 100 ms that is at most 5; without back-off, one per Timing.Backup
	// (100 ms) or per attempt (about 0.7 s under -race): 10 or more.
	time.Sleep(3 * time.Second)
	before, start := attempts(), time.Now()
	time.Sleep(7 * time.Second)
	got := attempts() - before
	t.Logf("%d backup attempts in %s (%d before)", got, time.Since(start), before)
	if got > 6 {
		t.Fatalf("%d backup attempts in %s: no back-off", got, time.Since(start))
	}
	if st := l.node.Status().BackupError; !strings.Contains(st, "exceeds the snapshot size limit") {
		t.Fatalf("status does not say why backups fail: %q", st)
	}
	// The state shrinks: backups resume and the error clears.
	l.sec.Restore(nil)
	if err := l.al.PutWorkload("w2", mkWorkload(t, 2)); err != nil {
		t.Fatal(err)
	}
	idx := l.node.fsm.AppliedIndex()
	eventually(t, 30*time.Second, "backups resumed", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.Index >= idx && l.node.Status().BackupError == ""
	})
}

// BenchmarkAdmit is the cost the cap adds to one growing write: a pragma
// query on the allowlist store and O(1) reads of the running totals.
func BenchmarkAdmit(b *testing.B) {
	al, err := allowlist.OpenInMemory()
	if err != nil {
		b.Fatal(err)
	}
	defer al.Close()
	sec := secrets.NewMemoryStore(2048, 64, 4096)
	led := sandboxledger.New(time.Hour, 20000)
	f := NewFSM(PreGenesis(testCluster, nil), &al, sec, led)
	f.core.Policy = f.LocalPolicy()
	v := make([]byte, 4096)
	for i := range 1024 {
		if _, err := sec.Put(context.Background(), "s/"+strconv.Itoa(i), v); err != nil {
			b.Fatal(err)
		}
	}
	for i := range 10000 {
		led.Record("sandbox-"+strconv.Itoa(i), "host")
	}
	t := &testing.T{}
	for i := range 500 {
		w := mkWorkload(t, i)
		applyAt(f, uint64(i+1), Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("w%d", i), Workload: &w}})
	}
	w := mkWorkload(t, 9999)
	e := Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: "x", Workload: &w}}
	raw, _ := json.Marshal(e)
	b.ResetTimer()
	for range b.N {
		if err := f.admit(e, len(raw), true); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSnapshotMemoryNearTheImageCap measures peak RSS of the snapshot
// (leader: dump, encode, open for backup) and restore (joiner: decode,
// SQLite restore) paths with an allowlist image near the image cap. It is
// a measurement for RESULTS.md, not a regression test: set
// CDSHA_MEMPROBE=1 (it builds about 190 MiB of history).
func TestSnapshotMemoryNearTheImageCap(t *testing.T) {
	if os.Getenv("CDSHA_MEMPROBE") == "" {
		t.Skip("set CDSHA_MEMPROBE=1")
	}
	f := newTestFSM(t, nil)
	target := admitImageBytes.Load() - 4<<20
	for i := 0; ; i++ {
		if i%50 == 0 {
			if n, _ := f.allowlist.LiveBytes(); n >= target {
				t.Logf("%d workloads, store %d bytes", i, n)
				break
			}
		}
		w := mkWorkload(t, i)
		applyAt(f, uint64(i+1), Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("workload-with-a-longer-name-%06d", i), Workload: &w}})
	}
	hwm := func() int64 {
		b, _ := os.ReadFile("/proc/self/status")
		m := regexp.MustCompile(`VmHWM:\s+(\d+) kB`).FindSubmatch(b)
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		return n << 10
	}
	rss := func() int64 {
		b, _ := os.ReadFile("/proc/self/status")
		m := regexp.MustCompile(`VmRSS:\s+(\d+) kB`).FindSubmatch(b)
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		return n << 10
	}
	reset := func() {
		runtime.GC()
		debug.FreeOSMemory()
		_ = os.WriteFile("/proc/self/clear_refs", []byte("5"), 0)
	}
	reset()
	base := rss()
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	image := len(s.(*fsmSnapshot).sn.Allowlist)
	s.Release()
	body := bytes.Clone(buf.Bytes()) // maybeBackup's io.ReadAll copy
	snapPeak := hwm()
	t.Logf("snapshot: image %d MiB, compressed %d MiB, RSS before %d MiB, peak %d MiB (+%d MiB)",
		image>>20, len(body)>>20, base>>20, snapPeak>>20, (snapPeak-base)>>20)
	f.allowlist.Close()
	reset()
	base = rss()
	to := newTestFSM(t, nil)
	sn, err := decodeSnapshot(bytes.NewReader(body), Format, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := to.allowlist.Restore(sn.Allowlist); err != nil {
		t.Fatal(err)
	}
	restorePeak := hwm()
	t.Logf("restore: RSS before %d MiB, peak %d MiB (+%d MiB)", base>>20, restorePeak>>20, (restorePeak-base)>>20)
}
