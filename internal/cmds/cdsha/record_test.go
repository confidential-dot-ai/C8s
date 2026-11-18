package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

func TestAcknowledgeRetriesPersistence(t *testing.T) {
	for name, seq := range map[string]uint64{"equal head": 5, "older head": 4} {
		t.Run(name, func(t *testing.T) {
			o := &options{
				stateDir: filepath.Join(
					t.TempDir(),
					"new",
					"state",
				),
			}
			genesis := cdschain.Hash{9}
			head := cdschain.Head{
				V:       cdschain.Version,
				Cluster: "lane",
				Seq:     5,
				Hash:    cdschain.Hash{5},
			}
			injected := errors.New("record sync failed")
			calls := 0
			persist := func(path string, data []byte, mode os.FileMode) error {
				calls++
				var rec record
				if err := json.Unmarshal(data, &rec); err != nil || rec.Acknowledged != head {
					t.Fatal("retry changed the retained highest head")
				}
				if err := fileutil.WriteAtomic(path, data, mode); err != nil {
					t.Fatal(err)
				}
				return injected
			}
			o.persist = persist
			if err := o.acknowledge(genesis, head); !errors.Is(err, injected) {
				t.Fatal("persistence failure was hidden")
			}
			retry := head
			retry.Seq = seq
			retry.Hash = cdschain.Hash{byte(seq)}
			if err := o.acknowledge(genesis, retry); !errors.Is(err, injected) || calls != 2 {
				t.Fatal("visible record bypassed a retry of persistence")
			}
			o.persist = nil
			if err := o.acknowledge(genesis, retry); err != nil {
				t.Fatal(err)
			}
			rec, err := o.record(head.Cluster)
			if err != nil || rec == nil || rec.Acknowledged != head {
				t.Fatal("retry lost the highest head")
			}
			path, err := o.recordPath(head.Cluster)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("record permissions are not 0600")
			}
			info, err = os.Stat(filepath.Dir(path))
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatal("new state directory permissions are not 0700")
			}
			conflict := head
			conflict.Hash = cdschain.Hash{7}
			err = o.acknowledge(genesis, conflict)
			if !errors.Is(err, ErrRecordConflict) || cmdsutil.ExitStatus(recordFailure("CDS confirmed it", err)) == cmdsutil.ExitNotConfirmed {
				t.Fatalf("a conflicting hash at the same sequence: %v", err)
			}
			rec, err = o.record(head.Cluster)
			if err != nil || rec == nil || rec.Acknowledged != head {
				t.Fatal("conflict replaced the retained head")
			}
		})
	}
}

func TestAppendRecordFailureIsPossiblyApplied(t *testing.T) {
	entries, key := testChain(t, 1)
	state, err := cdschain.Verify(entries)
	if err != nil {
		t.Fatal(err)
	}
	replica := &racedReplica{entries: entries}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	w := &writer{
		o:      &options{stateDir: t.TempDir(), persist: failedPersist},
		url:    srv.URL,
		client: srv.Client(),
		key:    key,
	}
	capture, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	original := os.Stderr
	os.Stderr = capture
	defer func() { os.Stderr = original }()
	pub, err := cdschain.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	head, err := w.append(context.Background(), state, cdschain.TypeOperatorKeys, cdschain.OperatorKeys{Keys: pub})
	if !errors.Is(err, errRecordNotSaved) || cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed {
		t.Fatalf("accepted write with failed record: %v", err)
	}
	if !strings.Contains(err.Error(), head.Hash.String()) || !strings.Contains(err.Error(), "local record") {
		t.Fatal("error omitted the confirmed head or local failure")
	}
	if _, err := capture.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(capture)
	if err != nil || len(output) != 0 {
		t.Fatal("printed success before persisting its record")
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if len(replica.entries) != 2 || replica.entries[1].Hash() != head.Hash {
		t.Fatal("test did not commit the remote entry")
	}
}

func TestGenesisRecordFailurePreservesHash(t *testing.T) {
	l := newLiveReplica(t)
	o := l.options()
	o.stateDir, o.persist = t.TempDir(), failedPersist
	var out bytes.Buffer
	err := o.genesis(
		context.Background(),
		&out,
		[]string{l.url},
		"lane",
		"v1.0.0",
		[]byte(testutil.CDSPinDocument(
			testutil.TestMeasurement,
			"launch",
		)),
		"",
	)
	if !errors.Is(err, errRecordNotSaved) || cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed {
		t.Fatalf("accepted genesis with failed record: %v", err)
	}
	state := l.waitServing(t)
	if !strings.Contains(err.Error(), state.Genesis.String()) || out.Len() != 0 {
		t.Fatal("failed persistence lost the genesis hash or printed success")
	}
}

func failedPersist(string, []byte, os.FileMode) error {
	return errors.New("record sync failed")
}

// An unusable state directory refuses the write before it is sent.
// Each case fails a different step of the check, so none can be dropped.
func TestWriteChecksTheStateDirBeforeAnythingIsSent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	_, key := testChain(t, 1)
	for name, stateDir := range map[string]func(locked string) string{
		"not a directory": func(string) string { return blockedRecordDir(t) },
		"new levels under an unreadable directory": func(locked string) string {
			return filepath.Join(locked, "c8s", "cds-ha")
		},
		"unreadable parent": func(locked string) string {
			return makeDir(t, filepath.Join(locked, "cds-ha"), 0o700)
		},
		"read-only directory": func(locked string) string {
			return makeDir(t, filepath.Join(locked, "cds-ha"), 0o500)
		},
	} {
		t.Run(name, func(t *testing.T) {
			locked := makeDir(t, filepath.Join(t.TempDir(), "locked"), 0o700)
			dir := stateDir(locked)
			if name != "read-only directory" {
				chmod(t, locked, 0o300)
			}
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
			defer srv.Close()
			w := &writer{o: &options{stateDir: dir}, url: srv.URL, client: srv.Client(), key: key}
			_, err := w.verified(context.Background())
			if !errors.Is(err, errStateDir) || cmdsutil.ExitStatus(err) == cmdsutil.ExitNotConfirmed || requests != 0 {
				t.Fatalf("unusable state directory: %d request(s), %v", requests, err)
			}
		})
	}
}

// A save that skipped the parent sync would pass here: the parent is
// writable through, but cannot be opened.
func TestAcknowledgeSyncsTheParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	locked := makeDir(t, filepath.Join(t.TempDir(), "locked"), 0o700)
	o := &options{stateDir: makeDir(t, filepath.Join(locked, "cds-ha"), 0o700)}
	chmod(t, locked, 0o300)
	head := cdschain.Head{V: cdschain.Version, Cluster: "lane", Hash: cdschain.Hash{1}}
	if err := o.acknowledge(head.Hash, head); err == nil {
		t.Fatal("saved a record without syncing the state directory's parent")
	}
}

func TestGenesisChecksTheRecordBeforeSending(t *testing.T) {
	l := newLiveReplica(t)
	o := l.options()
	run := func() error {
		pins := []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch"))
		return o.genesis(context.Background(), io.Discard, []string{l.url}, "lane", "v1.0.0", pins, "")
	}
	o.stateDir = blockedRecordDir(t)
	if err := run(); !errors.Is(err, errStateDir) {
		t.Fatalf("unusable state directory: %v", err)
	}
	o.stateDir = t.TempDir()
	if err := o.acknowledge(cdschain.Hash{9}, cdschain.Head{V: cdschain.Version, Cluster: "lane", Hash: cdschain.Hash{9}}); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("record of another genesis: %v", err)
	}
	// Neither refusal reached the replica: it still takes a genesis.
	o.stateDir = t.TempDir()
	if err := run(); err != nil {
		t.Fatalf("genesis after two unsent refusals: %v", err)
	}
}

func makeDir(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
	return path
}

// chmod sets mode until the test ends, so that t.TempDir can be removed.
func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

func blockedRecordDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A retry would find the refresh applied and report the resolve done.
func TestResolveStopsOnAnUnsavedRecord(t *testing.T) {
	l, o, seq, mine := forkedReplica(t)
	ctx := context.Background()
	if err := o.resolve(ctx, io.Discard, []string{l.url}, seq, mine.Hash(), nil, 0, false, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	held := l.waitServing(t).PolicySeq
	o.persist = failedPersist
	err := o.afterResolve(ctx, []string{l.url}, held, 10*time.Second)
	if !errors.Is(err, errRecordNotSaved) || cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed {
		t.Fatalf("refresh with a failed record: %v", err)
	}
	if got := l.waitServing(t).PolicySeq; got != held+1 {
		t.Fatalf("policy at seq %d, want one refresh above %d", got, held)
	}
}

// A rerun resumes from the plan, so it is written as durably as the record.
func TestResolvePlanIsWrittenDurably(t *testing.T) {
	var persisted []string
	o := &options{stateDir: t.TempDir()}
	o.persist = func(path string, data []byte, mode os.FileMode) error {
		persisted = append(persisted, path)
		return fileutil.WriteAtomic(path, data, mode)
	}
	want := resolvePlan{Seq: 4, Keep: cdschain.Hash{9}, Drop: cdschain.Hash{8}, Held: 6}
	if err := o.savePlan("lane", &want); err != nil {
		t.Fatal(err)
	}
	path, err := o.planPath("lane")
	if err != nil || len(persisted) != 1 || persisted[0] != path {
		t.Fatalf("plan written through %v, want one durable write of %s", persisted, path)
	}
	if got, err := o.plan("lane"); err != nil || got == nil || *got != want {
		t.Fatalf("read back %+v, %v", got, err)
	}
	if err := o.savePlan("lane", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := o.plan("lane"); err != nil || got != nil {
		t.Fatalf("a finished resolve left its plan: %+v, %v", got, err)
	}
}
