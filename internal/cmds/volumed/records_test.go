package volumed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeRecords is an in-memory MountRecords whose writes can be made to fail.
type fakeRecords struct {
	mu      sync.Mutex
	records map[string]Record
	putErr  error
	listErr error
}

func newRecords() *fakeRecords {
	return &fakeRecords{records: map[string]Record{}}
}

func (f *fakeRecords) Put(rec Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.records[mountKey(rec.Pod.UID, rec.Volume)] = rec
	return nil
}

func (f *fakeRecords) Remove(podUID, volumeName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, mountKey(podUID, volumeName))
	return nil
}

func (f *fakeRecords) List() ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []Record
	for _, rec := range f.records {
		out = append(out, rec)
	}
	return out, nil
}

func (f *fakeRecords) all() []Record {
	out, _ := f.List()
	return out
}

func testRecord() Record {
	return recordFor(&mount{
		pod:      testPod(testPodUID),
		name:     "weights",
		device:   "/dev/disk/by-id/virtio-c8s-vol-weights",
		cryptDev: mapperName(cryptKind, testPodUID, "weights"),
		target:   "/var/lib/kubelet/pods/" + testPodUID + "/volumes/kubernetes.io~empty-dir/c8s-volume-weights",
	})
}

func TestFileRecordsKeepsWhatWasWrittenAndForgetsWhatWasRemoved(t *testing.T) {
	recs := FileRecords{Dir: t.TempDir()}
	rec := testRecord()
	if err := recs.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := recs.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != rec {
		t.Fatalf("list = %+v, want the record that was written", got)
	}
	if err := recs.Remove(rec.Pod.UID, rec.Volume); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got, _ := recs.List(); len(got) != 0 {
		t.Fatalf("list = %+v after removing the only record", got)
	}
	// Teardown races pod deletion, so removing twice is the normal case.
	if err := recs.Remove(rec.Pod.UID, rec.Volume); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// A volumed killed mid-write must leave the next one a record it can decode,
// never a truncated one it would treat as an unrecorded mapping.
func TestFileRecordsWritesOnlyCompleteRecords(t *testing.T) {
	dir := t.TempDir()
	recs := FileRecords{Dir: dir}
	if err := recs.Put(testRecord()); err != nil {
		t.Fatalf("put: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the state directory holds %d files, want one per open volume", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(data, new(Record)) != nil {
		t.Fatalf("the record on disk does not decode: %s", data)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("record mode is %o, want 600", perm)
	}
}

// A record names the pod directory and the mapping a later volumed acts on as
// root, so a name that is not a pod UID and a volume never becomes a file.
func TestFileRecordsRefusesANameThatIsNotAPodAndVolume(t *testing.T) {
	dir := t.TempDir()
	recs := FileRecords{Dir: dir}
	for name, rec := range map[string]Record{
		"pod uid is a path": {Pod: PodCgroup{UID: "../../etc"}, Volume: "weights"},
		"volume is a path":  {Pod: PodCgroup{UID: testPodUID}, Volume: "../weights"},
		"no volume":         {Pod: PodCgroup{UID: testPodUID}},
	} {
		if err := recs.Put(rec); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the state directory holds %v", entries)
	}
}

func TestFileRecordsSkipsWhatItCannotDecode(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"junk" + recordExt, "not-a-record"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recs := FileRecords{Dir: dir}
	if err := recs.Put(testRecord()); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := recs.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("list = %+v, want only the record that decodes", got)
	}
}

func TestFileRecordsReportsAnUnreadableStateDir(t *testing.T) {
	recs := FileRecords{Dir: filepath.Join(t.TempDir(), "absent")}
	if _, err := recs.List(); err == nil {
		t.Fatal("listed records in a directory that does not exist")
	}
	if err := recs.Put(testRecord()); err == nil {
		t.Fatal("wrote a record into a directory that does not exist")
	}
}

// A record decides which mapping is closed and where a mount is detached from,
// so one that does not describe a mapping this daemon made is not adopted.
func TestRecordRefusesWhatThisDaemonCouldNotHaveWritten(t *testing.T) {
	cases := map[string]func(*Record){
		"another pod's mapping": func(r *Record) { r.Mapper = mapperName(cryptKind, testPodUID, "secrets") },
		"a mapper that is a path": func(r *Record) {
			r.Mapper = "../../dev/mapper/" + mapperName(cryptKind, testPodUID, "weights")
		},
		"a pod uid that is not a uuid": func(r *Record) { r.Pod.UID = "pod" },
		"a volume name with a slash":   func(r *Record) { r.Volume = "weights/../other" },
		"no device":                    func(r *Record) { r.Device = "" },
		"no target":                    func(r *Record) { r.Target = "" },
		"a truncated commitment":       func(r *Record) { r.Commitment = "ab" },
		"a commitment that is not hex": func(r *Record) { r.Commitment = strings.Repeat("zz", 32) },
	}
	for name, mutate := range cases {
		rec := testRecord()
		mutate(&rec)
		if _, err := rec.mount(); err == nil {
			t.Errorf("%s: adopted", name)
		}
	}
}

func TestRecordRebuildsTheVolumeItDescribes(t *testing.T) {
	rec := testRecord()
	rec.Mutable = true
	m, err := rec.mount()
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if m.pod != rec.Pod || m.name != rec.Volume || m.device != rec.Device || m.target != rec.Target {
		t.Errorf("rebuilt %+v from %+v", m, rec)
	}
	if !m.mutable {
		t.Error("a mutable volume was rebuilt as immutable, so teardown would unwind the wrong stack")
	}
	if recordFor(m) != rec {
		t.Errorf("recording the rebuilt volume gives %+v, want %+v", recordFor(m), rec)
	}
}
