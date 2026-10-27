package cdsha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/klauspost/compress/zstd"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
)

// A replica stops at an entry with a field it does not know, as at an
// unknown kind: applying the rest would drop whatever the field meant, and
// replicas that know it would hold another state.
func TestFSMStopsOnUnknownEntryField(t *testing.T) {
	_, opPub := operatorKey(t)
	now := time.Now().UnixMilli()
	for _, tc := range []struct{ name, raw string }{
		{"top level", fmt.Sprintf(`{"kind":"binding","binding":{"sandbox_id":"sb","host":"A","at_ms":%d},"from_the_future":1}`, now)},
		{"nested", fmt.Sprintf(`{"kind":"binding","binding":{"sandbox_id":"sb","host":"A","at_ms":%d,"from_the_future":1}}`, now)},
		{"trailing data", fmt.Sprintf(`{"kind":"binding","binding":{"sandbox_id":"sb","host":"A","at_ms":%d}} {}`, now)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFSM(t, opPub)
			res := f.Apply(&raft.Log{Index: 3, Type: raft.LogCommand, Data: []byte(tc.raw)})
			if _, ok := res.(error); !ok || f.Stuck() == "" || f.StuckLocal() {
				t.Fatalf("applied %v, stuck %q, local %v", res, f.Stuck(), f.StuckLocal())
			}
			if h, ok := f.ledger.Lookup("sb"); ok {
				t.Fatalf("the entry was applied: sb bound to %q", h)
			}
		})
	}
	// The same entry without the unknown field applies.
	f := newTestFSM(t, opPub)
	if res := applyAt(f, 3, Entry{Kind: KindBinding, Binding: bindingAt("sb", "A", now)}); res != true || f.Stuck() != "" {
		t.Fatalf("known entry: %v, stuck %q", res, f.Stuck())
	}
}

// A snapshot whose header has a field this replica does not know is
// refused, whether the field is in the header or inside its core.
func TestSnapshotWithUnknownHeaderFieldIsRefused(t *testing.T) {
	_, opPub := operatorKey(t)
	src := newTestFSM(t, opPub)
	applyAt(src, 1, Entry{Kind: KindBinding, Binding: bindingAt("sb", "A", time.Now().UnixMilli())})
	body := snapshotBytes(t, src)
	if err := newTestFSM(t, opPub).Restore(io.NopCloser(bytes.NewReader(body))); err != nil {
		t.Fatalf("unchanged snapshot: %v", err)
	}
	for name, add := range map[string]func(h map[string]any){
		"header": func(h map[string]any) { h["from_the_future"] = 1 },
		"core":   func(h map[string]any) { h["core"].(map[string]any)["from_the_future"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			dst := newTestFSM(t, opPub)
			if err := dst.Restore(io.NopCloser(bytes.NewReader(editHeader(t, body, add)))); err == nil {
				t.Fatal("a snapshot with an unknown field was installed")
			}
			if _, ok := dst.ledger.Lookup("sb"); ok {
				t.Fatal("the refused snapshot changed the state")
			}
		})
	}
}

func bindingAt(sandboxID, host string, atMS int64) *sandboxledger.Command {
	return &sandboxledger.Command{SandboxID: sandboxID, Host: host, AtMS: atMS}
}

// editHeader re-encodes snapshot body with its header line changed by edit.
func editHeader(t *testing.T, body []byte, edit func(map[string]any)) []byte {
	t.Helper()
	d, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	plain, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	header, rest, _ := bytes.Cut(plain, []byte("\n"))
	var h map[string]any
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatal(err)
	}
	edit(h)
	if header, err = json.Marshal(h); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := zstd.NewWriter(&out, zstd.WithWindowSize(snapshotWindow))
	if err != nil {
		t.Fatal(err)
	}
	w.Write(append(append(header, '\n'), rest...))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
