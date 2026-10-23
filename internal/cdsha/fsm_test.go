package cdsha

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/klauspost/compress/zstd"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// A replica that meets an entry it cannot read stops serving instead of
// skipping it: Raft would move on, and the replica would serve state the
// rest of the group does not have.
func TestFSMStopsOnEntryItCannotRead(t *testing.T) {
	_, opPub := operatorKey(t)
	for name, e := range map[string]any{
		"newer format": Entry{Kind: KindSecret, Format: Format + 1, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}},
		"unknown kind": Entry{Kind: "from-the-future"},
		"newer agreed": Entry{Kind: KindFormat, SetFormat: Format + 1},
		"no payload":   Entry{Kind: KindSecret},
		"undecodable":  json.RawMessage("[1]"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newTestFSM(t, opPub)
			res := applyAt(f, 3, e)
			if _, ok := res.(error); !ok || f.Stuck() == "" {
				t.Fatalf("applied %v, stuck %q", res, f.Stuck())
			}
			if f.AppliedIndex() != 3 {
				t.Fatal("the index still moves: Raft has moved on")
			}
		})
	}
	// An entry it reads is not a reason to stop, nor is a refused one.
	f := newTestFSM(t, opPub)
	if res := applyAt(f, 1, Entry{Kind: KindFormat, SetFormat: Format}); res != nil || f.Stuck() != "" {
		t.Fatalf("current format: %v, stuck %q", res, f.Stuck())
	}
	if res := applyAt(f, 2, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{}}); res == nil || f.Stuck() != "" {
		t.Fatalf("refused CA renewal: %v, stuck %q", res, f.Stuck())
	}
}

// The agreed format only rises, and a snapshot carries it: a replica that
// reads less refuses the snapshot rather than install state it cannot
// follow.
func TestSnapshotInANewerFormatIsRefused(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	f.readable = Format + 1
	applyAt(f, 1, Entry{Kind: KindFormat, SetFormat: Format + 1})
	applyAt(f, 2, Entry{Kind: KindFormat, SetFormat: Format}) // never lowers
	if got := f.Core().format(); got != Format+1 {
		t.Fatalf("agreed format %d", got)
	}
	if err := restoreCopy(t, f, newTestFSM(t, opPub)); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("older replica installed a newer snapshot: %v", err)
	}
	same := newTestFSM(t, opPub)
	same.readable = Format + 1
	if err := restoreCopy(t, f, same); err != nil || same.Core().format() != Format+1 {
		t.Fatalf("same release: %v, format %d", err, same.Core().format())
	}
}

// The state machine refuses malformed entries and decrees that do not
// apply, and a snapshot restores the same state, mesh CA included.
func TestFSMEdges(t *testing.T) {
	opKey, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	apply := func(e any) any { return applyAt(f, 7, e) }
	if f.Apply(&raft.Log{Index: 8, Type: raft.LogConfiguration}) != nil || f.AppliedIndex() != 8 {
		t.Fatal("configuration entries are not commands but advance the index")
	}
	ca := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	sign := func(d Decree) SignedDecree { return signDecree(t, opKey, d) }
	now := time.Now().UnixMilli()
	for name, de := range map[string]DecreeEntry{
		"genesis without pins":   {Decree: sign(Decree{IntentID: "g0", Kind: Genesis, BootstrapNode: "n0"}), AtMS: now, RootCert: ca.Cert.Raw, Key: key},
		"genesis with a bad key": {Decree: sign(Decree{IntentID: "g1", Kind: Genesis, BootstrapNode: "n0"}), AtMS: now, Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: []byte("x")},
		"genesis key mismatch":   {Decree: sign(Decree{IntentID: "g2", Kind: Genesis, BootstrapNode: "n0"}), AtMS: now, Pins: []string{"m1"}, RootCert: mustCA(t).Cert.Raw, Key: key},
		"expired at entry time":  {Decree: sign(Decree{IntentID: "g3", Kind: Genesis, BootstrapNode: "n0"}), AtMS: time.Now().Add(2 * time.Hour).UnixMilli(), Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: key},
	} {
		if res := apply(Entry{Kind: KindDecree, Decree: &de}).(DecreeResult); res.Err == "" {
			t.Errorf("%s applied", name)
		}
	}
	g := DecreeEntry{Decree: sign(Decree{IntentID: "g", Kind: Genesis, BootstrapNode: "n0"}), AtMS: now, Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: key}
	if res := apply(Entry{Kind: KindDecree, Decree: &g}).(DecreeResult); res.Err != "" || res.Epoch != 1 {
		t.Fatalf("genesis: %+v", res)
	}
	if f.CA() == nil || !f.Core().Pins("m1") || f.Core().GenesisAtMS != now {
		t.Fatal("genesis state")
	}
	if res := apply(Entry{Kind: KindDecree, Decree: &g}).(DecreeResult); res.Err == "" {
		t.Fatal("genesis applied twice")
	}
	f2 := newTestFSM(t, opPub)
	if err := restoreCopy(t, f, f2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f2.CA().Cert.Raw, ca.Cert.Raw) || f2.Core().Epoch != 1 {
		t.Fatal("restored state differs")
	}
	if err := f2.Restore(io.NopCloser(strings.NewReader("{"))); err == nil {
		t.Fatal("garbage snapshot restored")
	}
	if err := f2.restore(snapshot{Core: Core{RootCert: []byte("x")}}); err == nil {
		t.Fatal("snapshot with a CA and no key restored")
	}
	if err := (&fsmSnapshot{}).Persist(&memSink{fail: true}); err == nil {
		t.Fatal("failed sink reported success")
	}
	for _, bad := range [][]byte{zstdOf(t, "{"), zstdOf(t, "{}\n{\"t\":")} {
		if err := f2.Restore(io.NopCloser(bytes.NewReader(bad))); err == nil {
			t.Fatalf("broken snapshot %q restored", bad)
		}
	}
}

func zstdOf(t *testing.T, s string) []byte {
	t.Helper()
	e, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	return e.EncodeAll([]byte(s), nil)
}

// A snapshot keeps the allowlist history byte for byte: the restored store
// passes the history check CDS runs before serving.
func TestSnapshotKeepsAllowlistHistory(t *testing.T) {
	al, sec, led := testStores(t)
	_, opPub := operatorKey(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	if err := al.StartJournal(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if err := al.PutWorkload(name, mkWorkload(t, 0)); err != nil {
			t.Fatal(err)
		}
	}
	f2 := newTestFSM(t, opPub)
	if err := restoreCopy(t, f, f2); err != nil {
		t.Fatal(err)
	}
	if err := f2.allowlist.StartJournal(); err != nil {
		t.Fatalf("restored history: %v", err)
	}
	h1, _ := al.History()
	h2, _ := f2.allowlist.History()
	if len(h1) != 4 || len(h2) != len(h1) || h2[3].Digest != h1[3].Digest {
		t.Fatalf("history %d vs %d entries", len(h1), len(h2))
	}
}

// A renewal entry is adopted only when it renews the current certificate:
// self-signed under the same key, same subject, a later expiry.
func TestApplyRenewCARefusals(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	apply := func(i uint64, e Entry) any { return applyAt(f, i, e) }
	mesh, err := issuer.NewMeshCA("c8s-mesh-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca := mesh.Current().CA
	if err, _ := apply(1, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: ca.Cert.Raw}}).(error); err == nil {
		t.Fatal("renewed a CA before there was one")
	}
	f.mu.Lock()
	f.ca, f.core.RootCert = ca, ca.Cert.Raw
	f.mu.Unlock()
	good, err := issuer.SelfSignCA(ca.Key, "c8s-mesh-ca", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := issuer.NewMeshCA("c8s-mesh-ca", 3*time.Hour)
	// issuer.TestRenewalOf covers the other refusals; one proves it is called.
	for name, der := range map[string][]byte{"another key": other.Current().CA.Cert.Raw, "garbage": []byte("x")} {
		if err, _ := apply(4, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: der}}).(error); err == nil {
			t.Fatalf("adopted %s", name)
		}
		if !bytes.Equal(f.CA().Cert.Raw, ca.Cert.Raw) {
			t.Fatalf("%s replaced the CA", name)
		}
	}
	if res := apply(5, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: good.Raw}}); res != nil {
		t.Fatalf("a valid renewal: %v", res)
	}
	if !bytes.Equal(f.CA().Cert.Raw, good.Raw) || !bytes.Equal(f.Core().RootCert, good.Raw) || f.CA().Key != ca.Key {
		t.Fatal("the renewal was not adopted under the same key")
	}
}

func expiryToken(iat int64, id string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc(fmt.Appendf(nil, `{"iat":%d,"exp":%d,"jti":%q}`, iat, iat+60, id)) + ".sig"
}

// Spent tokens record their window, long-expired ones are pruned, and the
// windows survive a snapshot round trip.
func TestSpentTokenExpiry(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	idx := uint64(0)
	consume := func(tok string) {
		t.Helper()
		idx++
		res := applyAt(f, idx, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: tok}})
		if r, ok := res.(allowlist.Result); !ok || r.Err != "" {
			t.Fatalf("consume: %#v", res)
		}
	}
	// roundTrip snapshots f and restores it into a fresh FSM, returning the
	// used_token rows of both.
	roundTrip := func() (src, dst []map[string]any) {
		t.Helper()
		g := newTestFSM(t, opPub)
		if err := restoreCopy(t, f, g); err != nil {
			t.Fatal(err)
		}
		return usedTokens(t, f.allowlist), usedTokens(t, g.allowlist)
	}
	const t0, hour = int64(1_800_000_000), int64(3600)

	consume(expiryToken(t0+20*hour, "c"))
	consume(expiryToken(t0+20*hour+30, "d"))
	src, dst := roundTrip()
	if len(src) != 2 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("round trip:\n%v\n%v", src, dst)
	}
	consume(expiryToken(t0+30*hour, "e")) // prunes c and d
	src, dst = roundTrip()
	if len(src) != 1 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("after pruning:\n%v\n%v", src, dst)
	}
	windows := 0
	for _, row := range dst {
		if row["exp_unix"] != int64(0) {
			windows++
			if row["exp_unix"] != t0+30*hour+60 || row["iat_unix"] != t0+30*hour {
				t.Fatalf("row %v", row)
			}
		}
	}
	if windows != 1 {
		t.Fatalf("%d rows with a window", windows)
	}
}

// usedTokens reads the used_token rows of a store through its own image.
func usedTokens(t *testing.T, s *allowlist.Store) []map[string]any {
	t.Helper()
	image, err := s.Dump()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:/used-tokens-"+t.Name()+"?vfs=memdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error { return dc.(interface{ Deserialize([]byte) error }).Deserialize(image) }); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(t.Context(), "SELECT digest, exp_unix, iat_unix FROM used_token ORDER BY digest")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var d string
		var exp, iat int64
		if err := rows.Scan(&d, &exp, &iat); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{"digest": d, "exp_unix": exp, "iat_unix": iat})
	}
	return out
}

// historySnapshot is a snapshot whose allowlist history holds versions near
// copies of one ~70 KiB document, as a cluster's does, and the size of
// those documents.
func historySnapshot(t *testing.T, format uint32, versions int) (snapshot, int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(3, 4))
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	if err := al.StartJournal(); err != nil {
		t.Fatal(err)
	}
	ws := map[string]pkgallowlist.Workload{}
	for i := range 300 {
		ws[fmt.Sprintf("w%03d", i)] = digestWorkload(t, rng)
	}
	size := 0
	for v := range versions {
		ws[fmt.Sprintf("w%03d", v%300)] = digestWorkload(t, rng)
		doc := &pkgallowlist.Allowlist{Workloads: ws}
		b, _ := json.Marshal(doc)
		size += len(b)
		if err := al.ReplaceAll(doc); err != nil {
			t.Fatal(err)
		}
	}
	image, err := al.Dump()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot{Core: Core{ClusterID: testCluster, Format: format}, Allowlist: image}, size
}

func digestWorkload(t *testing.T, rng *rand.Rand) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(fmt.Sprintf("sha256:%016x%016x%016x%016x", rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()))
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}

// Snapshots share the history's repeats (zstd, long window), and a replica
// refuses one in a format it does not read.
func TestSnapshotCompression(t *testing.T) {
	sn, size := historySnapshot(t, Format, 300)
	var buf bytes.Buffer
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	got, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, false)
	if err != nil || !bytes.Equal(got.Allowlist, sn.Allowlist) {
		t.Fatalf("round trip: %v", err)
	}
	if head, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, true); err != nil || len(head.Allowlist) != 0 || head.Core.ClusterID != testCluster {
		t.Fatalf("header only: %v, %+v", err, head.Core)
	}
	if buf.Len()*50 > size {
		t.Fatalf("snapshot of %d bytes for %d bytes of near copies: repeats not shared", buf.Len(), size)
	}
	for _, format := range []uint32{Format + 1, baseFormat - 1} {
		buf.Reset()
		sn, _ := historySnapshot(t, format, 2)
		_ = encodeSnapshot(&buf, sn)
		if _, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, false); err == nil {
			t.Fatalf("took a format %d snapshot", format)
		}
	}
	for _, bad := range [][]byte{{0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3}, []byte(`{"core":{}}`)} {
		if _, err := decodeSnapshot(bytes.NewReader(bad), Format, false); err == nil {
			t.Fatalf("garbage %x decoded", bad)
		}
	}
}

// A replica refuses a snapshot older than what it applied (Raft would
// install it and roll a serving replica back), and takes the index of a
// newer one it installs.
func TestFSMRefusesOlderSnapshot(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	put := func(index uint64, v string) {
		t.Helper()
		if res := applyAt(f, index, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte(v)}}); res != nil {
			if err, ok := res.(error); ok {
				t.Fatal(err)
			}
		}
	}
	snapshotAt := func() []byte {
		t.Helper()
		s, err := f.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	value := func(fsm *FSM) string {
		v, _ := fsm.secrets.Get(context.Background(), "/p")
		return string(v)
	}
	put(2, "old")
	old := snapshotAt()
	put(5, "new")
	if err := f.Restore(io.NopCloser(bytes.NewReader(old))); !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("older snapshot: %v", err)
	}
	if value(f) != "new" || f.AppliedIndex() != 5 {
		t.Fatalf("rolled back to %q at %d", value(f), f.AppliedIndex())
	}
	// A newer snapshot installs and moves the applied index.
	put(9, "newer")
	newer := snapshotAt()
	g := newTestFSM(t, opPub)
	if err := g.Restore(io.NopCloser(bytes.NewReader(old))); err != nil || g.AppliedIndex() != 2 {
		t.Fatalf("fresh replica, snapshot at 2: %v, applied %d", err, g.AppliedIndex())
	}
	if err := g.Restore(io.NopCloser(bytes.NewReader(newer))); err != nil || g.AppliedIndex() != 9 || value(g) != "newer" {
		t.Fatalf("newer snapshot: %v, applied %d, value %q", err, g.AppliedIndex(), value(g))
	}
	// The same index again (Raft restarting from its own snapshot) is fine.
	if err := g.Restore(io.NopCloser(bytes.NewReader(newer))); err != nil {
		t.Fatalf("snapshot at the applied index: %v", err)
	}
}
