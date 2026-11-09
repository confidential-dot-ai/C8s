package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Only a 200 naming the entry is done; a 202 or a broken answer
// after the entry left may have been applied (exit 3); a 409 applied nothing.
func TestSubmitAnswers(t *testing.T) {
	e := cdschain.Entry{Body: []byte(`{"v":1}`), Sig: "x"}
	done, _ := json.Marshal(cdschain.Head{Seq: 1, Hash: e.Hash()})
	for _, tc := range []struct {
		code         int
		body         string
		notConfirmed bool
		anyErr       bool
	}{
		{http.StatusOK, string(done), false, false},
		{http.StatusAccepted, string(done), true, true},
		{http.StatusServiceUnavailable, "store unreachable", false, true},
		{http.StatusInternalServerError, "", true, true},
		{http.StatusConflict, "another write", false, true},
		{http.StatusOK, `{"seq":1}`, true, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := Submit(context.Background(), srv.Client(), srv.URL, e)
		srv.Close()
		if errors.Is(err, ErrNotConfirmed) != tc.notConfirmed || (err != nil) != tc.anyErr {
			t.Errorf("%d %s: %v", tc.code, tc.body, err)
		}
	}
	if _, err := Submit(context.Background(), http.DefaultClient, "http://127.0.0.1:1", e); !errors.Is(err, ErrNotConfirmed) {
		t.Errorf("no answer: %v", err)
	}
}

// U2: a set that a majority of the members' builds are not in needs --force.
func TestRunningIn(t *testing.T) {
	a, b := cdschain.Build{Version: "v1.0.0"}, cdschain.Build{Version: "v2.0.0"}
	statuses := []*haapi.Status{{IsMember: true, Build: "v1.0.0"}, {IsMember: true, Build: "v1.0.0"}, {IsMember: true, Build: "v2.0.0"}, nil}
	if n := runningIn(statuses, []cdschain.Build{b}); n != 1 {
		t.Fatalf("running v2 = %d", n)
	}
	if n := runningIn(statuses, []cdschain.Build{a, b}); n != 3 {
		t.Fatalf("running v1 or v2 = %d", n)
	}
	if got := above([]cdschain.Build{a, b}, "v1.5.0"); len(got) != 1 || got[0] != b {
		t.Fatalf("raise-floor kept %v", got)
	}
}

// A resolution needs every replica, and never drops an entry a replica
// answered done or this CLI acknowledged.
func TestPlanResolution(t *testing.T) {
	keep, drop := cdschain.Hash{1}, cdschain.Hash{2}
	forkOn := func(mine, theirs cdschain.Hash, done ...cdschain.Head) *haapi.Status {
		return &haapi.Status{Fork: &haapi.Fork{Seq: 5, Mine: mine, Theirs: theirs}, Confirmed: done}
	}
	for _, tc := range []struct {
		name     string
		statuses []*haapi.Status
		lost     []int
		rec      *record
		want     string
	}{
		{"ok", []*haapi.Status{forkOn(keep, drop), forkOn(drop, keep), {}}, nil, nil, ""},
		{"a replica does not answer", []*haapi.Status{forkOn(keep, drop), nil, {}}, nil, nil, "does not answer"},
		{"assumed lost", []*haapi.Status{forkOn(keep, drop), nil, {}}, []int{1}, nil, ""},
		{"drops a done entry", []*haapi.Status{forkOn(keep, drop), forkOn(drop, keep, cdschain.Head{Seq: 5}), {}}, nil, nil, "done"},
		{"drops the acknowledged head", []*haapi.Status{forkOn(keep, drop), forkOn(drop, keep), {}}, nil, &record{Acknowledged: cdschain.Head{Seq: 5, Hash: drop}}, "acknowledged"},
		{"keeps an unseen entry", []*haapi.Status{forkOn(cdschain.Hash{3}, drop), {}, {}}, nil, nil, "neither"},
	} {
		got, err := planResolution(tc.statuses, 5, keep, tc.lost, tc.rec)
		if tc.want == "" && (err != nil || got != drop) {
			t.Errorf("%s: %v %v", tc.name, got, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// The record never goes down and refuses another genesis.
func TestAcknowledge(t *testing.T) {
	o := &options{stateDir: t.TempDir()}
	g := cdschain.Hash{9}
	for _, seq := range []uint64{3, 1} {
		if err := o.acknowledge(g, cdschain.Head{Cluster: "lane", Seq: seq}); err != nil {
			t.Fatal(err)
		}
	}
	if rec, _ := o.record("lane"); rec.Acknowledged.Seq != 3 {
		t.Fatalf("record went down to %d", rec.Acknowledged.Seq)
	}
	if err := o.acknowledge(cdschain.Hash{8}, cdschain.Head{Cluster: "lane", Seq: 4}); err == nil {
		t.Fatal("another genesis was recorded")
	}
}

// A pending replica (no held chain) gets no resolution, rather than a crash.
func TestResolutionsSkipPendingReplicas(t *testing.T) {
	held := &cdschain.Head{Cluster: "lane"}
	reqs := resolutions([]*haapi.Status{{Held: held}, {Pending: true}, nil}, "lane", 5, cdschain.Hash{1}, cdschain.Hash{2})
	if len(reqs) != 1 || reqs[0].Slot != 0 || reqs[0].Cluster != "lane" {
		t.Fatalf("resolutions %+v", reqs)
	}
}

// testChain is a genesis and n-1 operator-keys entries signed by key.
func testChain(t *testing.T, n int) ([]cdschain.Entry, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := cdschain.PublicKeyPEM(&key.PublicKey)
	payload, _ := json.Marshal(cdschain.Genesis{Endpoints: []string{"a:1"}, Members: []string{pub}, OperatorKeys: pub, CAKey: pub,
		Accepted: []cdschain.Build{{Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, "launch"), Version: "v1.0.0"}}})
	e, err := cdschain.Sign(key, cdschain.Body{Cluster: "lane", Type: cdschain.TypeGenesis, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	entries := []cdschain.Entry{e}
	for seq := 1; seq < n; seq++ {
		payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pub})
		e, _ = cdschain.Sign(key, cdschain.Body{Cluster: "lane", Seq: uint64(seq), Prev: entries[seq-1].Hash(), Type: cdschain.TypeOperatorKeys, Payload: payload})
		entries = append(entries, e)
	}
	return entries, key
}

// racedReplica takes an entry only on its head and answers 409 otherwise, as
// a replica does; before each of the next races submits, race lands another
// writer's entry first.
type racedReplica struct {
	mu      sync.Mutex
	entries []cdschain.Entry
	race    func(head *cdschain.State) cdschain.Entry
	races   int
}

func (f *racedReplica) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, _ := cdschain.Verify(f.entries)
	switch r.URL.Path {
	case haapi.StatusPath:
		_ = json.NewEncoder(w).Encode(haapi.Status{Member: "m"})
	case haapi.ChainPath:
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		_ = json.NewEncoder(w).Encode(haapi.Chain{Entries: f.entries[from:]})
	case haapi.EntriesPath:
		var e cdschain.Entry
		_ = json.NewDecoder(r.Body).Decode(&e)
		if f.races > 0 {
			f.entries = append(f.entries, f.race(state))
			f.races--
			state, _ = cdschain.Verify(f.entries)
		}
		if _, err := state.Apply(e); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		f.entries = append(f.entries, e)
		_ = json.NewEncoder(w).Encode(cdschain.Head{Cluster: state.Cluster, Seq: state.Head.Seq + 1, Hash: e.Hash()})
	}
}

// A policy write that another write beat between its read and its swap (a
// 409) is ErrPolicyChanged, which the allowlist commands re-read and retry
// on; the retry at the new version lands.
func TestWritePolicyLosingARaceIsRetried(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	entries, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(t.TempDir(), "operator.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := func(label string) *pkgallowlist.Allowlist {
		al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"label":"` + label +
			`","containers":[{"digest":"sha256:` + strings.Repeat("1", 64) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		return al
	}
	replica := &racedReplica{entries: entries, race: func(head *cdschain.State) cdschain.Entry {
		canonical, _ := doc("ghcr.io/x/other:v1").Canonical()
		payload, _ := json.Marshal(cdschain.Policy{Allowlist: canonical})
		e, _ := cdschain.Sign(key, cdschain.Body{Cluster: head.Cluster, Seq: head.Head.Seq + 1, Prev: head.Head.Hash, Type: cdschain.TypePolicy, Payload: payload})
		return e
	}, races: 1}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	opts := &cdsconn.Options{URL: srv.URL, Insecure: true, OperatorKey: keyPath, Timeout: 5 * time.Second}
	head := func() *cdschain.State {
		replica.mu.Lock()
		defer replica.mu.Unlock()
		state, _ := cdschain.Verify(replica.entries)
		return state
	}
	for attempt := 1; ; attempt++ {
		handled, err := WritePolicy(context.Background(), opts, doc("ghcr.io/x/w:v1"), head().PolicyVersion())
		if !handled {
			t.Fatal("a replica set was not handled")
		}
		if err == nil && attempt == 2 {
			break
		}
		if attempt == 2 || !errors.Is(err, ErrPolicyChanged) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	// A write read at the seed's version is refused before it is sent.
	if _, err := WritePolicy(context.Background(), opts, doc("ghcr.io/x/w:v2"), "1"); !errors.Is(err, ErrPolicyChanged) || head().Head.Seq != 2 {
		t.Fatalf("a write read at an older version: %v, head %d", err, head().Head.Seq)
	}
}

// accept-image and raise-floor re-read and retry a write a busy writer
// keeps beating, until --retry-for has passed; then nothing was applied.
func TestWriteBuildsRetriesALostRace(t *testing.T) {
	entries, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(t.TempDir(), "operator.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	replica := &racedReplica{entries: entries, races: 7, race: func(head *cdschain.State) cdschain.Entry {
		pub, _ := cdschain.PublicKeyPEM(&key.PublicKey)
		payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pub})
		e, _ := cdschain.Sign(key, cdschain.Body{Cluster: head.Cluster, Seq: head.Head.Seq + 1, Prev: head.Head.Hash, Type: cdschain.TypeOperatorKeys, Payload: payload})
		return e
	}}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	o := &options{Options: cdsconn.Options{URL: srv.URL, Insecure: true, OperatorKey: keyPath, Timeout: 5 * time.Second}, stateDir: t.TempDir(), retryFor: time.Minute}
	same := func(current []cdschain.Build) []cdschain.Build { return current }
	if err := o.writeBuilds(context.Background(), io.Discard, true, same); err != nil {
		t.Fatalf("a write beaten 7 times: %v", err)
	}
	replica.mu.Lock()
	replica.races, o.retryFor = 1<<30, time.Second
	replica.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := o.writeBuilds(ctx, io.Discard, true, same); !errors.Is(err, errHeadMoved) || time.Since(start) > 5*time.Second {
		t.Fatalf("a writer that never stops: %v after %s", err, time.Since(start))
	}
}

// After a resolve, the kept chain's allowlist is served at a version above
// any a dropped branch's policy entry had (seq held or below, version
// held+1), so a node holding one fetches the kept allowlist again.
func TestRefreshPolicyOutranksTheDroppedBranch(t *testing.T) {
	entries, key := testChain(t, 1)
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := al.Canonical()
	payload, _ := json.Marshal(cdschain.Policy{Allowlist: canonical})
	e, _ := cdschain.Sign(key, cdschain.Body{Cluster: "lane", Seq: 1, Prev: entries[0].Hash(), Type: cdschain.TypePolicy, Payload: payload})
	replica := &racedReplica{entries: append(entries, e)}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	const held = 3
	w := &writer{o: &options{stateDir: t.TempDir()}, url: srv.URL, client: srv.Client(), key: key}
	if err := w.refreshPolicy(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	replica.mu.Lock()
	state, err := cdschain.Verify(replica.entries)
	replica.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	version, _ := strconv.ParseUint(state.PolicyVersion(), 10, 64)
	if version <= held+1 || string(state.Policy) != string(canonical) {
		t.Fatalf("served at version %d (a dropped policy may hold %d): %s", version, held+1, state.Policy)
	}
}

// A replica of another genesis than the recorded one is refused, and,
// with no record, one whose genesis --operator-key did not sign.
func TestVerifiedRefusesAnotherGenesis(t *testing.T) {
	recorded, key := testChain(t, 2)
	other, otherKey := testChain(t, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(haapi.Chain{Entries: other})
	}))
	defer srv.Close()
	verified := func(o *options, key *ecdsa.PrivateKey) error {
		_, err := (&writer{o: o, url: srv.URL, client: srv.Client(), key: key}).verified(context.Background())
		return err
	}
	if err := verified(&options{stateDir: t.TempDir()}, otherKey); err != nil {
		t.Fatalf("negative control: %v", err)
	}
	if err := verified(&options{stateDir: t.TempDir()}, key); err == nil || !strings.Contains(err.Error(), "not signed by --operator-key") {
		t.Fatalf("no record, a genesis another key signed: %v", err)
	}
	state, err := cdschain.Verify(recorded)
	if err != nil {
		t.Fatal(err)
	}
	o := &options{stateDir: t.TempDir()}
	if err := o.acknowledge(state.Genesis, state.Head); err != nil {
		t.Fatal(err)
	}
	if err := verified(o, otherKey); err == nil || !strings.Contains(err.Error(), "recorded") {
		t.Fatalf("a replica of another genesis than the recorded one: %v", err)
	}
}

// Concurrent commands sharing a state directory: a chain read in flight when
// another command records a newer acknowledged head answers the older head,
// current when the read was sent, and is not refused. A read sent after the
// record still refuses it (negative control).
func TestVerifiedHoldsTheRecordFromBeforeTheRead(t *testing.T) {
	entries, key := testChain(t, 3)
	o := &options{stateDir: t.TempDir()}
	state, err := cdschain.Verify(entries[:2])
	if err != nil {
		t.Fatal(err)
	}
	newer := cdschain.Head{Cluster: "lane", Seq: 2, Hash: entries[2].Hash()}
	var sibling atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if sibling.Load() {
			if err := o.acknowledge(state.Genesis, newer); err != nil {
				t.Error(err)
			}
		}
		_ = json.NewEncoder(w).Encode(haapi.Chain{Entries: entries[:2]})
	}))
	defer srv.Close()
	if err := o.acknowledge(state.Genesis, state.Head); err != nil {
		t.Fatal(err)
	}
	sibling.Store(true)
	w := &writer{o: o, url: srv.URL, client: srv.Client(), key: key}
	if _, err := w.verified(context.Background()); err != nil {
		t.Fatalf("a read in flight when a sibling acknowledged head 2: %v", err)
	}
	sibling.Store(false)
	if _, err := w.verified(context.Background()); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("a read sent after head 2 was acknowledged: %v", err)
	}
}

// A command reads a chain it read before in round trips and verification
// independent of the chain's length: the replica sends what follows the
// cached head, and only that is verified.
func TestVerifiedFollowsTheCachedChain(t *testing.T) {
	for _, n := range []int{3, 300} {
		entries, key := testChain(t, n+1)
		var reads, served atomic.Int32
		served.Store(int32(n))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reads.Add(1)
			from, _ := strconv.Atoi(r.URL.Query().Get("from"))
			end := min(int(served.Load()), from+32)
			_ = json.NewEncoder(w).Encode(haapi.Chain{Entries: entries[min(from, end):end]})
		}))
		w := &writer{o: &options{stateDir: t.TempDir()}, url: srv.URL, client: srv.Client(), key: key}
		start := time.Now()
		if _, err := w.verified(context.Background()); err != nil {
			t.Fatal(err)
		}
		whole := time.Since(start)
		served.Store(int32(n + 1))
		reads.Store(0)
		start = time.Now()
		state, err := w.verified(context.Background())
		extended := time.Since(start)
		srv.Close()
		if err != nil || state.Head.Seq != uint64(n) {
			t.Fatalf("chain of %d: %v %v", n, state, err)
		}
		if got := reads.Load(); got != 1 {
			t.Errorf("chain of %d: %d chain reads after one new entry, want 1", n, got)
		}
		if n == 300 && extended*4 > whole {
			t.Errorf("chain of %d: verifying one new entry took %s, the whole chain %s", n, extended, whole)
		}
	}
}

// A replica assumed lost may have held a longer dropped branch than any that
// answers: the refresh goes above the head the operator names for it, and a
// resolve with a lost replica and no such head is refused.
func TestRefreshAboveCoversALostReplica(t *testing.T) {
	statuses := []*haapi.Status{{Held: &cdschain.Head{Seq: 5}}, nil, {Held: &cdschain.Head{Seq: 7}}}
	if _, err := refreshAbove(statuses, []int{1}, 0, false); err == nil {
		t.Fatal("a lost replica without --lost-head was accepted")
	}
	if held, err := refreshAbove(statuses, []int{1}, 12, true); err != nil || held != 12 {
		t.Fatalf("held %d, %v; want the lost replica's 12", held, err)
	}
	if held, err := refreshAbove(statuses, nil, 0, false); err != nil || held != 7 {
		t.Fatalf("negative control: held %d, %v; want 7", held, err)
	}
}

// --floor must be a semantic version: an invalid one would evict nothing.
func TestAcceptImageRefusesAnInvalidFloor(t *testing.T) {
	for floor, invalid := range map[string]bool{"1.4": true, "latest": true, "v1.4.0": false} {
		cmd := newAcceptImageCmd(&options{})
		cmd.SetArgs([]string{"--new-pin", "/nonexistent", "--version", "v1.5.0", "--floor", floor})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		if got := err != nil && strings.Contains(err.Error(), "not a semantic version"); got != invalid {
			t.Errorf("--floor %q: %v", floor, err)
		}
	}
}

// genesis and resolve take --endpoints; with --url as well they refuse
// rather than reach no replica (genesis panicked indexing none).
func TestURLWithEndpointsIsRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	keyPath, pinPath := filepath.Join(dir, "operator.pem"), filepath.Join(dir, "pin.json")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"genesis", "--cluster", "lane", "--version", "v1.0.0"}, {"resolve", "--seq", "1", "--keep", strings.Repeat("ab", 32)}} {
		cmd := NewCmd()
		cmd.SetArgs(append(args, "--url", "https://a:1", "--endpoints", "a:1", "--operator-key", keyPath, "--image-policy-file", pinPath))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "pass --url or --endpoints") {
			t.Errorf("%s with --url and --endpoints: %v", args[0], err)
		}
	}
}

// A policy write that cannot reach the replica set's writer fails, never
// falls back to the old PUT; a CDS without /ha/status is not handled.
func TestWritePolicyWriterErrorIsHandled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	entries, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(t.TempDir(), "operator.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"label":"ghcr.io/x/w:v1",` +
		`"containers":[{"digest":"sha256:` + strings.Repeat("1", 64) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	replica := httptest.NewServer(&racedReplica{entries: entries})
	defer replica.Close()
	missing := &cdsconn.Options{URL: replica.URL, Insecure: true, OperatorKey: filepath.Join(t.TempDir(), "none.pem"), Timeout: 5 * time.Second}
	if handled, err := WritePolicy(context.Background(), missing, doc, "1"); !handled || err == nil {
		t.Fatalf("a writer error: handled=%v %v, want handled with the error", handled, err)
	}
	single := httptest.NewServer(http.NotFoundHandler())
	defer single.Close()
	opts := &cdsconn.Options{URL: single.URL, Insecure: true, OperatorKey: keyPath, Timeout: 5 * time.Second}
	if handled, err := WritePolicy(context.Background(), opts, doc, "1"); handled || err != nil {
		t.Fatalf("a single CDS: handled=%v %v, want the old write", handled, err)
	}
}

// genesis names why a slot's status did not answer (an attestation or pin
// mismatch, an unreachable endpoint) rather than calling it not pending.
func TestGenesisNamesWhyASlotDoesNotAnswer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	keyPath, pinPath := filepath.Join(dir, "operator.pem"), filepath.Join(dir, "pin.json")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch")), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	cmd := NewCmd()
	cmd.SetArgs([]string{"genesis", "--cluster", "lane", "--version", "v1.0.0", "--endpoints", endpoint, "--operator-key", keyPath, "--image-policy-file", pinPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "does not answer its status: ") {
		t.Fatalf("genesis against a replica that does not answer: %v", err)
	}
}

// A write command takes --endpoints like the rest and writes through a
// replica that serves; with none serving it says so.
func TestWriteCommandsTakeEndpoints(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	keyPath, pinPath := filepath.Join(dir, "operator.pem"), filepath.Join(dir, "pin.json")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch")), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	cmd := NewCmd()
	cmd.SetArgs([]string{"raise-floor", "--to", "v1.0.0", "--endpoints", endpoint + "," + endpoint, "--operator-key", keyPath, "--image-policy-file", pinPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no replica of --endpoints serves") {
		t.Fatalf("raise-floor with --endpoints and no replica serving: %v", err)
	}
}

// status names why a replica could not be read or verified, and fails when
// any could not, instead of printing a null status.
func TestStatusReportsAReplicaItCannotRead(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pinPath := filepath.Join(t.TempDir(), "pin.json")
	if err := os.WriteFile(pinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch")), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	var out bytes.Buffer
	cmd := NewCmd()
	cmd.SetArgs([]string{"status", "--endpoints", endpoint, "--image-policy-file", pinPath})
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	var line struct {
		Error  string          `json:"error"`
		Status json.RawMessage `json:"status"`
	}
	if jerr := json.Unmarshal(out.Bytes(), &line); jerr != nil || line.Error == "" || line.Status != nil {
		t.Fatalf("status printed %q, want the replica's error and no status", out.String())
	}
	if err == nil || !strings.Contains(err.Error(), "1 of 1 replicas") {
		t.Fatalf("status with no replica read: %v, want an error", err)
	}
}
