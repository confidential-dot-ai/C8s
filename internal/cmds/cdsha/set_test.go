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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// liveReplica is one genesis-pending replica over a memory store, served over
// plaintext HTTP, and the operator key file its launch file names.
type liveReplica struct {
	replica  *haapi.Replica
	store    *haapi.Memory
	url      string
	endpoint string
	key      *ecdsa.PrivateKey
	keyPath  string
}

func newLiveReplica(t *testing.T) *liveReplica {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(t.TempDir(), "operator.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := http.Handler(http.NotFoundHandler())
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := handler
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	mesh, err := issuer.NewMeshCA("c8s-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store := haapi.NewMemory()
	replica, err := haapi.New(haapi.Config{
		Cluster:      "lane",
		Endpoints:    []string{endpoint},
		Self:         0,
		OperatorKeys: []*ecdsa.PublicKey{&key.PublicKey},
		Gossip:       200 * time.Millisecond,
		PeerTimeout:  200 * time.Millisecond,
		StoreTimeout: time.Second,
		WarnEntries:  1000,
		Mesh:         mesh,
		Peer:         srv.Client(),
		Attested:     func(armtls.Pins) (*http.Client, error) { return srv.Client(), nil },
		SelfCheck:    func(context.Context, string) (bool, error) { return true, nil },
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	handler = replica.Handler(func(*http.Request, []byte, []*ecdsa.PublicKey) error { return nil })
	mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go replica.Run(ctx)
	return &liveReplica{replica: replica, store: store, url: srv.URL, endpoint: endpoint, key: key, keyPath: keyPath}
}

func (l *liveReplica) options() *options {
	return &options{
		Options:   cdsconn.Options{URL: l.url, Insecure: true, OperatorKey: l.keyPath, Timeout: 5 * time.Second},
		endpoints: []string{l.endpoint},
	}
}

func (l *liveReplica) waitServing(t *testing.T) *cdschain.State {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, err := l.replica.Current(context.Background())
		if err == nil {
			return state
		}
		if time.Now().After(deadline) {
			t.Fatalf("the replica does not serve: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func policyDocument(t *testing.T, label string) *pkgallowlist.Allowlist {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"label":"` + label +
		`","containers":[{"digest":"sha256:` + strings.Repeat("1", 64) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

// genesis collects every pending replica's member key, posts entry 0 with the
// pin as the first accepted build and records it; a replica that holds a chain
// takes no second genesis.
func TestGenesisStartsThePendingReplicas(t *testing.T) {
	l := newLiveReplica(t)
	o := l.options()
	pin := []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch"))
	var out bytes.Buffer
	if err := o.genesis(context.Background(), &out, []string{l.url}, "lane", "v1.0.0", pin, ""); err != nil {
		t.Fatal(err)
	}
	state := l.waitServing(t)
	if state.Head.Seq != 0 || len(state.Accepted) != 1 || state.Accepted[0].Version != "v1.0.0" || state.Accepted[0].Measurements != string(pin) {
		t.Fatalf("genesis state %+v", state)
	}
	if want := "genesis " + state.Genesis.String(); !strings.Contains(out.String(), want) {
		t.Fatalf("printed %q, want %q", out.String(), want)
	}
	rec, err := o.record("lane")
	if err != nil || rec == nil || rec.Genesis != state.Genesis {
		t.Fatalf("record %+v %v, want the genesis", rec, err)
	}
	if err := o.genesis(context.Background(), &out, []string{l.url}, "lane", "v1.0.0", pin, ""); err == nil || !strings.Contains(err.Error(), "not a genesis-pending replica") {
		t.Fatalf("a second genesis: %v", err)
	}
	if err := o.genesis(context.Background(), &out, []string{l.url}, "other", "v1.0.0", pin, ""); err == nil {
		t.Fatal("a genesis for another cluster was posted")
	}
}

// A resolve keeps the named entry, and writes the kept chain's allowlist again
// above every head a replica held, so a node that pulled a dropped allowlist
// sees a newer version.
func TestResolveRewritesTheAllowlistAboveTheDroppedBranch(t *testing.T) {
	l := newLiveReplica(t)
	o := l.options()
	pin := []byte(testutil.CDSPinDocument(testutil.TestMeasurement, "launch"))
	if err := o.genesis(context.Background(), &bytes.Buffer{}, []string{l.url}, "lane", "v1.0.0", pin, ""); err != nil {
		t.Fatal(err)
	}
	state := l.waitServing(t)
	writeOpts := &cdsconn.Options{URL: l.url, Insecure: true, OperatorKey: l.keyPath, Timeout: 5 * time.Second}
	if handled, err := WritePolicy(context.Background(), writeOpts, policyDocument(t, "ghcr.io/x/w:v1"), state.PolicyVersion()); !handled || err != nil {
		t.Fatalf("policy write: %v %v", handled, err)
	}
	state = l.waitServing(t)
	keys, _ := cdschain.PublicKeyPEM(&l.key.PublicKey)
	entryAt := func(variant string) cdschain.Entry {
		payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: keys + variant})
		e, err := cdschain.Sign(l.key, cdschain.Body{Cluster: "lane", Seq: state.Head.Seq + 1, Prev: state.Head.Hash, Type: cdschain.TypeOperatorKeys, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	seq := state.Head.Seq + 1
	mine := entryAt("")
	if _, done, err := l.replica.Submit(context.Background(), mine); err != nil || !done {
		t.Fatalf("submit: %v %v", done, err)
	}
	// Another writer's entry at the same seq lands on the store: a fork.
	other, _ := cdschain.PublicKeyPEM(&testKey(t).PublicKey)
	theirs := entryAt(other)
	data, _ := theirs.Encode()
	ctx := context.Background()
	if err := l.store.PutEntry(ctx, theirs.Hash(), data); err != nil {
		t.Fatal(err)
	}
	old, _ := l.store.GetHead(ctx)
	next, _ := json.Marshal(cdschain.Head{V: cdschain.Version, Cluster: "lane", Seq: seq, Hash: theirs.Hash()})
	if err := l.store.CASHead(ctx, old, next); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for l.replica.Status().Fork == nil {
		if time.Now().After(deadline) {
			t.Fatal("the replica did not halt on the fork")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var out bytes.Buffer
	if err := o.resolve(ctx, &out, []string{l.url}, seq, mine.Hash(), nil, 0, false, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "slot 0: resolved") {
		t.Fatalf("printed %q", out.String())
	}
	state = l.waitServing(t)
	if state.Head.Seq <= seq || state.PolicySeq <= seq || state.Head.Seq != state.PolicySeq {
		t.Fatalf("head %d, policy at %d: want the allowlist written again above seq %d", state.Head.Seq, state.PolicySeq, seq)
	}
	resp, err := http.Get(l.url + haapi.ChainPath + "?from=" + strconv.FormatUint(seq, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page haapi.Chain
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || len(page.Entries) == 0 || page.Entries[0].Hash() != mine.Hash() {
		t.Fatalf("chain from seq %d: %v, want the kept entry %s first", seq, err, mine.Hash())
	}
}

// resolve refuses when no replica holds a chain, and the wait after it ends on
// a replica still halted, naming the seq to resolve next.
func TestResolveRefusals(t *testing.T) {
	l := newLiveReplica(t)
	if err := l.options().resolve(context.Background(), &bytes.Buffer{}, []string{l.url}, 1, cdschain.Hash{7}, nil, 0, false, time.Second); err == nil || !strings.Contains(err.Error(), "holds a chain") {
		t.Fatalf("resolve on a pending set: %v", err)
	}
	halted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(haapi.Status{Fork: &haapi.Fork{Seq: 4, Mine: cdschain.Hash{1}, Theirs: cdschain.Hash{2}}})
	}))
	defer halted.Close()
	err := l.options().afterResolve(context.Background(), []string{halted.URL}, 3, time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "resolve seq 4 next") {
		t.Fatalf("after a resolve with a replica still halted: %v", err)
	}
}

// store-credential posts the file to every replica under an operator token,
// and names the replica that refused it.
func TestStoreCredentialReachesEveryReplica(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, key := testChain(t, 1)
	der, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	keyPath, credPath := filepath.Join(dir, "operator.pem"), filepath.Join(dir, "cds-store.kubeconfig")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []byte
	var authorized bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != haapi.StoreCredentialPath {
			http.NotFound(w, r)
			return
		}
		got, _ = io.ReadAll(r.Body)
		authorized = r.Header.Get("Authorization") != ""
	}))
	defer srv.Close()
	cmd := NewCmd()
	cmd.SetArgs([]string{"store-credential", "--url", srv.URL, "--insecure", "--operator-key", keyPath, "--file", credPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil || string(got) != "credential" || !authorized {
		t.Fatalf("store-credential: %v, posted %q, token %v", err, got, authorized)
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer refusing.Close()
	cmd = NewCmd()
	cmd.SetArgs([]string{"store-credential", "--url", refusing.URL, "--insecure", "--operator-key", keyPath, "--file", credPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), refusing.URL) {
		t.Fatalf("store-credential refused: %v, want the replica named", err)
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writeOperatorKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A kept chain with no policy entry has nothing to write again: the refresh
// writes no entry rather than invent an allowlist.
func TestRefreshPolicyWithoutAPolicyWritesNothing(t *testing.T) {
	entries, key := testChain(t, 2)
	replica := &racedReplica{entries: entries}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	w := &writer{o: &options{stateDir: t.TempDir()}, url: srv.URL, client: srv.Client(), key: key}
	if err := w.refreshPolicy(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if h := replica.head(); h.Seq != 1 {
		t.Fatalf("wrote up to head %d on a chain without a policy", h.Seq)
	}
}

// --operator-keys adds its keys to the genesis writers; a missing file is refused.
func TestGenesisWritersAddTheOperatorKeysFile(t *testing.T) {
	_, key := testChain(t, 1)
	_, other := testChain(t, 1)
	otherPEM, _ := cdschain.PublicKeyPEM(&other.PublicKey)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pem")
	_ = os.WriteFile(good, []byte(otherPEM), 0o600)
	writers, err := publicPEM(&key.PublicKey, good)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM([]byte(writers))
	if err != nil || len(keys) != 2 || !keys[0].Equal(&key.PublicKey) || !keys[1].Equal(&other.PublicKey) {
		t.Fatalf("writers %d keys, %v", len(keys), err)
	}
	if _, err := publicPEM(&key.PublicKey, filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("a missing --operator-keys file was accepted")
	}
}

// A route manifest written to a replica set lands as a routes entry whose
// token authorizes exactly that manifest's PUT, so replicas serve it as the
// single CDS would have.
func TestWriteRoutesCarriesATokenForTheManifest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	entries, key := testChain(t, 1)
	replica := &racedReplica{entries: entries}
	srv := httptest.NewServer(replica)
	defer srv.Close()
	signer, err := operatorauth.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"routes":[]}`)
	opts := &cdsconn.Options{URL: srv.URL, Insecure: true, OperatorKey: writeOperatorKey(t, key), Timeout: 5 * time.Second}
	if handled, err := WriteRoutes(context.Background(), opts, manifest, signer); !handled || err != nil {
		t.Fatalf("handled=%v %v", handled, err)
	}
	replica.mu.Lock()
	last := replica.entries[len(replica.entries)-1]
	replica.mu.Unlock()
	b, err := last.Decode()
	if err != nil || b.Type != cdschain.TypeRoutes {
		t.Fatalf("the last entry is %v, %v; want a routes entry", b.Type, err)
	}
	var r cdschain.Routes
	if err := json.Unmarshal(b.Payload, &r); err != nil || string(r.Manifest) != string(manifest) {
		t.Fatalf("routes entry %s: %v", b.Payload, err)
	}
	keys := []*ecdsa.PublicKey{&key.PublicKey}
	if err := operatorauth.VerifyStored(keys, r.Token, http.MethodPut, routes.Path, manifest); err != nil {
		t.Fatalf("the token does not authorize the manifest: %v", err)
	}
	if err := operatorauth.VerifyStored(keys, r.Token, http.MethodPut, routes.Path, []byte(`{"routes":[{}]}`)); err == nil {
		t.Fatal("the token authorizes another manifest")
	}
}

func (f *racedReplica) head() cdschain.Head {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, _ := cdschain.Verify(f.entries)
	return state.Head
}
