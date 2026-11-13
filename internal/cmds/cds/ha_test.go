package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A replica of a set signs a leaf only while it serves, checked right
// before signing (and the negative control: it signs when serving).
func TestAttestRefusedWhileTheReplicaServesNothing(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	for _, serving := range []error{nil, errors.New("unconfirmed: no gossip")} {
		h := newTestAttestHandler(t, stub.URL(), nil)
		h.Serving = func(context.Context) error { return serving }
		csrPEM, _ := generateCSR(t)
		w := postAttest(t, h, issueChallenge(t, h), csrPEM)
		if want := map[bool]int{true: http.StatusOK, false: http.StatusServiceUnavailable}[serving == nil]; w.Code != want {
			t.Fatalf("serving=%v: /attest = %d, want %d: %s", serving, w.Code, want, w.Body)
		}
	}
}

// A replica set takes allowlist and routes writes as chain entries: their
// old PUT routes answer 409 whatever the replica's state, and /readyz and
// /ha pass the gate.
func TestHAGateRefusesOldWrites(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	mesh, err := issuer.NewMeshCA("gate", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := cdsha.New(cdsha.Config{Cluster: "lane", Endpoints: []string{"a:1"}, Mesh: mesh}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := haGate(pending)(next)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPut, "/allowlist", http.StatusConflict},
		{http.MethodPut, "/routes", http.StatusConflict},
		// A single replica holds secrets: their PUT is gated on serving.
		{http.MethodPut, "/secrets/app/key", http.StatusServiceUnavailable},
		{http.MethodGet, "/readyz", http.StatusTeapot},
		{http.MethodGet, "/ha/status", http.StatusTeapot},
		{http.MethodGet, "/allowlist", http.StatusServiceUnavailable},
		// A pod's secret release is brokered only while the replica serves.
		{http.MethodPost, secretbroker.PodRoute, http.StatusServiceUnavailable},
		// An allowlist document by digest: the client re-hashes it.
		{http.MethodGet, "/allowlist/objects/sha256/" + strings.Repeat("ab", 32), http.StatusTeapot},
	} {
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}

// A replica VM's runtime disk may carry the etcd client file of its store.
func TestRuntimeDiskSelectsTheEtcdStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "etcd.yaml"), []byte("endpoints: [\"http://127.0.0.1:1\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{measured: &cdsconfig.Config{ClusterID: "lane"}, ha: haConfig{runtimeDir: dir}}
	st, err := openChainStore(context.Background(), cfg, 3)
	if _, isEtcd := st.(*cdsha.Etcd); err != nil || !isEtcd {
		t.Fatalf("store %T, %v", st, err)
	}
	if st, err := openChainStore(context.Background(), config{measured: cfg.measured, ha: haConfig{runtimeDir: t.TempDir()}}, 3); err != nil || st != nil {
		t.Fatalf("without the file: %T %v, want the credential path", st, err)
	}
}

// A replica set of more than one replica serves no secrets; a single
// replica keeps the existing rule.
func TestReplicaSetRefusesSecrets(t *testing.T) {
	images := []remote.ImagePin{{Name: "node"}}
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := haSecrets(&cdsconfig.HA{Endpoints: []string{"a:1", "b:1", "c:1"}}, images, hosts); ok {
		t.Fatal("a set of three serves secrets")
	}
	if ok, why := haSecrets(&cdsconfig.HA{Endpoints: []string{"a:1"}}, images, hosts); !ok {
		t.Fatalf("a single replica refuses secrets: %s", why)
	}
	ledger := sandboxledger.New(time.Hour, 10)
	if haLedger(&cdsconfig.HA{Endpoints: []string{"a:1", "b:1", "c:1"}}, ledger) != nil {
		t.Fatal("a set of three keeps a sandbox ledger")
	}
	if haLedger(&cdsconfig.HA{Endpoints: []string{"a:1"}}, ledger) == nil || haLedger(nil, ledger) == nil {
		t.Fatal("a single CDS lost its sandbox ledger")
	}
}

// A replica serves each allowlist it serves, the seed and then every policy
// entry, at a version no other document had and above the last, so a node
// that pulled the seed is never answered 304 for the first policy; every
// replica gives it the same version, the chain's.
func TestReplicaServesEachAllowlistAtANewVersion(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	seed := parseSeed(t, map[string]string{"attestation-api": digestA})
	if err := seedWorkloads(&store, seed); err != nil {
		t.Fatal(err)
	}
	policy := func(d string) []byte {
		raw, _ := parseSeed(t, map[string]string{"attestation-api": digestA, "web": d}).Canonical()
		return raw
	}
	served, last := map[string][]byte{}, uint64(0)
	for _, s := range []*cdschain.State{{}, {Policy: policy(digestB), PolicySeq: 1}, {Policy: policy(digestA), PolicySeq: 3}} {
		if err := servePolicy(&store, s, seed, s.Policy == nil); err != nil {
			t.Fatal(err)
		}
		al, version, err := store.LoadAll()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := al.Canonical()
		n, _ := strconv.ParseUint(version, 10, 64)
		if prev, ok := served[version]; (ok && !bytes.Equal(prev, raw)) || n <= last || version != s.PolicyVersion() {
			t.Fatalf("policy seq %d served at version %s after version %d", s.PolicySeq, version, last)
		}
		served[version], last = raw, n
	}
}

// A replica that adopts a chain counts a policy it had not served as written
// now: nodes get it only once the router-first delay has passed since then,
// however old the entry, so a restart adds the delay and never skips it. Until
// then a node pull is told to retry, never handed the launch seed the history
// starts with.
func TestAdoptedPolicyWaitsOutTheNodeDelay(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	store.SetNodeDelay(30 * time.Second)
	seed := parseSeed(t, map[string]string{"attestation-api": digestA})
	if err := seedWorkloads(&store, seed); err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	serve := chainPolicyServer(&store, seed)
	h := allowlist.Handler{Store: &store}
	nodePull := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist?"+pkgallowlist.NodeQuery, nil))
		return w
	}
	if w := nodePull(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("before the replica serves its chain, a node pull = %d, want 503", w.Code)
	}
	raw, _ := parseSeed(t, map[string]string{"attestation-api": digestA, "web": digestB}).Canonical()
	if err := serve(&cdschain.State{Policy: raw, PolicySeq: 7}); err != nil {
		t.Fatal(err)
	}
	adopted := time.Now()
	newest, _, err := store.Served()
	if err != nil {
		t.Fatal(err)
	}
	if w := nodePull(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("within the delay, a node pull = %d %s, want 503", w.Code, w.Body.String())
	}
	if _, _, err := store.InEffect(adopted.Add(31 * time.Second)); err != nil {
		t.Fatalf("nodes still lack the adopted policy after the delay: %v", err)
	}
	if body, _, _ := store.InEffect(adopted.Add(31 * time.Second)); !bytes.Equal(body, newest) {
		t.Fatal("after the delay nodes get another allowlist than the chain's")
	}
}

// Any replica serves every policy of its chain by digest, not only the one it
// served since it started, and whether or not it serves: a router asks a
// replica for the allowlist a backend's leaf was stamped under, so once every
// replica has restarted, or while one is not confirmed, the stamps must
// still resolve.
func TestReplicaServesEveryChainPolicyByDigest(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	seed := parseSeed(t, map[string]string{"attestation-api": digestA})
	if err := seedWorkloads(&store, seed); err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	operator, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := issuer.NewMeshCA("lane", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serve := chainPolicyServer(&store, seed)
	replica, err := cdsha.New(cdsha.Config{
		Cluster: "lane", Endpoints: []string{"a:1"},
		OperatorKeys: []*ecdsa.PublicKey{&operator.PublicKey},
		Gossip:       100 * time.Millisecond, PeerTimeout: time.Second, StoreTimeout: time.Second,
		Mesh:      mesh,
		SelfCheck: func(context.Context, string) (bool, error) { return true, nil },
		OnState: func(s *cdschain.State) {
			if err := serve(s); err != nil {
				t.Error(err)
			}
		},
	}, cdsha.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := replica.Pending(true)
	if err != nil {
		t.Fatal(err)
	}
	opPEM, _ := cdschain.PublicKeyPEM(&operator.PublicKey)
	genesis, _ := json.Marshal(cdschain.Genesis{
		Endpoints: []string{"a:1"}, Members: []string{pending.Member}, OperatorKeys: opPEM, CAKey: pending.CAKey,
		Accepted: []cdschain.Build{{Measurements: testutil.CDSPinDocument(strings.Repeat("a1", 48), "launch"), Version: "v1.0.0"}},
	})
	chain := []cdschain.Entry{}
	sign := func(b cdschain.Body) {
		b.Cluster = "lane"
		if len(chain) > 0 {
			b.Seq, b.Prev = uint64(len(chain)), chain[len(chain)-1].Hash()
		}
		e, err := cdschain.Sign(operator, b)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, e)
	}
	sign(cdschain.Body{Type: cdschain.TypeGenesis, Payload: genesis})
	var policies [][]byte
	for _, workloads := range []map[string]string{
		{"attestation-api": digestA, "web": digestA},
		{"attestation-api": digestA, "web": digestB},
		{"attestation-api": digestA, "web": digestB, "db": digestA},
	} {
		raw, _ := parseSeed(t, workloads).Canonical()
		payload, _ := json.Marshal(cdschain.Policy{Allowlist: raw})
		sign(cdschain.Body{Type: cdschain.TypePolicy, Payload: payload})
		policies = append(policies, raw)
	}
	if err := replica.Start(cdsha.Handoff{Entries: chain}); err != nil {
		t.Fatal(err)
	}
	router := newRouter(dependencies{
		HA:               replica,
		AllowlistHandler: allowlist.Handler{Store: &store},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	})
	get := func(raw []byte) *httptest.ResponseRecorder {
		sum := sha256.Sum256(raw)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/allowlist/objects/sha256/"+hex.EncodeToString(sum[:]), nil))
		return w
	}
	// Before it serves (its build is not checked yet), and after.
	if w := get(policies[0]); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), policies[0]) {
		t.Errorf("a replica that serves nothing yet answers a document by digest with %d %q", w.Code, w.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go replica.Run(ctx)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := replica.Current(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the replica does not serve: %v", err)
		}
	}
	seedRaw, _ := seed.Canonical()
	for i, raw := range append(policies, seedRaw) {
		if w := get(raw); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), raw) {
			t.Errorf("document %d by digest = %d %q, want its bytes", i+1, w.Code, w.Body.String())
		}
	}
	if w := get([]byte("no document")); w.Code != http.StatusNotFound {
		t.Errorf("a digest outside the chain and history = %d, want 404", w.Code)
	}
}

// A replica certifies the node images its chain's newest nodes entry names,
// from the next request on, and the launch file's again once the chain holds
// none (a resolve dropped it).
func TestReplicaCertifiesTheChainsNodeImages(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL(), nil)
	launch := refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{imagePin(t, "node-next", otherLaunchDigest)}}
	nodes, err := newNodeSet(launch)
	if err != nil {
		t.Fatal(err)
	}
	h.Images = nodes.images
	attest := func() int {
		csrPEM, _ := generateCSR(t)
		return postAttest(t, h, issueChallenge(t, h), csrPEM).Code
	}
	if code := attest(); code == http.StatusOK {
		t.Fatal("a node outside the launch file's set was certified")
	}
	worker, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{imagePin(t, "worker", testLaunchDigest)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := serveNodes(nodes, string(worker), launch, nil); err != nil {
		t.Fatal(err)
	}
	if code := attest(); code != http.StatusOK {
		t.Fatalf("a node the chain's nodes entry names: status %d", code)
	}
	if err := serveNodes(nodes, "", launch, nil); err != nil {
		t.Fatal(err)
	}
	if code := attest(); code == http.StatusOK {
		t.Fatal("a node certified after the chain dropped its nodes entry")
	}
}

// A replica set's nodes and operator-keys entries are held to the launch
// file's rule that a Pod launch key is no node or operator authority: a write
// naming one is refused, and a nodes entry naming one certifies no node on
// any replica.
func TestAPodLaunchKeyIsNoNodeOrOperatorAuthorityOnTheChain(t *testing.T) {
	keyPEM := func() string {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := cdschain.PublicKeyPEM(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	podKey, otherKey := keyPEM(), keyPEM()
	pods := []remote.ImagePin{{Name: "pod", Anchor: []byte(podKey)}}
	nodesDoc := func(anchor string) string {
		doc, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{{
			Name: "worker", Digest: bytes.Repeat([]byte{0x21}, refvalues.DigestSize), Anchor: []byte(anchor),
			Registers: map[int][]byte{1: bytes.Repeat([]byte{0x22}, refvalues.DigestSize), 2: bytes.Repeat([]byte{0x23}, refvalues.DigestSize)},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(doc)
	}
	body := func(typ cdschain.Type, payload any) cdschain.Body {
		raw, _ := json.Marshal(payload)
		return cdschain.Body{Type: typ, Payload: raw}
	}
	for _, tc := range []struct {
		name    string
		body    cdschain.Body
		refused bool
	}{
		{"nodes naming the Pod launch key", body(cdschain.TypeNodes, cdschain.Nodes{Nodes: nodesDoc(podKey)}), true},
		{"nodes naming another key", body(cdschain.TypeNodes, cdschain.Nodes{Nodes: nodesDoc(otherKey)}), false},
		{"operator keys naming the Pod launch key", body(cdschain.TypeOperatorKeys, cdschain.OperatorKeys{Keys: otherKey + podKey}), true},
		{"operator keys naming other keys", body(cdschain.TypeOperatorKeys, cdschain.OperatorKeys{Keys: otherKey}), false},
	} {
		if err := chainValidator(pods, nil, nil)(tc.body); (err != nil) != tc.refused {
			t.Errorf("%s: %v, refused want %v", tc.name, err, tc.refused)
		}
	}
	nodes, err := newNodeSet(refvalues.ReferenceValues{Family: teetypes.FamilyTDX})
	if err != nil {
		t.Fatal(err)
	}
	for anchor, certified := range map[string]int{podKey: 0, otherKey: 1} {
		if err := serveNodes(nodes, nodesDoc(anchor), refvalues.ReferenceValues{}, pods); err != nil {
			t.Fatal(err)
		}
		if got := len(nodes.images()); got != certified {
			t.Errorf("a chain node set naming the %s key certifies %d images, want %d", map[bool]string{true: "Pod launch", false: "other"}[anchor == podKey], got, certified)
		}
	}
}
