package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func do(t *testing.T, method, url, auth string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// countEvictions replaces evictBindings for the test and counts its starts.
func countEvictions(t *testing.T) *atomic.Int32 {
	var n atomic.Int32
	orig := evictBindings
	t.Cleanup(func() { evictBindings = orig })
	evictBindings = func(*sandboxledger.Ledger, <-chan struct{}, time.Duration) { n.Add(1) }
	return &n
}

// haTestCluster is three CDS processes (run) in HA mode on loopback hosts,
// with a fake attestor and a fake Kubernetes API holding a Genesis decree.
type haTestCluster struct {
	t      *testing.T
	kube   *fake.Clientset
	signer *operatorauth.Signer
	// decreeKeyPEM is the operator private key, which also signs decrees.
	decreeKeyPEM []byte
	apiURL       string
	keysPath     string
	hosts        []string
	httpPort     int
	peerPort     int
	tweak        func(*config) // optional, applied to every replica's config
}

func newHATestCluster(t *testing.T, hosts []string) *haTestCluster {
	t.Helper()
	origKube, origAtt := newInClusterKubeClientset, newHAAttestor
	t.Cleanup(func() { newInClusterKubeClientset, newHAAttestor = origKube, origAtt })
	c := &haTestCluster{t: t, kube: fake.NewClientset(), apiURL: newHealthyAttestationApi(t).URL, hosts: hosts, httpPort: freePort(t), peerPort: freePort(t)}
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return c.kube, nil }
	newHAAttestor = func(config) (cdsha.Attestor, error) { return fakeAttestor{"m1"}, nil }
	opKey, keysPath := writeOperatorKeyPair(t)
	c.keysPath = keysPath
	keyPEM, err := certutil.MarshalECKeyPEM(opKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.signer, err = operatorauth.NewSignerFromKeyPEM(keyPEM); err != nil {
		t.Fatal(err)
	}
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "genesis", Kind: cdsha.Genesis,
		BootstrapNode: "n0", ExpiresAt: time.Now().Add(time.Hour)}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	cm, _ := cdsha.DecreeConfigMap("ns", sd)
	if _, err := c.kube.CoreV1().ConfigMaps("ns").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	c.decreeKeyPEM = keyPEM
	return c
}

// start runs the three replicas; ha is every replica's HA config except
// its own address, peers and node name.
func (c *haTestCluster) start(ha haConfig) (chan error, []string) {
	errs := make(chan error, len(c.hosts))
	bases := make([]string, len(c.hosts))
	for i, host := range c.hosts {
		cfg := validRunConfig(c.t, c.apiURL)
		cfg.host, cfg.port, cfg.operatorKeys, cfg.jwtClockSkew = host, c.httpPort, c.keysPath, 1
		h := ha
		h.peers = nil
		for j, other := range c.hosts {
			if j != i {
				h.peers = append(h.peers, fmt.Sprintf("%s:%d", other, c.peerPort))
			}
		}
		h.advertiseIP, h.port, h.nodeName = host, c.peerPort, fmt.Sprintf("n%d", i)
		cfg.ha = h
		if c.tweak != nil {
			c.tweak(&cfg)
		}
		bases[i] = fmt.Sprintf("http://%s:%d", host, c.httpPort)
		go func() { errs <- run(cfg) }()
	}
	return errs, bases
}

// haTemplate is the HA config the tests share.
func (c *haTestCluster) haTemplate(timing cdsha.Timing) haConfig {
	return haConfig{clusterID: "c1", decreeNS: "ns", attestor: "test", pins: []string{"m1"}, operatorKey: c.keysPath,
		seats: 3, timing: timing}
}

// stop ends every replica of run() (they all listen for SIGTERM).
func (c *haTestCluster) stop(errs chan error) {
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	for range c.hosts {
		select {
		case <-errs:
		case <-time.After(20 * time.Second):
			c.t.Error("a replica did not stop")
		}
	}
}

// waitServing waits until every replica's serving state is want. Serving
// means the full server answers (/ca 200), not the pre-join one.
func waitServing(t *testing.T, bases []string, want bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for _, b := range bases {
		for {
			if time.Now().After(deadline) {
				t.Fatalf("%s: serving never became %v", b, want)
			}
			if resp, err := http.Get(b + "/ha/status"); err == nil {
				var st cdsha.Status
				_ = json.NewDecoder(resp.Body).Decode(&st)
				resp.Body.Close()
				full := true
				if want {
					c, _, _ := do(t, http.MethodGet, b+"/ca", "", nil)
					full = c == http.StatusOK
				}
				if st.Serving == want && (want || st.ID != "") && full {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// auth signs one operator write with the real CLI signer.
func (c *haTestCluster) auth(method, path string, body []byte) string {
	c.t.Helper()
	h, err := c.signer.Authorization(method, path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	return h
}

// firstWrite makes the first operator write after Genesis. Tokens issued
// within the clock skew of Genesis are refused (an earlier life of the
// cluster may have spent them), so it retries with a fresh token while
// the answer is 401.
func (c *haTestCluster) firstWrite(base, path string, body []byte) (int, []byte) {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _, resp := do(c.t, http.MethodPut, base+path, c.auth(http.MethodPut, path, body), body)
		if code != http.StatusUnauthorized || time.Now().After(deadline) {
			return code, resp
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Three complete CDS processes in HA mode, driven through the HTTP API: one
// cluster from a Genesis decree, one mesh CA, and every operator write made
// at one replica served by all, with its single-use token spent everywhere.
func TestRunHAReplicasServeOneState(t *testing.T) {
	c := newHATestCluster(t, []string{"127.0.3.10", "127.0.3.11", "127.0.3.12"})
	evictions := countEvictions(t)
	doc := []byte(anySeed(map[string]string{"web": digestA}))
	preGenesis := c.auth(http.MethodPut, "/allowlist", doc)
	// Replicas 1 and 2 stay non-voters: the voter seats are never all held.
	timing := cdsha.DefaultTiming
	timing.Stabilize = time.Hour
	errs, bases := c.start(c.haTemplate(timing))
	t.Cleanup(func() { c.stop(errs) })
	waitServing(t, bases, true)
	// Bindings are evicted at each command's time only, never by a local clock.
	if n := evictions.Load(); n != 0 {
		t.Fatalf("%d replicas run the local binding eviction loop", n)
	}

	// One mesh CA, served by every replica.
	var ca []byte
	for _, b := range bases {
		code, _, body := do(t, http.MethodGet, b+"/ca", "", nil)
		if code != http.StatusOK || (ca != nil && !bytes.Equal(body, ca)) {
			t.Fatalf("%s /ca: %d, same=%v", b, code, bytes.Equal(body, ca))
		}
		ca = body
	}

	// A rolling restart waits for readiness: a non-voter is not ready
	// while a voter seat is empty, though it serves.
	if code, _, _ := do(t, http.MethodGet, bases[0]+"/readyz", "", nil); code != http.StatusOK {
		t.Fatalf("the voter is not ready: %d", code)
	}
	if code, _, _ := do(t, http.MethodGet, bases[1]+"/readyz", "", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("a non-voter is ready while a seat is empty: %d", code)
	}

	// A challenge issued at one replica is redeemed at another (the shared
	// key): /attest gets past the challenge to the CSR.
	var ch struct {
		Challenge string `json:"challenge"`
	}
	_, _, body := do(t, http.MethodPost, bases[0]+"/authenticate", "", nil)
	if err := json.Unmarshal(body, &ch); err != nil || ch.Challenge == "" {
		t.Fatalf("/authenticate: %s", body)
	}
	attest, _ := json.Marshal(map[string]any{"challenge": ch.Challenge, "csr": "x", "evidence": map[string]any{}})
	if _, _, body := do(t, http.MethodPost, bases[1]+"/attest", "", attest); strings.Contains(string(body), "challenge") {
		t.Fatalf("a challenge from replica 0 refused at replica 1: %s", body)
	}

	// A token signed before Genesis may have been spent by an earlier life.
	if code, _, _ := do(t, http.MethodPut, bases[0]+"/allowlist", preGenesis, doc); code != http.StatusUnauthorized {
		t.Fatalf("a token signed before Genesis: %d", code)
	}
	// A whole-document write at replica 0, served by 1 and 2 with one ETag.
	if code, body := c.firstWrite(bases[0], "/allowlist", doc); code != http.StatusNoContent {
		t.Fatalf("PUT /allowlist at replica 0: %d %s", code, body)
	}
	// Followers serve reads from their own applied state, so they may lag
	// the write briefly (bounded staleness), then serve the same document.
	_, h0, _ := do(t, http.MethodGet, bases[0]+"/allowlist", "", nil)
	for _, b := range bases[1:] {
		waitServed(t, b, func(code int, h http.Header, body []byte) bool {
			return code == http.StatusOK && h.Get("ETag") == h0.Get("ETag") && strings.Contains(string(body), digestA)
		}, "/allowlist", "the allowlist written at replica 0")
	}
	// A token spent at replica 0 is refused at another replica.
	tok := c.auth(http.MethodPut, "/allowlist", doc)
	if code, _, body := do(t, http.MethodPut, bases[0]+"/allowlist", tok, doc); code != http.StatusNoContent {
		t.Fatalf("second PUT /allowlist at replica 0: %d %s", code, body)
	}
	if code, _, _ := do(t, http.MethodPut, bases[2]+"/allowlist", tok, doc); code < 400 {
		t.Fatalf("a spent operator token was accepted at another replica: %d", code)
	}
	// A per-entry write at replica 1 reaches replica 0.
	entry := []byte(`{"label":"ghcr.io/x/api:v1","containers":[{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","command":{"policy":"any"},"args":{"policy":"any"}}]}`)
	if code, _, body := do(t, http.MethodPut, bases[1]+"/allowlist/workloads/api", c.auth(http.MethodPut, "/allowlist/workloads/api", entry), entry); code != http.StatusNoContent {
		t.Fatalf("PUT workload at replica 1: %d %s", code, body)
	}
	waitServed(t, bases[0], func(_ int, _ http.Header, body []byte) bool { return strings.Contains(string(body), "2222222222") },
		"/allowlist", "the entry written at replica 1")
	// Every replica serves the same history, signature included.
	for _, b := range bases {
		waitServed(t, b, func(_ int, _ http.Header, body []byte) bool { return strings.Contains(string(body), "2222222222") },
			"/allowlist", "the entry written at replica 1")
	}
	_, _, hist0 := do(t, http.MethodGet, bases[0]+"/allowlist/history", "", nil)
	for _, b := range bases[1:] {
		if _, _, h := do(t, http.MethodGet, b+"/allowlist/history", "", nil); !bytes.Equal(h, hist0) {
			t.Fatalf("%s serves another history:\n%s\nvs\n%s", b, h, hist0)
		}
	}
}

// waitServed polls base+path until ok holds, failing after a few seconds: a
// follower serves a committed write once it has applied it.
func waitServed(t *testing.T, base string, ok func(int, http.Header, []byte) bool, path, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, h, body := do(t, http.MethodGet, base+path, "", nil)
		if ok(code, h, body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s does not serve %s: %d etag %q", base, what, code, h.Get("ETag"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An HA replica refuses writes once its allowlist volume is too full for a
// replacement replica to copy the store.
func TestRunHAFullStoreRefusesWrites(t *testing.T) {
	c := newHATestCluster(t, []string{"127.0.3.20"})
	c.tweak = func(cfg *config) { cfg.allowlistMaxBytes = resource.QuantityValue{Quantity: resource.MustParse("1Ki")} }
	ha := c.haTemplate(cdsha.DefaultTiming)
	ha.seats, ha.peersDNS = 1, "localhost" // no other replica answers
	errs, bases := c.start(ha)
	t.Cleanup(func() { c.stop(errs) })
	waitServing(t, bases, true)
	if code, body := c.firstWrite(bases[0], "/allowlist", []byte(anySeed(map[string]string{"web": digestA}))); code != http.StatusInsufficientStorage {
		t.Fatalf("a write to a full store: %d %s", code, body)
	}
}
