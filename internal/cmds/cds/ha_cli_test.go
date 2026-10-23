package cds

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
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testKeyPEM returns a P-256 key and its PEM public key.
func testKeyPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func runHA(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newHACmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestHADecreeCLI(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	for name, path := range map[string]string{"sec1": writePEM(t, "EC PRIVATE KEY", sec1), "pkcs8": writePEM(t, "PRIVATE KEY", pkcs8)} {
		out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", path, "--kind", "Genesis", "--bootstrap-node", "n0")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var cm struct {
			Kind string            `json:"kind"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &cm); err != nil || cm.Kind != "ConfigMap" {
			t.Fatalf("%s: output %q: %v", name, out, err)
		}
		var sd cdsha.SignedDecree
		if err := json.Unmarshal([]byte(cm.Data["decree"]), &sd); err != nil || sd.Decree.Kind != cdsha.Genesis || sd.Decree.IntentID == "" {
			t.Fatalf("%s: decree %+v: %v", name, sd, err)
		}
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err := cdsha.CheckDecree(sd, cdsha.PreGenesis("c1", pub), time.Now()); err != nil {
			t.Fatalf("%s: the CLI's decree does not verify: %v", name, err)
		}
	}
	keyPath := writePEM(t, "EC PRIVATE KEY", sec1)
	if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", keyPath, "--kind", "RotateKey"); err == nil {
		t.Fatal("RotateKey without the acknowledgement flag")
	}
	if out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", keyPath, "--kind", "RotateKey", "--i-understand-rotation-forks-the-cluster"); err == nil || !strings.Contains(out, "--base-epoch") {
		t.Fatalf("RotateKey without --base-epoch (replicas would refuse it, silently): %v", err)
	}
	out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", keyPath, "--kind", "RotateKey", "--base-epoch", "1", "--i-understand-rotation-forks-the-cluster")
	if err != nil || !strings.Contains(out, "WARNING") {
		t.Fatalf("RotateKey without pins must warn (D14): %v %q", err, out)
	}
	notPEM := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(notPEM, []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"missing":    filepath.Join(t.TempDir(), "none"),
		"not PEM":    notPEM,
		"unparsable": writePEM(t, "PRIVATE KEY", []byte("junk")),
	} {
		if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "Genesis", "--bootstrap-node", "n0"); err == nil {
			t.Errorf("%s operator key accepted", name)
		}
	}
}

func TestHARecoverDecreeCLI(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(key)
	p := writePEM(t, "EC PRIVATE KEY", sec1)
	if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "Recover", "--bootstrap-node", "n1"); err == nil {
		t.Fatal("Recover without the acknowledgement")
	}
	if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "Recover", "--i-understand-recover-is-break-glass"); err == nil {
		t.Fatal("Recover without a node")
	}
	if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "UpdateMeasurements", "--measurements", "m", "--bootstrap-node", "n1"); err == nil {
		t.Fatal("UpdateMeasurements naming a node")
	}
	out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "Recover", "--bootstrap-node", "n1", "--base-epoch", "3", "--i-understand-recover-is-break-glass")
	if err != nil || !strings.Contains(out, "RotateKey") {
		t.Fatalf("Recover: %v %q", err, out)
	}
}

func TestHAStatusCLI(t *testing.T) {
	serve := func(hb cdsha.Status, code int) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ha/status" || code != http.StatusOK {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			_ = json.NewEncoder(w).Encode(hb)
		}))
		t.Cleanup(s.Close)
		return s
	}
	a := serve(cdsha.Status{Epoch: 2, CAFingerprint: "aa", Serving: true}, http.StatusOK)
	b := serve(cdsha.Status{Epoch: 2, CAFingerprint: "aa", Serving: true}, http.StatusOK)
	stale := serve(cdsha.Status{Epoch: 1, CAFingerprint: "bb", Serving: true}, http.StatusOK)
	broken := serve(cdsha.Status{}, http.StatusInternalServerError)
	if out, err := runHA(t, "status", "--insecure", a.URL, b.URL); err != nil || !strings.Contains(out, "epoch=2") {
		t.Fatalf("agreeing replicas: %v %q", err, out)
	}
	// A replica serves armTLS: plaintext is refused unless asked for.
	if out, err := runHA(t, "status", a.URL); err == nil || !strings.Contains(out, "refusing plaintext") {
		t.Fatalf("plaintext status without --insecure: %v %q", err, out)
	}
	if _, err := runHA(t, "status", "--insecure", a.URL, stale.URL); err == nil {
		t.Fatal("diverging replicas reported as healthy")
	}
	if out, err := runHA(t, "status", "--insecure", a.URL, broken.URL); err == nil || !strings.Contains(out, "ERROR") {
		t.Fatalf("unreachable replica: %v %q", err, out)
	}
	if err := reportDivergence([]cdsha.Status{{Epoch: 1, CAFingerprint: "a"}}, 1); err == nil {
		t.Fatal("a replica that is not serving reported as healthy")
	}
}

func TestLoadHAOperatorKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der256, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	raw := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der256})
	if got, err := loadHAOperatorKey("", raw); err != nil || !bytes.Equal(got, der256) {
		t.Fatalf("PEM bytes: %v", err)
	}
	if got, err := loadHAOperatorKey(writePEM(t, "PUBLIC KEY", der256), nil); err != nil || !bytes.Equal(got, der256) {
		t.Fatalf("PEM file: %v", err)
	}
	for name, c := range map[string]struct {
		path string
		raw  []byte
	}{
		"none":         {},
		"missing file": {path: filepath.Join(t.TempDir(), "none")},
		"no PEM":       {raw: []byte("plain")},
		"not a key":    {raw: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})},
		"P-384":        {raw: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384})},
	} {
		if _, err := loadHAOperatorKey(c.path, c.raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadHAConfigFile(t *testing.T) {
	write := func(c nodeservices.CDSHAConfig) string {
		raw, _ := json.Marshal(c)
		p := filepath.Join(t.TempDir(), "cds-ha.json")
		_ = os.WriteFile(p, raw, 0o600)
		return p
	}
	img := launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}}
	h := haConfig{configFile: write(nodeservices.CDSHAConfig{ClusterID: "c1", DecreeKey: "PEM", Image: img})}
	if err := loadHAConfigFile(&h); err != nil {
		t.Fatal(err)
	}
	want, _ := cdsha.ImagePin("tdx", img.Measurement, img.RTMRs)
	if h.clusterID != "c1" || len(h.pins) != 1 || h.pins[0] != want || string(h.operatorKeyPEM) != "PEM" {
		t.Fatalf("loaded %+v", h)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	for name, path := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "none"),
		"not JSON":  bad,
		"bad image": write(nodeservices.CDSHAConfig{ClusterID: "c1", Image: launchconfig.Image{Platform: "tdx"}}),
	} {
		h := haConfig{configFile: path}
		if err := loadHAConfigFile(&h); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDNSPeersDropsSelf(t *testing.T) {
	peers, err := dnsPeers("localhost", "127.0.0.1", 9443)(context.Background())
	if err != nil {
		t.Skipf("no resolver for localhost: %v", err)
	}
	for _, p := range peers {
		if strings.HasPrefix(p, "127.0.0.1:") {
			t.Fatalf("self in peers: %v", peers)
		}
	}
	if _, err := dnsPeers("does-not-exist.invalid", "", 1)(context.Background()); err == nil {
		t.Fatal("unresolvable peer name gave no error")
	}
}

type fakeAttestor struct{ measurement string }

func (a fakeAttestor) Evidence(rd [48]byte) ([]byte, error) {
	return json.Marshal(map[string]any{"m": a.measurement, "rd": rd})
}

func (fakeAttestor) Verify(ev []byte) (cdsha.Claims, error) {
	var e struct {
		M  string   `json:"m"`
		RD [48]byte `json:"rd"`
	}
	if err := json.Unmarshal(ev, &e); err != nil || e.M == "" {
		return cdsha.Claims{}, errors.New("bad evidence")
	}
	return cdsha.Claims{Measurement: e.M, ReportData: e.RD}, nil
}

// Before it joins, a replica serves no CA, derives no challenge key and
// reports itself as not serving; the gate answers 503 on serving routes.
func TestHAHandlersBeforeJoin(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	al, _ := allowlist.OpenInMemory()
	defer al.Close()
	node, err := cdsha.NewNode(cdsha.Config{ClusterID: "c1", NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1",
		Attestor: fakeAttestor{"m1"}, BakedPins: []string{"m1"}, OperatorPubKey: pub, Seats: 3,
		Peers:     func(context.Context) ([]string, error) { return nil, nil },
		Allowlist: &al, Secrets: secrets.NewMemoryStore(4, 2, 64), Ledger: sandboxledger.New(time.Hour, 4)})
	if err != nil {
		t.Fatal(err)
	}
	if (haMeshCA{node: node}).Current().CA != nil || haChallengeKey(node, "issuance")() != nil {
		t.Fatal("a replica that has not joined serves key material")
	}
	w := httptest.NewRecorder()
	serveJSON(node.Status)(w, httptest.NewRequest(http.MethodGet, "/ha/status", nil))
	var st cdsha.Status
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil || st.Serving || st.Joined {
		t.Fatalf("status %+v: %v", st, err)
	}
	// No pin decree yet: clients keep their launch-document pins.
	pw := httptest.NewRecorder()
	haPins(node)(pw, httptest.NewRequest(http.MethodGet, "/ha/pins", nil))
	if pw.Code != http.StatusNotFound {
		t.Fatalf("/ha/pins before any pin decree: %d", pw.Code)
	}
	// /ca refuses rather than serving an empty bundle.
	cw := httptest.NewRecorder()
	handleCA(haMeshCA{node: node})(cw, httptest.NewRequest(http.MethodGet, "/ca", nil))
	if cw.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ca before join: %d", cw.Code)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gated := haGate(node.Serving, ok)
	for path, want := range map[string]int{"/attest": 503, "/secrets/x": 503, "/allowlist": 503, "/ca": 503, "/healthz": 200, "/ha/status": 200, "/ha/pins": 200, "/metrics": 200} {
		w := httptest.NewRecorder()
		gated.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
}

// newHANode and haStart wire the flags: the base config builds a replica, and
// each missing or bad input fails with its own error before anything serves.
func TestHAStartWiring(t *testing.T) {
	origKube, origAtt := newInClusterKubeClientset, newHAAttestor
	t.Cleanup(func() { newInClusterKubeClientset, newHAAttestor = origKube, origAtt })
	nodeAttestor := newHAAttestor
	newHAAttestor = func(cfg config) (cdsha.Attestor, error) {
		if cfg.ha.attestor == "fake" {
			return fakeAttestor{"m1"}, nil
		}
		return nodeAttestor(cfg)
	}
	al, _ := allowlist.OpenInMemory()
	defer al.Close()
	st := haStores{allowlist: &al, secrets: secrets.NewMemoryStore(4, 2, 64), ledger: sandboxledger.New(time.Hour, 4)}
	_, pub := testKeyPEM(t)
	base := config{requestTimeout: time.Second, ha: haConfig{
		clusterID: "c1", decreeNS: "ns", peersDNS: "peers.invalid", advertiseIP: "127.0.0.1", nodeName: "n0", attestor: "fake",
		pins: []string{"m1"}, operatorKeyPEM: pub, seats: 3, timing: cdsha.DefaultTiming}}
	// The replica replaces what the store held before it joined, and takes
	// every write: a binding is refused until the cluster commits it.
	seeded, _ := pkgallowlist.ParseJSON([]byte(anySeed(map[string]string{"web": digestA})))
	if err := al.ReplaceAll(seeded); err != nil {
		t.Fatal(err)
	}
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return fake.NewClientset(), nil }
	if _, err := newHANode(base, st); err != nil {
		t.Fatal(err)
	}
	if doc, _, err := al.LoadAll(); err != nil || len(doc.Workloads) != 0 {
		t.Fatalf("the allowlist kept rows from before the replica: %v %v", doc.Workloads, err)
	}
	if st.ledger.Record("sb", "10.0.0.1") {
		t.Fatal("a sandbox binding was taken on one replica alone")
	}
	for name, c := range map[string]struct {
		mutate func(c *config)
		want   string // "" builds the replica
	}{
		"base":             {func(*config) {}, ""},
		"static peers":     {func(c *config) { c.ha.peersDNS, c.ha.peers = "", []string{"127.0.0.2:1"} }, ""},
		"no peers":         {func(c *config) { c.ha.peersDNS = "" }, "are required with --ha-cluster-id"},
		"no node name":     {func(c *config) { c.ha.nodeName = "" }, "are required with --ha-cluster-id"},
		"no decree ns":     {func(c *config) { c.ha.decreeNS = "" }, "are required with --ha-cluster-id"},
		"unknown attestor": {func(c *config) { c.ha.attestor = "nope" }, `attestor "nope" not available`},
		"no operator key":  {func(c *config) { c.ha.operatorKeyPEM = nil }, "--ha-operator-key is required"},
		"no kube client": {func(*config) {
			newInClusterKubeClientset = func() (kubernetes.Interface, error) { return nil, errors.New("no cluster") }
		}, "no cluster"},
		"no advertise address": {func(c *config) { c.ha.advertiseIP = "" }, "--ha-advertise-ip"},
		"recovery key not PEM": {func(c *config) { c.ha.recoveryKeyPEM = []byte("not pem") }, "recovery key: no PEM block"},
	} {
		newInClusterKubeClientset = func() (kubernetes.Interface, error) { return fake.NewClientset(), nil }
		cfg := base
		c.mutate(&cfg)
		_, err := newHANode(cfg, st)
		if c.want == "" && err != nil {
			t.Errorf("%s: %v", name, err)
		} else if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	if _, _, err := haStart(context.Background(), config{ha: haConfig{configFile: filepath.Join(t.TempDir(), "none")}}, st); err == nil || !strings.Contains(err.Error(), "--ha-config") {
		t.Fatalf("haStart without its --ha-config file: %v", err)
	}
	if n, _, err := haStart(context.Background(), config{}, st); err != nil || n != nil {
		t.Fatalf("singleton: %v", err)
	}
}

// The pre-join server answers health and status, and refuses malformed or
// misdirected restores.
func TestPreJoinRestoreHandler(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	al, _ := allowlist.OpenInMemory()
	defer al.Close()
	node, err := cdsha.NewNode(cdsha.Config{ClusterID: "c1", NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1",
		Attestor: fakeAttestor{"m1"}, BakedPins: []string{"m1"}, OperatorPubKey: pub, Seats: 3,
		Peers:     func(context.Context) ([]string, error) { return nil, nil },
		Allowlist: &al, Secrets: secrets.NewMemoryStore(4, 2, 64), Ledger: sandboxledger.New(time.Hour, 4)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = node.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	mux := preJoinMux(node)
	call := func(method, path string, body string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w.Code
	}
	if call(http.MethodGet, "/healthz", "") != http.StatusOK || call(http.MethodGet, "/ha/status", "") != http.StatusOK {
		t.Fatal("health and status")
	}
	if call(http.MethodGet, "/readyz", "") != http.StatusServiceUnavailable {
		t.Fatal("ready before dead_after without a cluster")
	}
	if call(http.MethodPost, "/ha/restore", "{") != http.StatusBadRequest {
		t.Fatal("malformed restore")
	}
	sd, _ := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "r", Kind: cdsha.Restore, BootstrapNode: "n9",
		SnapshotSHA256: cdsha.SnapshotSHA256([]byte("s")), ExpiresAt: time.Now().Add(time.Hour)}, k)
	body, _ := json.Marshal(RestoreRequest{Decree: sd, Snapshot: []byte("s")})
	// 409 until Run is up; then a restore for another node is misdirected.
	if err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) {
		return call(http.MethodPost, "/ha/restore", string(body)) == http.StatusMisdirectedRequest, nil
	}); err != nil {
		t.Fatal("a restore for another node is not refused as misdirected")
	}
	sd.Decree.BootstrapNode = "n0" // signature no longer matches
	body, _ = json.Marshal(RestoreRequest{Decree: sd, Snapshot: []byte("s")})
	if c := call(http.MethodPost, "/ha/restore", string(body)); c != http.StatusConflict {
		t.Fatalf("restore with a bad signature: %d", c)
	}
	// Anything else is a retryable 503 (a client the Service sent here
	// retries), never a 404 that reads as "CDS has no such route".
	for _, path := range []string{"/allowlist", "/ca", "/secrets/x"} {
		if c := call(http.MethodGet, path, ""); c != http.StatusServiceUnavailable {
			t.Fatalf("pre-join %s: %d", path, c)
		}
	}
}

// recover refuses what it cannot read before it reaches any replica.
func TestHARecoverCLIErrors(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	keyPath := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	garbage := filepath.Join(dir, "garbage.json")
	_ = os.WriteFile(garbage, []byte("{"), 0o600)
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"items":[]}`), 0o600)
	// A real backup sealed to k, so the key paths are what fails.
	b, _ := cdsha.SealBackup(&k.PublicKey, cdsha.BackupMeta{ClusterID: "c1", Epoch: 1, Index: 5}, []byte("{}"))
	kube := fake.NewClientset()
	if err := (cdsha.KubeDecrees{Client: kube, Namespace: "ns", ClusterID: "c1"}).PutBackup(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	list, _ := kube.CoreV1().ConfigMaps("ns").List(context.Background(), metav1.ListOptions{})
	raw, _ := json.Marshal(list)
	good := filepath.Join(dir, "backup.json")
	_ = os.WriteFile(good, raw, 0o600)
	run := func(args ...string) error {
		cmd := newHARecoverCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"--cluster-id", "c1", "--bootstrap-node", "n0", "--url", "http://127.0.0.1:1", "--insecure",
			"--min-epoch", "0", "--min-index", "0", "--attempts", "1"}, args...))
		return cmd.ExecuteContext(context.Background())
	}
	none := filepath.Join(dir, "none")
	other, _ := testKeyPEM(t)
	otherDER, _ := x509.MarshalECPrivateKey(other)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"missing backup file": {[]string{"--backup-file", none, "--recovery-key", keyPath, "--decree-key", keyPath}, "no such file"},
		"garbage backup file": {[]string{"--backup-file", garbage, "--recovery-key", keyPath, "--decree-key", keyPath}, "--backup-file"},
		"no backup in file":   {[]string{"--backup-file", empty, "--recovery-key", keyPath, "--decree-key", keyPath}, "no backup manifest"},
		"no recovery key":     {[]string{"--backup-file", good, "--recovery-key", none, "--decree-key", keyPath}, "recovery key: read"},
		"wrong recovery key":  {[]string{"--backup-file", good, "--recovery-key", writePEM(t, "EC PRIVATE KEY", otherDER), "--decree-key", keyPath}, "recovery key"},
		"no decree key":       {[]string{"--backup-file", good, "--recovery-key", keyPath, "--decree-key", none}, "--decree-key"},
		"nobody answers":      {[]string{"--backup-file", good, "--recovery-key", keyPath, "--decree-key", keyPath}, "no answer"},
	} {
		if err := run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// The HA flags and cds-ha.json fill the replica's recovery key and seats.
func TestHARecoveryKeyAndSeatsFlags(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rec.pem")
	_ = os.WriteFile(p, []byte("PEM"), 0o600)
	var h haConfig
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	bindHAFlags(fs, &h)
	if err := fs.Parse([]string{"--ha-recovery-key", p}); err != nil || string(h.recoveryKeyPEM) != "PEM" {
		t.Fatalf("--ha-recovery-key: %v %q", err, h.recoveryKeyPEM)
	}
	if err := fs.Parse([]string{"--ha-recovery-key", filepath.Join(dir, "none")}); err == nil {
		t.Fatal("a missing recovery key file parsed")
	}
	img := launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}}
	raw, _ := json.Marshal(nodeservices.CDSHAConfig{ClusterID: "c1", DecreeKey: "PEM", Replicas: 5, RecoveryKey: "REC", Image: img})
	cf := filepath.Join(dir, "cds-ha.json")
	_ = os.WriteFile(cf, raw, 0o600)
	hc := haConfig{configFile: cf, seats: 3}
	if err := loadHAConfigFile(&hc); err != nil || hc.seats != 5 || string(hc.recoveryKeyPEM) != "REC" {
		t.Fatalf("cds-ha.json: %v %+v", err, hc)
	}
}

func TestSetDecreeImages(t *testing.T) {
	h := func(c string) string { return strings.Repeat(c, 96) }
	spec := h("a") + ":" + h("b") + ":" + h("c")
	pin := spec
	d := cdsha.Decree{Kind: cdsha.UpdateMeasurements}
	if err := setDecreeImages(&d, nil); err != nil || d.Images != nil {
		t.Fatal("no --image changed the decree")
	}
	if err := setDecreeImages(&d, []string{strings.ToUpper(spec), spec}); err != nil || len(d.Images) != 2 || len(d.Measurements) != 1 || d.Measurements[0] != pin {
		t.Fatalf("images %+v measurements %v: %v", d.Images, d.Measurements, err)
	}
	d = cdsha.Decree{Kind: cdsha.UpdateMeasurements, Measurements: []string{pin}}
	if err := setDecreeImages(&d, []string{spec}); err != nil {
		t.Fatalf("matching --measurements refused: %v", err)
	}
	for name, c := range map[string]struct {
		kind  cdsha.DecreeKind
		specs []string
		meas  []string
	}{
		"genesis":        {cdsha.Genesis, []string{spec}, nil},
		"two parts":      {cdsha.UpdateMeasurements, []string{h("a") + ":" + h("b")}, nil},
		"short register": {cdsha.UpdateMeasurements, []string{"aa:bb:cc"}, nil},
		"other pins":     {cdsha.UpdateMeasurements, []string{spec}, []string{"x"}},
	} {
		d := cdsha.Decree{Kind: c.kind, Measurements: c.meas}
		if err := setDecreeImages(&d, c.specs); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestPrintDecrees(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "i1", BaseEpoch: 2, Kind: cdsha.SetVoters, Voters: 5}, k)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	keyFile := filepath.Join(t.TempDir(), "decree.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	records := []cdsha.DecreeRecord{{Decree: sd, AtMS: 1, Epoch: 3}}
	var out bytes.Buffer
	if err := printDecrees(&out, records, keyFile, false); err != nil || !strings.Contains(out.String(), "SetVoters") || !strings.Contains(out.String(), "voters=5") {
		t.Fatalf("%v: %s", err, out.String())
	}
	out.Reset()
	if err := printDecrees(&out, records, "", true); err != nil || !strings.Contains(out.String(), `"intent_id": "i1"`) {
		t.Fatalf("json: %v: %s", err, out.String())
	}
	records[0].Decree.Decree.Voters = 7 // tampered after signing
	if err := printDecrees(io.Discard, records, keyFile, false); err == nil {
		t.Fatal("a tampered record passed the signature check")
	}
	if err := printDecrees(io.Discard, records, filepath.Join(t.TempDir(), "absent"), false); err == nil {
		t.Fatal("absent key file accepted")
	}
}

// decrees reads the applied record from a replica and refuses what it cannot
// trust or decode.
func TestHADecreesCLI(t *testing.T) {
	k, _ := testKeyPEM(t)
	h := strings.Repeat("a", 96)
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "g1", Kind: cdsha.Genesis, BootstrapNode: "n0",
		Images: []cdsha.DecreeImage{{MRTD: h, RTMR1: h, RTMR2: h}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	records := []cdsha.DecreeRecord{{Decree: sd, AtMS: 1, Epoch: 1}}
	serve := func(code int, body string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ha/decrees" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	raw, _ := json.Marshal(records)
	good := serve(http.StatusOK, string(raw))
	out, err := runHA(t, "decrees", "--url", good+"/", "--insecure")
	if err != nil || !strings.Contains(out, "Genesis") || !strings.Contains(out, "images=1") || !strings.Contains(out, "node=n0") {
		t.Fatalf("decrees: %v %q", err, out)
	}
	if _, err := runHA(t, "decrees", "--url", good); err == nil {
		t.Fatal("plaintext http without --insecure accepted")
	}
	for name, url := range map[string]string{
		"server error":  serve(http.StatusInternalServerError, "boom"),
		"not JSON":      serve(http.StatusOK, "{"),
		"nobody serves": "http://127.0.0.1:1",
	} {
		if _, err := runHA(t, "decrees", "--url", url, "--insecure"); err == nil {
			t.Errorf("%s: decrees succeeded", name)
		}
	}
}
