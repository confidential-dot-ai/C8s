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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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
	out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", keyPath, "--kind", "RotateKey", "--i-understand-rotation-forks-the-cluster")
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
	if out, err := runHA(t, "status", a.URL, b.URL); err != nil || !strings.Contains(out, "epoch=2") {
		t.Fatalf("agreeing replicas: %v %q", err, out)
	}
	if _, err := runHA(t, "status", a.URL, stale.URL); err == nil {
		t.Fatal("diverging replicas reported as healthy")
	}
	if out, err := runHA(t, "status", a.URL, broken.URL); err == nil || !strings.Contains(out, "ERROR") {
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
	if haCACertPEM(node)() != nil || haChallengeKey(node, "issuance")() != nil {
		t.Fatal("a replica that has not joined serves key material")
	}
	w := httptest.NewRecorder()
	haStatus(node)(w, httptest.NewRequest(http.MethodGet, "/ha/status", nil))
	var st cdsha.Status
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil || st.Serving || st.Joined {
		t.Fatalf("status %+v: %v", st, err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gated := haGate(node.Serving, ok)
	for path, want := range map[string]int{"/attest": 503, "/secrets/x": 503, "/allowlist": 503, "/ca": 503, "/healthz": 200, "/ha/status": 200, "/metrics": 200} {
		w := httptest.NewRecorder()
		gated.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
}

// newHANode and haStart wire the flags; errors surface before anything serves.
func TestHAStartWiring(t *testing.T) {
	orig := newInClusterKubeClientset
	t.Cleanup(func() { newInClusterKubeClientset = orig })
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: func() []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return der
	}()})
	al, _ := allowlist.OpenInMemory()
	defer al.Close()
	st := haStores{allowlist: &al, secrets: secrets.NewMemoryStore(4, 2, 64), ledger: sandboxledger.New(time.Hour, 4)}
	base := config{attestationApiURL: "http://127.0.0.1:1", requestTimeout: time.Second, ha: haConfig{
		clusterID: "c1", decreeNS: "ns", peersDNS: "peers.invalid", advertiseIP: "127.0.0.1", port: 0, nodeName: "n0", attestor: "node",
		pins: []string{"m1"}, operatorKeyPEM: pub, seats: 3, timing: cdsha.DefaultTiming}}
	for name, mutate := range map[string]func(c *config){
		"no peers dns":     func(c *config) { c.ha.peersDNS = "" },
		"no node name":     func(c *config) { c.ha.nodeName = "" },
		"unknown attestor": func(c *config) { c.ha.attestor = "nope" },
		"no operator key":  func(c *config) { c.ha.operatorKeyPEM = nil },
		"no kube client": func(c *config) {
			newInClusterKubeClientset = func() (kubernetes.Interface, error) { return nil, errors.New("no cluster") }
		},
		"attestation-api down": func(c *config) {},
	} {
		newInClusterKubeClientset = func() (kubernetes.Interface, error) { return fake.NewClientset(), nil }
		c := base
		mutate(&c)
		if _, err := newHANode(c, st); err == nil {
			t.Errorf("%s: replica built", name)
		}
	}
	c := base
	c.ha.attestor = "nope"
	if _, err := haStart(context.Background(), c, st); err == nil {
		t.Fatal("haStart built a replica with an unknown attestor")
	}
	c = config{ha: haConfig{configFile: filepath.Join(t.TempDir(), "none")}}
	if _, err := haStart(context.Background(), c, st); err == nil {
		t.Fatal("haStart without its --ha-config file")
	}
	if n, err := haStart(context.Background(), config{}, st); err != nil || n != nil {
		t.Fatalf("singleton: %v", err)
	}
}
