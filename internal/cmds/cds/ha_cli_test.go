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

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
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
		out, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", path, "--kind", "Genesis")
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
		if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", p, "--kind", "Genesis"); err == nil {
			t.Errorf("%s operator key accepted", name)
		}
	}
}

func TestHAStatusCLI(t *testing.T) {
	serve := func(hb cdsha.Heartbeat, code int) *httptest.Server {
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
	a := serve(cdsha.Heartbeat{Epoch: 2, KeyFingerprint: "aa", Serving: true}, http.StatusOK)
	b := serve(cdsha.Heartbeat{Epoch: 2, KeyFingerprint: "aa", Serving: true}, http.StatusOK)
	stale := serve(cdsha.Heartbeat{Epoch: 1, KeyFingerprint: "bb", Serving: true}, http.StatusOK)
	broken := serve(cdsha.Heartbeat{}, http.StatusInternalServerError)
	if out, err := runHA(t, "status", a.URL, b.URL); err != nil || !strings.Contains(out, "epoch=2") {
		t.Fatalf("agreeing replicas: %v %q", err, out)
	}
	if _, err := runHA(t, "status", a.URL, stale.URL); err == nil {
		t.Fatal("diverging replicas reported as healthy")
	}
	if out, err := runHA(t, "status", a.URL, broken.URL); err == nil || !strings.Contains(out, "ERROR") {
		t.Fatalf("unreachable replica: %v %q", err, out)
	}
	if err := reportDivergence([]cdsha.Heartbeat{{Epoch: 1, KeyFingerprint: "a"}}, 1); err == nil {
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

// Before it holds a key, a replica serves no CA, derives no challenge key
// and reports itself as not serving.
func TestHAHandlersBeforeKey(t *testing.T) {
	_, pub := func() (*ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return k, der
	}()
	rep, err := cdsha.New(cdsha.Config{ClusterID: "c1", Attestor: fakeAttestor{"m1"}, Kube: fake.NewClientset(),
		Peers: func(context.Context) ([]string, error) { return nil, nil }, BakedPins: []string{"m1"}, OperatorPubKey: pub, Timing: cdsha.DefaultTiming})
	if err != nil {
		t.Fatal(err)
	}
	if haCACertPEM(rep)() != nil || haChallengeKey(rep, "issuance")() != nil {
		t.Fatal("a keyless replica serves key material")
	}
	w := httptest.NewRecorder()
	haStatus(rep)(w, httptest.NewRequest(http.MethodGet, "/ha/status", nil))
	var hb cdsha.Heartbeat
	if err := json.NewDecoder(w.Body).Decode(&hb); err != nil || hb.Serving || hb.Joined {
		t.Fatalf("status %+v: %v", hb, err)
	}
}

// newReplica and meshCA wire the flags; errors surface before any key exists.
func TestNewReplicaWiring(t *testing.T) {
	orig := newInClusterKubeClientset
	t.Cleanup(func() { newInClusterKubeClientset = orig })
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return fake.NewClientset(), nil }
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: func() []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return der
	}()})
	base := config{attestationApiURL: "http://127.0.0.1:1", requestTimeout: time.Second, ha: haConfig{
		clusterID: "c1", namespace: "ns", peersDNS: "peers.invalid", port: 9443, attestor: "node",
		pins: []string{"m1"}, operatorKeyPEM: pub, timing: cdsha.DefaultTiming}}
	for name, mutate := range map[string]func(c *config){
		"no peers dns":     func(c *config) { c.ha.peersDNS = "" },
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
		if _, err := newReplica(c); err == nil {
			t.Errorf("%s: replica built", name)
		}
	}
	// meshCA: an HA config that cannot build a replica fails, and a missing
	// --ha-config file fails before anything else.
	c := base
	c.ha.attestor = "nope"
	if _, _, err := meshCA(context.Background(), c); err == nil {
		t.Fatal("meshCA built a replica with an unknown attestor")
	}
	c = config{ha: haConfig{configFile: filepath.Join(t.TempDir(), "none")}}
	if _, _, err := meshCA(context.Background(), c); err == nil {
		t.Fatal("meshCA without its --ha-config file")
	}
	// Singleton: a fresh CA.
	if ca, rep, err := meshCA(context.Background(), config{caCommonName: "t", caCertValidity: time.Hour}); err != nil || ca == nil || rep != nil {
		t.Fatalf("singleton meshCA: %v", err)
	}
}
