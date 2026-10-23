package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/klauspost/compress/zstd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func mustCA(t *testing.T) *issuer.CA {
	t.Helper()
	mesh, err := issuer.NewMeshCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return mesh.Current().CA
}

func TestNewAttestor(t *testing.T) {
	if _, err := NewAttestor("node", AttestorOptions{}); err == nil {
		t.Fatal("node attestor without an attestation-api URL")
	}
	if a, err := NewAttestor("node", AttestorOptions{AttestationAPIURL: "http://127.0.0.1:1", Timeout: time.Second}); err != nil || a == nil {
		t.Fatalf("node attestor: %v", err)
	}
	for _, name := range []string{"tdx", "nope"} {
		if _, err := NewAttestor(name, AttestorOptions{}); err == nil || !strings.Contains(err.Error(), "not available") {
			t.Fatalf("attestor %q: %v", name, err)
		}
	}
}

func tdxClaims(rd []byte) teetypes.Claims {
	return teetypes.Claims{LaunchDigest: digest(1), ReportData: rd,
		PlatformData: map[string]any{"rtmr_1": digest(2), "rtmr_2": digest(3), "rtmr_3": digest(4)}}
}

// nodeClaims maps a verified result to the image pin and the launch-key
// anchor, and refuses anything incomplete.
func TestNodeClaims(t *testing.T) {
	tdxRes := func(c teetypes.Claims) teetypes.VerificationResult {
		return teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: c}
	}
	rd := make([]byte, 64)
	rd[0] = 7
	c, err := nodeClaims(tdxRes(tdxClaims(rd)))
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := ImagePin("tdx", digest(1), map[int]string{1: digest(2), 2: digest(3)})
	if c.Measurement != pin || c.Anchor != digest(4) || c.ReportData[0] != 7 {
		t.Fatalf("claims %+v, want measurement %s", c, pin)
	}
	// RTMR3 is the anchor, not part of the measurement.
	other := tdxClaims(rd)
	other.PlatformData["rtmr_3"] = digest(9)
	if c2, _ := nodeClaims(tdxRes(other)); c2.Measurement != c.Measurement || c2.Anchor == c.Anchor {
		t.Fatal("RTMR3 must change the anchor only")
	}
	snp := teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformSNP,
		Claims: teetypes.Claims{LaunchDigest: digest(5), InitData: []byte{0xab, 0xcd}, ReportData: rd}}
	if c, err := nodeClaims(snp); err != nil || c.Anchor != "abcd" || c.Measurement != digest(5) {
		t.Fatalf("snp claims %+v: %v", c, err)
	}
	tail := make([]byte, 64)
	tail[60] = 1
	unknown := snp
	unknown.Platform = "other"
	regs := func(drop string) teetypes.Claims {
		c := tdxClaims(rd)
		c.PlatformData = maps.Clone(c.PlatformData)
		delete(c.PlatformData, drop)
		return c
	}
	for name, res := range map[string]teetypes.VerificationResult{
		"short report_data": tdxRes(tdxClaims(make([]byte, 20))),
		"non-zero tail":     tdxRes(tdxClaims(tail)),
		"no launch digest":  tdxRes(teetypes.Claims{ReportData: rd, PlatformData: tdxClaims(nil).PlatformData}),
		"no RTMR1":          tdxRes(regs("rtmr_1")),
		"no RTMR2":          tdxRes(regs("rtmr_2")),
		"no RTMR3":          tdxRes(regs("rtmr_3")),
		"unknown platform":  unknown,
	} {
		if _, err := nodeClaims(res); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestImagePin(t *testing.T) {
	m := strings.ToUpper(digest(1))
	pin, err := ImagePin("tdx", m, map[int]string{1: digest(2), 2: digest(3)})
	if err != nil || pin != strings.Join([]string{digest(1), digest(2), digest(3)}, ":") {
		t.Fatalf("tdx pin %q: %v", pin, err)
	}
	if _, err := ImagePin("tdx", m, map[int]string{1: digest(2)}); err == nil {
		t.Fatal("tdx pin without RTMR2")
	}
	if pin, err := ImagePin("snp", m, nil); err != nil || pin != digest(1) {
		t.Fatalf("snp pin %q: %v", pin, err)
	}
	// A decree image's pin is the replica's ImagePin, in lowercase only.
	img := testImage(1)
	if pin, err := img.Pin(); err != nil || pin != img.MRTD+":"+img.RTMR1+":"+img.RTMR2 {
		t.Fatalf("decree image pin %q: %v", pin, err)
	}
	img.RTMR1 = strings.Repeat("AB", 48)
	if _, err := img.Pin(); err == nil {
		t.Fatal("uppercase register accepted")
	}
	if _, err := ImagePin("nope", m, nil); err == nil {
		t.Fatal("unknown platform pinned")
	}
}

type failingAttestor struct{}

func (failingAttestor) Evidence([48]byte) ([]byte, error) { return nil, errors.New("no TEE") }
func (failingAttestor) Verify([]byte) (Claims, error)     { return Claims{}, errors.New("no TEE") }

// peerVerifier refuses every peer that is not a replica of this cluster.
func TestPeerVerifier(t *testing.T) {
	v := peerVerifier{clusterID: testCluster, att: MockAttestor{}, pins: func() []string { return []string{"m1"} }}
	m1 := MockAttestor{Measurement: "m1"}
	day := time.Now().Add(24 * time.Hour)
	good, err := newPeerCert(testCluster, m1, day)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.claims(good.Certificate[0]); err != nil {
		t.Fatal(err)
	}
	unpinned, _ := newPeerCert(testCluster, MockAttestor{Measurement: "m9"}, day)
	otherCluster, _ := newPeerCert("tenant-b", m1, day)
	expired, _ := newPeerCert(testCluster, m1, time.Now().Add(-time.Hour))
	plain := mustCA(t).Cert.Raw // no evidence extension
	// A leaked key re-signs the expired certificate, evidence and all, with
	// a later NotAfter.
	gc, _ := x509.ParseCertificate(expired.Certificate[0])
	gc.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	gc.ExtraExtensions = gc.Extensions
	key := expired.PrivateKey.(*ecdsa.PrivateKey)
	extended, err := x509.CreateCertificate(rand.Reader, gc, gc, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"expired":              expired.Certificate[0],
		"re-signed later":      extended,
		"unpinned measurement": unpinned.Certificate[0],
		"other cluster":        otherCluster.Certificate[0],
		"no evidence":          plain,
		"not a certificate":    []byte("junk"),
	} {
		if _, err := v.claims(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other := v
	other.anchor = "another-launch-key"
	if _, err := other.claims(good.Certificate[0]); err == nil {
		t.Error("peer with another launch-key anchor accepted")
	}
	cold := v
	cold.pins = func() []string { return nil }
	if _, err := cold.claims(unpinned.Certificate[0]); err != nil {
		t.Errorf("a cold replica must defer the pin check to the offered chain: %v", err)
	}
}

func TestKubeDecrees(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if err := st.SetDecreeStatus(ctx, "missing", DecreeStatus{RejectedReason: "x"}); err == nil {
		t.Fatal("status written to a missing decree")
	}
	k, _ := operatorKey(t)
	sd := signDecree(t, k, Decree{IntentID: "g", Kind: Genesis, BootstrapNode: "n0"})
	good, err := DecreeConfigMap("decrees", sd)
	if err != nil || good.Name != DecreeName(testCluster, "g") || good.Labels[LabelDecree] != testCluster {
		t.Fatalf("decree object %+v: %v", good, err)
	}
	bad, _ := DecreeConfigMap("decrees", SignedDecree{Decree: Decree{ClusterID: testCluster, IntentID: "bad"}})
	bad.Data[keyDecree] = "{not json"
	if _, err := kube.CoreV1().ConfigMaps("decrees").Create(ctx, good, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().ConfigMaps("decrees").Create(ctx, bad, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingDecrees(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending %+v: %v", pending, err)
	}
	for _, p := range pending {
		if (p.Name == bad.Name) != (p.Err != nil) {
			t.Fatalf("%s: parse error %v", p.Name, p.Err)
		}
	}
	epoch := uint64(1)
	if err := st.SetDecreeStatus(ctx, good.Name, DecreeStatus{AppliedEpoch: &epoch}); err != nil {
		t.Fatal(err)
	}
	if pending, _ := st.PendingDecrees(ctx); len(pending) != 1 || pending[0].Name != bad.Name {
		t.Fatalf("a decree with a status is still pending: %+v", pending)
	}
}

func TestNewNodeRejectsIncompleteConfig(t *testing.T) {
	al, sec, led := testStores(t)
	good := Config{ClusterID: testCluster, NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1", Attestor: MockAttestor{"m1"},
		Seats: 3, Allowlist: al, Secrets: sec, Ledger: led}
	n, err := NewNode(good)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n.ID(), "n0/") || nodeOf(raft.ServerID(n.ID())) != "n0" || bornOf(raft.ServerID(n.ID())) == 0 {
		t.Fatalf("member id %q", n.ID())
	}
	if n.Serving() || n.Status().Joined {
		t.Fatal("a fresh replica serves")
	}
	if _, err := n.CA(); err == nil {
		t.Fatal("a fresh replica hands out a CA")
	}
	for name, mutate := range map[string]func(c *Config){
		"no cluster id":    func(c *Config) { c.ClusterID = "" },
		"no node name":     func(c *Config) { c.NodeName = "" },
		"slash in name":    func(c *Config) { c.NodeName = "a/b" },
		"no seats":         func(c *Config) { c.Seats = 0 },
		"no attestor":      func(c *Config) { c.Attestor = nil },
		"no stores":        func(c *Config) { c.Allowlist = nil },
		"attestor fails":   func(c *Config) { c.Attestor = failingAttestor{} },
		"own evidence bad": func(c *Config) { c.Attestor = MockAttestor{} },
	} {
		c := good
		mutate(&c)
		if _, err := NewNode(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newPeerCert(testCluster, failingAttestor{}, time.Now()); err == nil {
		t.Error("peer certificate without evidence")
	}
	if nodeOf("no-slash") != "" || bornOf("n0/notanumber-x") != 0 {
		t.Error("malformed member ids parsed")
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
		if err := al.PutWorkload(name, mkWorkload(t)); err != nil {
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
