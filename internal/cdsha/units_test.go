package cdsha

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func mustCA(t *testing.T) *issuer.CA {
	t.Helper()
	ca, err := issuer.NewCAWithCurve("test", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestNewAttestor(t *testing.T) {
	if _, err := NewAttestor("node", AttestorOptions{}); err == nil {
		t.Fatal("node attestor without an attestation-api URL")
	}
	if a, err := NewAttestor("node", AttestorOptions{AttestationAPIURL: "http://127.0.0.1:1", Timeout: time.Second}); err != nil || a == nil {
		t.Fatalf("node attestor: %v", err)
	}
	if _, err := NewAttestor("tdx", AttestorOptions{}); err == nil {
		t.Fatal("tdx attestor without accepted TCB statuses")
	}
	if _, err := NewAttestor("tdx", AttestorOptions{TDXTCBStatuses: []string{"NoSuchStatus"}}); err == nil {
		t.Fatal("tdx attestor with an unknown TCB status")
	}
	if a, err := NewAttestor("tdx", AttestorOptions{TDXTCBStatuses: DefaultTDXTCBStatuses}); err != nil || a == nil {
		t.Fatalf("tdx attestor: %v", err)
	}
	if _, err := NewAttestor("nope", AttestorOptions{}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("unknown attestor: %v", err)
	}
}

func tdxClaims(rd []byte) teetypes.Claims {
	return teetypes.Claims{LaunchDigest: digest(1), ReportData: rd,
		PlatformData: map[string]any{"rtmr_1": digest(2), "rtmr_2": digest(3), "rtmr_3": digest(4)}}
}

func TestPeerClaims(t *testing.T) {
	rd := make([]byte, 64)
	rd[0] = 7
	c, err := peerClaims(tdxClaims(rd))
	if err != nil {
		t.Fatal(err)
	}
	if c.Anchor != digest(4) || c.ReportData[0] != 7 || len(c.Measurement) != 96 {
		t.Fatalf("claims %+v", c)
	}
	// Measurement covers MRTD and RTMR1-2, not RTMR3 (the anchor).
	other := tdxClaims(rd)
	other.PlatformData["rtmr_3"] = digest(9)
	if c2, _ := peerClaims(other); c2.Measurement != c.Measurement || c2.Anchor == c.Anchor {
		t.Fatal("RTMR3 must change the anchor only")
	}
	other.PlatformData["rtmr_2"] = digest(9)
	if c3, _ := peerClaims(other); c3.Measurement == c.Measurement {
		t.Fatal("RTMR2 must change the measurement")
	}
	bad := make([]byte, 64)
	bad[63] = 1
	for name, cl := range map[string]teetypes.Claims{
		"short report_data":    tdxClaims(make([]byte, 48)),
		"non-zero tail":        tdxClaims(bad),
		"no launch digest":     {ReportData: make([]byte, 64), PlatformData: tdxClaims(nil).PlatformData},
		"no RTMR1":             {LaunchDigest: digest(1), ReportData: make([]byte, 64), PlatformData: map[string]any{"rtmr_2": digest(3), "rtmr_3": digest(4)}},
		"no RTMR3 (no anchor)": {LaunchDigest: digest(1), ReportData: make([]byte, 64), PlatformData: map[string]any{"rtmr_1": digest(2), "rtmr_2": digest(3)}},
	} {
		if _, err := peerClaims(cl); err == nil {
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
	if _, err := ImagePin("nope", m, nil); err == nil {
		t.Fatal("unknown platform pinned")
	}
}

// The pin a launch document produces (ImagePin) is the measurement the node
// attestor reports for that image, on both platforms.
func TestNodeIdentityMatchesImagePin(t *testing.T) {
	cl := tdxClaims(make([]byte, 64))
	m, anchor, err := nodeIdentity(teetypes.PlatformTDX, cl)
	if err != nil || anchor != digest(4) {
		t.Fatalf("tdx: %v anchor %s", err, anchor)
	}
	if pin, _ := ImagePin("tdx", digest(1), map[int]string{1: digest(2), 2: digest(3)}); pin != m {
		t.Fatalf("tdx identity %s != pin %s", m, pin)
	}
	snp := teetypes.Claims{LaunchDigest: digest(5), InitData: []byte{0xab, 0xcd}}
	m, anchor, err = nodeIdentity(teetypes.PlatformSNP, snp)
	if err != nil || anchor != "abcd" {
		t.Fatalf("snp: %v anchor %s", err, anchor)
	}
	if pin, _ := ImagePin("snp", digest(5), nil); pin != m {
		t.Fatalf("snp identity %s != pin %s", m, pin)
	}
	if _, _, err := nodeIdentity(teetypes.PlatformType("other"), snp); err == nil {
		t.Fatal("unknown platform accepted")
	}
	if _, _, err := nodeIdentity(teetypes.PlatformTDX, teetypes.Claims{LaunchDigest: digest(1)}); err == nil {
		t.Fatal("tdx claims without RTMRs accepted")
	}
}

func TestNodeClaimsRejects(t *testing.T) {
	ok := teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: tdxClaims(make([]byte, 64))}
	if _, err := nodeClaims(ok); err != nil {
		t.Fatal(err)
	}
	unsigned := ok
	unsigned.SignatureValid = false
	short := ok
	short.Claims = tdxClaims(make([]byte, 20))
	for name, res := range map[string]teetypes.VerificationResult{"invalid signature": unsigned, "short report_data": short} {
		if _, err := nodeClaims(res); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

type failingAttestor struct{}

func (failingAttestor) Evidence([48]byte) ([]byte, error) { return nil, errors.New("no TEE") }
func (failingAttestor) Verify([]byte) (Claims, error)     { return Claims{}, errors.New("no TEE") }

// The tdx attestor fails closed outside a TD and on garbage evidence.
func TestTDXAttestorFailsClosed(t *testing.T) {
	a, err := NewTDXAttestor(DefaultTDXTCBStatuses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify([]byte("not a quote")); err == nil {
		t.Fatal("garbage quote verified")
	}
	if _, err := os.Stat("/sys/kernel/config/tsm/report"); err != nil {
		if _, err := a.Evidence([48]byte{}); err == nil {
			t.Fatal("quote produced outside a TD")
		}
	}
}

// peerVerifier refuses every peer that is not a replica of this cluster.
func TestPeerVerifier(t *testing.T) {
	v := peerVerifier{clusterID: testCluster, att: testAttestor{}, pins: func() []string { return []string{"m1"} }}
	good, err := newPeerCert(testCluster, testAttestor{measurement: "m1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.claims(good.Certificate[0]); err != nil {
		t.Fatal(err)
	}
	unpinned, _ := newPeerCert(testCluster, testAttestor{measurement: "m9"})
	otherCluster, _ := newPeerCert("tenant-b", testAttestor{measurement: "m1"})
	plain := mustCA(t).Cert.Raw // no evidence extension
	for name, der := range map[string][]byte{
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
	if err := v.verifyConn(tls.ConnectionState{}); err == nil {
		t.Error("connection without a peer certificate accepted")
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
	sd, _ := SignDecree(Decree{ClusterID: testCluster, IntentID: "g", Kind: Genesis, BootstrapNode: "n0", ExpiresAt: time.Now().Add(time.Hour)}, k)
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

func testStores(t *testing.T) (*allowlist.Store, *secrets.MemoryStore, *sandboxledger.Ledger) {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return &al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8)
}

func TestNewNodeRejectsIncompleteConfig(t *testing.T) {
	al, sec, led := testStores(t)
	good := Config{ClusterID: testCluster, NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1", Attestor: testAttestor{"m1"},
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
		"own evidence bad": func(c *Config) { c.Attestor = testAttestor{} },
	} {
		c := good
		mutate(&c)
		if _, err := NewNode(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newPeerCert(testCluster, failingAttestor{}); err == nil {
		t.Error("peer certificate without evidence")
	}
	if nodeOf("no-slash") != "" || bornOf("n0/notanumber-x") != 0 {
		t.Error("malformed member ids parsed")
	}
	if hp, id := splitRaftAddr("10.0.0.1:9443#n0/1-a"); hp != "10.0.0.1:9443" || id != "n0/1-a" {
		t.Errorf("split %q %q", hp, id)
	}
	if a := (raftAddr{}); a.Network() != "tcp" {
		t.Error("raft address network")
	}
}

// The state machine refuses malformed entries and decrees that do not
// apply, and a snapshot restores the same state, mesh CA included.
func TestFSMEdges(t *testing.T) {
	al, sec, led := testStores(t)
	opKey, opPub := operatorKey(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	apply := func(e any) any {
		raw, _ := json.Marshal(e)
		return f.Apply(&raft.Log{Index: 7, Type: raft.LogCommand, Data: raw})
	}
	if _, ok := f.Apply(&raft.Log{Index: 1, Type: raft.LogCommand, Data: []byte("{")}).(error); !ok {
		t.Fatal("garbage entry applied")
	}
	if _, ok := apply(Entry{Kind: KindSecret}).(error); !ok {
		t.Fatal("entry without payload applied")
	}
	if f.Apply(&raft.Log{Index: 8, Type: raft.LogConfiguration}) != nil || f.AppliedIndex() != 8 {
		t.Fatal("configuration entries are not commands but advance the index")
	}
	ca := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	sign := func(d Decree) SignedDecree {
		d.ClusterID, d.ExpiresAt = testCluster, time.Now().Add(time.Hour)
		sd, _ := SignDecree(d, opKey)
		return sd
	}
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
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := snap.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	al2, sec2, led2 := testStores(t)
	f2 := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := f2.Restore(io.NopCloser(&buf)); err != nil {
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
	// A snapshot in the earlier single-object form (older backups) restores.
	old, _ := json.Marshal(snapshot{Core: PreGenesis(testCluster, opPub)})
	if err := f2.Restore(io.NopCloser(bytes.NewReader(old))); err != nil {
		t.Fatalf("earlier snapshot form: %v", err)
	}
	for _, bad := range [][]byte{{0x1f, 0x8b, 0}, gzipped(t, "{"), gzipped(t, "{}\n{\"t\":")} {
		if err := f2.Restore(io.NopCloser(bytes.NewReader(bad))); err == nil {
			t.Fatalf("broken snapshot %q restored", bad)
		}
	}
}

type memSink struct {
	*bytes.Buffer
	fail bool
}

func (s *memSink) Write(p []byte) (int, error) {
	if s.fail {
		return 0, errors.New("disk full")
	}
	return s.Buffer.Write(p)
}
func (s *memSink) ID() string    { return "mem" }
func (s *memSink) Cancel() error { return nil }
func (s *memSink) Close() error  { return nil }

var _ raft.SnapshotSink = (*memSink)(nil)

func TestCertHolderRenews(t *testing.T) {
	n := 0
	h, err := newCertHolder(func() (tls.Certificate, error) {
		n++
		return tls.Certificate{Certificate: [][]byte{{byte(n)}}}, nil
	})
	if err != nil || h.current().Certificate[0][0] != 1 || h.age() > time.Minute {
		t.Fatal(err)
	}
	if err := h.renew(); err != nil || h.current().Certificate[0][0] != 2 {
		t.Fatal("renew did not replace the certificate")
	}
	if _, err := newCertHolder(func() (tls.Certificate, error) { return tls.Certificate{}, errors.New("no TEE") }); err == nil {
		t.Fatal("holder without a certificate")
	}
}

var _ = os.Stat

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
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
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	s.Release()
	al2, sec2, led2 := testStores(t)
	f2 := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := f2.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if err := al2.StartJournal(); err != nil {
		t.Fatalf("restored history: %v", err)
	}
	h1, _ := al.History()
	h2, _ := al2.History()
	if len(h1) != 4 || len(h2) != len(h1) || h2[3].Digest != h1[3].Digest {
		t.Fatalf("history %d vs %d entries", len(h1), len(h2))
	}
}
