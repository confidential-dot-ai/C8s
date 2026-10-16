package cdsha

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

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

func TestTimingValidate(t *testing.T) {
	if err := DefaultTiming.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, tm := range map[string]Timing{
		"zero heartbeat":           {Heartbeat: 0, LeaseDuration: 15 * time.Second, AckTimeout: time.Second},
		"heartbeat >= lease":       {Heartbeat: 15 * time.Second, LeaseDuration: 15 * time.Second, AckTimeout: time.Second},
		"no ack timeout":           {Heartbeat: time.Second, LeaseDuration: 15 * time.Second},
		"fractional lease seconds": {Heartbeat: time.Second, LeaseDuration: 1500 * time.Millisecond, AckTimeout: time.Second},
	} {
		if err := tm.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Records re-signed with the right key but carrying invalid content: every
// link rule is checked, not only the signature.
func TestChainVerifyRejectsResignedLinks(t *testing.T) {
	g := genesisState(t, 3, opPub())
	e1 := extend(t, g, false, "m1", "m2")
	resign := func(mutate func(r *Record)) Chain {
		r := e1.Chain[1].Record
		mutate(&r)
		s, err := SignRecord(r, g.Key)
		if err != nil {
			t.Fatal(err)
		}
		return Chain{g.Chain[0], s}
	}
	_, otherOp := operatorKey(t)
	cases := map[string]func(r *Record){
		"empty pins":            func(r *Record) { r.Measurements = nil },
		"pins not the decree's": func(r *Record) { r.Measurements = []string{"m1", "m3"} },
		"epoch gap":             func(r *Record) { r.Epoch = 5 },
		"prev hash":             func(r *Record) { r.PrevEpochHash = []byte("x") },
		"operator key changed":  func(r *Record) { r.OperatorPubKey = otherOp },
		"term decreased":        func(r *Record) { r.Term = 1 },
		"applied decrees":       func(r *Record) { r.AppliedDecrees = nil },
		"root changed without rotation": func(r *Record) {
			r.RootCert = mustCA(t).Cert.Raw
		},
	}
	for name, mutate := range cases {
		if err := resign(mutate).Verify(testCluster); err == nil {
			t.Errorf("%s: chain verified", name)
		}
	}
	// Pins are signed in canonical order; a reordered copy keeps a valid
	// signature but is refused.
	reordered := Chain{g.Chain[0], e1.Chain[1]}
	reordered[1].Record.Measurements = []string{"m2", "m1"}
	if err := reordered.Verify(testCluster); err == nil {
		t.Error("reordered pins: chain verified")
	}
	// Epoch 0 rules.
	g0 := g.Chain[0].Record
	for name, mutate := range map[string]func(r *Record){
		"genesis not at epoch 0":       func(r *Record) { r.Epoch = 1 },
		"genesis with applied decrees": func(r *Record) { r.AppliedDecrees = append(r.AppliedDecrees, "x") },
		"genesis decree for other key": func(r *Record) { r.OperatorPubKey = otherOp },
		"genesis with a prev hash":     func(r *Record) { r.PrevEpochHash = []byte("x") },
	} {
		r := g0
		mutate(&r)
		s, err := SignRecord(r, g.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := (Chain{s}).Verify(testCluster); err == nil {
			t.Errorf("%s: chain verified", name)
		}
	}
	if err := (Chain{}).Verify(testCluster); err == nil {
		t.Error("empty chain verified")
	}
}

func TestChainHasPrefix(t *testing.T) {
	g := genesisState(t, 0, opPub())
	e1 := extend(t, g, false, "m1", "m2")
	e2 := extend(t, e1, true)
	fork := extend(t, g, false, "m1", "m3")
	switch {
	case !e2.Chain.HasPrefix(e1.Chain), !e2.Chain.HasPrefix(e2.Chain), !e2.Chain.HasPrefix(nil):
		t.Fatal("a chain must extend its own prefixes")
	case e1.Chain.HasPrefix(e2.Chain):
		t.Fatal("a shorter chain extends a longer one")
	case e2.Chain.HasPrefix(fork.Chain):
		t.Fatal("a fork counted as a prefix")
	}
}

type failingAttestor struct{}

func (failingAttestor) Evidence([48]byte) ([]byte, error) { return nil, errors.New("no TEE") }
func (failingAttestor) Verify([]byte) (Claims, error)     { return Claims{}, errors.New("no TEE") }

func TestNewRejectsIncompleteConfig(t *testing.T) {
	kube := fake.NewClientset()
	peers := func(context.Context) ([]string, error) { return nil, nil }
	good := Config{ClusterID: testCluster, Attestor: testAttestor{measurement: "m1"}, Kube: kube, Peers: peers,
		BakedPins: []string{"m1"}, OperatorPubKey: opPub(), Timing: DefaultTiming}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(c *Config){
		"no cluster id":       func(c *Config) { c.ClusterID = "" },
		"no attestor":         func(c *Config) { c.Attestor = nil },
		"no pins":             func(c *Config) { c.BakedPins = nil },
		"no operator key":     func(c *Config) { c.OperatorPubKey = nil },
		"bad timing":          func(c *Config) { c.Timing = Timing{} },
		"attestor fails":      func(c *Config) { c.Attestor = failingAttestor{} },
		"own evidence unread": func(c *Config) { c.Attestor = testAttestor{} },
	} {
		c := good
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newPeerCert(testCluster, failingAttestor{}); err == nil {
		t.Error("peer certificate without evidence")
	}
}

func TestStoreEdgeCases(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	st := Store{Client: kube, Namespace: "c8s-system", DecreeNamespace: "decrees", ClusterID: testCluster}
	if rec, v, err := st.GetEpoch(ctx); rec != nil || v.Exists || err != nil {
		t.Fatalf("absent CDSEpoch: %v %v %v", rec, v, err)
	}
	// Garbage in CDSEpoch: unparsable, but the version is returned so a
	// writer can overwrite it.
	_, err := kube.CoreV1().ConfigMaps("c8s-system").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: EpochName(testCluster), Namespace: "c8s-system"},
		Data:       map[string]string{keyRecord: "{not json"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rec, v, err := st.GetEpoch(ctx); rec != nil || !v.Exists || err == nil {
		t.Fatalf("garbage CDSEpoch: %v %v %v", rec, v, err)
	}
	if err := st.SetDecreeStatus(ctx, "missing", DecreeStatus{RejectedReason: "x"}); err == nil {
		t.Fatal("status written to a missing decree")
	}
	cm, err := DecreeConfigMap("decrees", genesisDecree(t))
	if err != nil {
		t.Fatal(err)
	}
	cm.Data[keyDecree] = "{not json"
	if _, err := kube.CoreV1().ConfigMaps("decrees").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingDecrees(ctx)
	if err != nil || len(pending) != 1 || pending[0].Err == nil {
		t.Fatalf("unparsable decree must be pending with an error: %+v %v", pending, err)
	}
	if err := st.SetDecreeStatus(ctx, cm.Name, DecreeStatus{RejectedReason: "unparsable"}); err != nil {
		t.Fatal(err)
	}
	if pending, _ := st.PendingDecrees(ctx); len(pending) != 0 {
		t.Fatal("a decree with a status is still pending")
	}
}

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

func TestCheckDecreeRules(t *testing.T) {
	opKey, _ := testOp()
	st := genesisState(t, 0, opPub())
	tail := st.Chain.Tail()
	sign := func(d Decree) SignedDecree {
		if d.ClusterID == "" {
			d.ClusterID = testCluster
		}
		if d.ExpiresAt.IsZero() {
			d.ExpiresAt = time.Now().Add(time.Hour)
		}
		sd, err := SignDecree(d, opKey)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	ok := sign(Decree{IntentID: "ok", Kind: UpdateMeasurements, Measurements: []string{"m1", "m2"}})
	if err := CheckDecree(ok, tail, time.Now()); err != nil {
		t.Fatal(err)
	}
	reordered := ok
	reordered.Decree.Measurements = []string{"m2", "m1"}
	notECDSA := tail
	notECDSA.OperatorPubKey = []byte("garbage")
	noKey := tail
	noKey.OperatorPubKey = nil
	for name, c := range map[string]struct {
		sd   SignedDecree
		tail Record
	}{
		"expired":                    {sign(Decree{IntentID: "e", Kind: RotateKey, ExpiresAt: time.Now().Add(-time.Second)}), tail},
		"other cluster":              {sign(Decree{ClusterID: "tenant-b", IntentID: "c", Kind: RotateKey}), tail},
		"empty intent":               {sign(Decree{Kind: RotateKey}), tail},
		"replayed intent":            {sign(Decree{IntentID: tail.AppliedDecrees[0], Kind: RotateKey}), tail},
		"stale base epoch":           {sign(Decree{IntentID: "b", BaseEpoch: 3, Kind: RotateKey}), tail},
		"empty UpdateMeasurements":   {sign(Decree{IntentID: "u", Kind: UpdateMeasurements}), tail},
		"Genesis on a keyed cluster": {sign(Decree{IntentID: "g", Kind: Genesis}), tail},
		"unknown kind":               {sign(Decree{IntentID: "k", Kind: "Nuke"}), tail},
		"reordered after signing":    {reordered, tail},
		"cluster without operator":   {ok, noKey},
		"unparsable operator key":    {ok, notECDSA},
	} {
		if err := CheckDecree(c.sd, c.tail, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
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

// handleSync hands the key only to a peer the current epoch pins (Q3).
func TestHandleSyncAuthorizesByCurrentPins(t *testing.T) {
	r, err := New(Config{ClusterID: testCluster, Attestor: testAttestor{measurement: "m1"}, Kube: fake.NewClientset(),
		Peers: func(context.Context) ([]string, error) { return nil, nil }, BakedPins: []string{"m1"}, OperatorPubKey: opPub(), Timing: DefaultTiming})
	if err != nil {
		t.Fatal(err)
	}
	call := func(measurement string) int {
		cert, err := newPeerCert(testCluster, testAttestor{measurement: measurement})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/ha/v1/sync", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		w := httptest.NewRecorder()
		r.peerHandler().ServeHTTP(w, req)
		return w.Code
	}
	if code := call("m1"); code != http.StatusServiceUnavailable {
		t.Fatalf("keyless replica answered sync with %d", code)
	}
	if err := r.accept(genesisState(t, 0, opPub()), "test"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.serving = true
	r.mu.Unlock()
	if code := call("m9"); code != http.StatusForbidden {
		t.Fatalf("unpinned peer got %d", code)
	}
	if code := call("m1"); code != http.StatusOK {
		t.Fatalf("pinned peer got %d", code)
	}
}
