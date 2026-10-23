package cdsha

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// signRaw signs a decree as is, without SignDecree's normalization.
func signRaw(t *testing.T, d Decree, k *ecdsa.PrivateKey) SignedDecree {
	t.Helper()
	msg, err := d.signedBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := operatorauth.SignDetached(k, msg)
	if err != nil {
		t.Fatal(err)
	}
	return SignedDecree{Decree: d, Signature: sig}
}

// Every refusal of the decree check, each matched by its own error, so a
// row cannot pass on another check's refusal.
func TestCheckDecree(t *testing.T) {
	k, pub := operatorKey(t)
	otherKey, _ := operatorKey(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	now := time.Now()
	img := testImage(1)
	pin, _ := img.Pin()
	// keyed is a cluster with a mesh CA at epoch 3; bare has none yet.
	keyed := Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3, RootCert: []byte{1}, AppliedDecrees: []string{"done"}}
	bare := Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3}
	sign := func(d Decree) SignedDecree {
		t.Helper()
		d.ClusterID, d.BaseEpoch = cmp.Or(d.ClusterID, testCluster), 3
		if d.IntentID == "" {
			d.IntentID = "i"
		}
		if d.ExpiresAt.IsZero() {
			d.ExpiresAt = now.Add(time.Hour)
		}
		return signRaw(t, d, k)
	}
	update := Decree{Kind: UpdateMeasurements, Measurements: []string{pin}, Images: []DecreeImage{img}}
	tampered := sign(update)
	tampered.Decree.Measurements = []string{"evil"}
	wrongSigner, _ := SignDecree(sign(update).Decree, otherKey)
	stale := sign(Decree{Kind: RotateKey})
	stale.Decree.BaseEpoch = 2
	stale = signRaw(t, stale.Decree, k)
	noIntent := sign(Decree{Kind: RotateKey})
	noIntent.Decree.IntentID = ""
	noIntent = signRaw(t, noIntent.Decree, k)
	for _, c := range []struct {
		name string
		sd   SignedDecree
		tail Core
		want string // "" accepts
	}{
		{"update with images", sign(update), keyed, ""},
		{"genesis", sign(Decree{Kind: Genesis, BootstrapNode: "n0"}), bare, ""},
		{"no operator key", sign(update), Core{ClusterID: testCluster, Epoch: 3}, "no operator key"},
		{"key not PKIX", sign(update), Core{ClusterID: testCluster, OperatorPubKey: []byte("x"), Epoch: 3}, "decree key"},
		{"key not ECDSA", sign(update), Core{ClusterID: testCluster, OperatorPubKey: rsaDER, Epoch: 3}, "not ECDSA"},
		{"changed after signing", tampered, keyed, "bad operator signature"},
		{"wrong signer", wrongSigner, keyed, "bad operator signature"},
		{"other cluster", sign(Decree{ClusterID: "tenant-b", Kind: RotateKey}), keyed, "decree for cluster"},
		{"empty intent", noIntent, keyed, "empty intent_id"},
		{"already applied", sign(Decree{IntentID: "done", Kind: RotateKey}), keyed, "already applied"},
		{"stale base epoch", stale, keyed, "base_epoch 2"},
		{"empty set", sign(Decree{Kind: UpdateMeasurements}), keyed, "empty measurement set"},
		{"genesis with a key", sign(Decree{Kind: Genesis, BootstrapNode: "n0"}), keyed, "without a key"},
		{"genesis with a set", sign(Decree{Kind: Genesis, BootstrapNode: "n0", Measurements: []string{pin}}), bare, "without a key"},
		{"restore without hash", sign(Decree{Kind: Restore, BootstrapNode: "n0"}), bare, "names the snapshot"},
		{"hash on update", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{pin}, SnapshotSHA256: "aa"}), keyed, "names the snapshot"},
		{"genesis without node", sign(Decree{Kind: Genesis}), bare, "must name its node"},
		{"restore without node", sign(Decree{Kind: Restore, SnapshotSHA256: "aa"}), bare, "must name its node"},
		{"node on rotate", sign(Decree{Kind: RotateKey, BootstrapNode: "n0"}), keyed, "only Genesis, Recover and Restore"},
		{"recover with a set", sign(Decree{Kind: Recover, BootstrapNode: "n0", Measurements: []string{pin}}), keyed, "a Recover decree"},
		{"recover without a key", sign(Decree{Kind: Recover, BootstrapNode: "n0"}), bare, "a Recover decree"},
		{"unknown kind", sign(Decree{Kind: "Nuke"}), keyed, "unknown kind"},
		{"voters on update", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{pin}, Voters: 3}), keyed, "names a voter count"},
		{"set voters without count", sign(Decree{Kind: SetVoters}), keyed, "names a voter count"},
		{"even voters", sign(Decree{Kind: SetVoters, Voters: 2}), keyed, "voters must be odd"},
		{"too many voters", sign(Decree{Kind: SetVoters, Voters: MaxVoters + 2}), keyed, "voters must be odd"},
		{"voters without a key", sign(Decree{Kind: SetVoters, Voters: 3}), bare, "a SetVoters decree applies"},
		{"voters with a set", sign(Decree{Kind: SetVoters, Voters: 3, Measurements: []string{pin}}), keyed, "a SetVoters decree applies"},
		{"unsorted set", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{"m2", "m1"}}), keyed, "canonical"},
		{"duplicate pins", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{"m1", "m1"}}), keyed, "canonical"},
		{"images on recover", sign(Decree{Kind: Recover, BootstrapNode: "n0", Images: []DecreeImage{img}}), keyed, "not exactly the pins"},
		{"set is not the images", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{"m1"}, Images: []DecreeImage{img}}), keyed, "not exactly the pins"},
		{"bad image", sign(Decree{Kind: UpdateMeasurements, Measurements: []string{"m1"}, Images: []DecreeImage{{MRTD: "zz"}}}), keyed, "lowercase hex"},
		{"expired", sign(Decree{Kind: RotateKey, ExpiresAt: now.Add(-time.Second)}), keyed, "expired"},
	} {
		err := CheckDecree(c.sd, c.tail, now)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// VerifyDecreeSignature is the audit check of the decree record: the
// operator signature only.
func TestVerifyDecreeSignature(t *testing.T) {
	k, pub := operatorKey(t)
	ok, err := SignDecree(Decree{ClusterID: testCluster, IntentID: "i", Kind: RotateKey}, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecreeSignature(ok, pub); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	tampered := ok
	tampered.Decree.BaseEpoch = 9
	// The operator key signs other things with SignDetached too: a
	// signature over the bare decree JSON, without the domain, is not one.
	body, _ := json.Marshal(ok.Decree)
	bare := ok
	bare.Signature, _ = operatorauth.SignDetached(k, body)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	for name, c := range map[string]struct {
		sd   SignedDecree
		key  []byte
		want string
	}{
		"tampered":    {tampered, pub, "bad operator signature"},
		"no domain":   {bare, pub, "bad operator signature"},
		"junk key":    {ok, []byte("junk"), "decree key"},
		"Ed25519 key": {ok, edDER, "not ECDSA"},
	} {
		if err := VerifyDecreeSignature(c.sd, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The decree record is bounded, oldest first out, and snapshots carry it.
func TestDecreeRecordBound(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	f.mu.Lock()
	for i := range maxDecreeRecord + 10 {
		f.record(SignedDecree{Decree: Decree{IntentID: "d"}}, int64(i), uint64(i))
	}
	f.mu.Unlock()
	rec := f.Decrees()
	if len(rec) != maxDecreeRecord || rec[0].Epoch != 10 {
		t.Fatalf("bound: %d records, first epoch %d", len(rec), rec[0].Epoch)
	}
	g := newTestFSM(t, opPub)
	if err := restoreCopy(t, f, g); err != nil || len(g.Decrees()) != maxDecreeRecord {
		t.Fatalf("restore: %v, %d records", err, len(g.Decrees()))
	}
}

// A decree object without data still takes a status; a failing API is reported.
func TestSetDecreeStatusEdges(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "decrees"}})
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if err := st.SetDecreeStatus(ctx, "d", DecreeStatus{RejectedReason: "no"}); err != nil {
		t.Fatal(err)
	}
	cm, _ := kube.CoreV1().ConfigMaps("decrees").Get(ctx, "d", metav1.GetOptions{})
	if !strings.Contains(cm.Data[keyStatus], "no") {
		t.Fatalf("status %q", cm.Data[keyStatus])
	}
	kube.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(corev1.Resource("configmaps"), "d", errors.New("changed"))
	})
	if err := st.SetDecreeStatus(ctx, "d", DecreeStatus{RejectedReason: "no"}); err == nil {
		t.Fatal("a conflicting update reported as written")
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

func testImage(b byte) DecreeImage {
	h := func(c byte) string { return strings.Repeat(string("0123456789abcdef"[c%16]), 96) }
	return DecreeImage{MRTD: h(b), RTMR1: h(b + 1), RTMR2: h(b + 2)}
}

// A decree that names images is kept in the agreed state, for clients
// outside the group (GET /ha/pins); a later set without images drops it,
// so those clients are never told a set that is no longer in force.
func TestPinDecreeIsAgreedState(t *testing.T) {
	a, b := testImage(1), testImage(5)
	pinA, _ := a.Pin()
	pinB, _ := b.Pin()
	opKey, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	ca := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	apply := func(i uint64, de DecreeEntry) {
		t.Helper()
		de.AtMS = time.Now().UnixMilli()
		if res := applyAt(f, i, Entry{Kind: KindDecree, Decree: &de}).(DecreeResult); res.Err != "" {
			t.Fatalf("entry %d: %s", i, res.Err)
		}
	}
	apply(1, DecreeEntry{Policy: f.LocalPolicy(), Decree: signDecree(t, opKey, Decree{Kind: Genesis, BootstrapNode: "n0"}), Pins: []string{pinA}, RootCert: ca.Cert.Raw, Key: key})
	if f.Core().PinsDecree != nil {
		t.Fatal("a pin decree before any was applied")
	}
	ab := signDecree(t, opKey, Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: normalizePins([]string{pinA, pinB}), Images: []DecreeImage{a, b}})
	apply(2, DecreeEntry{Decree: ab})
	if sd := f.Core().PinsDecree; sd == nil || sd.Decree.IntentID != ab.Decree.IntentID {
		t.Fatalf("pin decree %+v", sd)
	}
	apply(3, DecreeEntry{Decree: signDecree(t, opKey, Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: normalizePins([]string{pinA, pinB, "ee"})})})
	if f.Core().PinsDecree != nil {
		t.Fatal("a set without images kept the pin decree")
	}
}

func TestVerifyPinDecree(t *testing.T) {
	k, pub := operatorKey(t)
	other, _ := operatorKey(t)
	a, b := testImage(1), testImage(5)
	pinA, _ := a.Pin()
	pinB, _ := b.Pin()
	sign := func(key *ecdsa.PrivateKey, d Decree) SignedDecree {
		d.ExpiresAt = time.Now().Add(-time.Hour) // expired: clients ignore expiry
		return signDecree(t, key, d)
	}
	good := sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA, pinB}, Images: []DecreeImage{a, b}})
	if err := VerifyPinDecree(good, testCluster, pub); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		sd   SignedDecree
		want string
	}{
		"other cluster":   {good, "cluster"},
		"other key":       {sign(other, good.Decree), "signature"},
		"no images":       {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}}), "no images"},
		"genesis":         {sign(k, Decree{ClusterID: testCluster, Kind: Genesis, BootstrapNode: "n0", Images: []DecreeImage{a}}), "not exactly the pins"},
		"pins not images": {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}, Images: []DecreeImage{b}}), "not exactly the pins"},
		"bad image":       {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{"x"}, Images: []DecreeImage{{MRTD: "zz"}}}), "lowercase hex"},
	} {
		cluster := testCluster
		if name == "other cluster" {
			cluster = "elsewhere"
		}
		if err := VerifyPinDecree(c.sd, cluster, pub); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
