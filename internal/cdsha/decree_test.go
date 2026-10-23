package cdsha

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"context"
	"errors"

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
