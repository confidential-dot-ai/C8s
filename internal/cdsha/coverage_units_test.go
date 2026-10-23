package cdsha

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
)

// Backups sealed to, or opened with, a key off P-256 fail closed.
func TestBackupRefusesOtherCurves(t *testing.T) {
	meta := BackupMeta{ClusterID: testCluster, Epoch: 1, Index: 2}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SealBackup(&p224.PublicKey, meta, []byte("snap")); err == nil {
		t.Fatal("sealed to a P-224 key")
	}
	if _, err := SealBackup(&p384.PublicKey, meta, []byte("snap")); err == nil {
		t.Fatal("sealed to a P-384 key")
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := SealBackup(&rk.PublicKey, meta, []byte("snap"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(p224, b); err == nil {
		t.Fatal("opened with a P-224 key")
	}
	if _, err := OpenBackup(p384, b); err == nil {
		t.Fatal("opened with a P-384 key")
	}
	bad := b
	bad.EphemeralPub = []byte{4, 1, 2}
	if _, err := OpenBackup(rk, bad); err == nil {
		t.Fatal("opened with a malformed ephemeral key")
	}
	if got, err := OpenBackup(rk, b); err != nil || string(got) != "snap" {
		t.Fatalf("round trip %q: %v", got, err)
	}
}

// A backup that authenticates but does not hold a gzip stream is refused.
func TestOpenBackupRefusesNonGzipPlaintext(t *testing.T) {
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rec, _ := rk.PublicKey.ECDH()
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(rec)
	aead, err := backupKey(shared, eph.PublicKey().Bytes(), rec.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	meta := BackupMeta{ClusterID: testCluster}
	aad, _ := json.Marshal(meta)
	nonce := make([]byte, aead.NonceSize())
	b := Backup{Meta: meta, EphemeralPub: eph.PublicKey().Bytes(), Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, []byte("not gzip"), aad)}
	if _, err := OpenBackup(rk, b); err == nil {
		t.Fatal("a non-gzip backup opened")
	}
}

func failOn(verb string, match func(k8stesting.Action) bool) k8stesting.ReactionFunc {
	return func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() == verb && (match == nil || match(a)) {
			return true, nil, errors.New("api down")
		}
		return false, nil, nil
	}
}

// Reads of backups and decrees report the API's errors.
func TestDecreeStoreListErrors(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	kube.PrependReactor("list", "configmaps", failOn("list", nil))
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if _, err := st.GetBackup(ctx); err == nil {
		t.Fatal("a backup read through a failing API")
	}
	if _, err := st.PendingDecrees(ctx); err == nil {
		t.Fatal("decrees listed through a failing API")
	}
}

func TestBackupFromConfigMapsRefusesAnotherClustersManifest(t *testing.T) {
	ctx := context.Background()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: "other", Epoch: 1, Index: 1}, []byte("snap"))
	kube := fake.NewClientset()
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if err := st.PutBackup(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBackup(ctx); err == nil || !strings.Contains(err.Error(), "another cluster") {
		t.Fatalf("a manifest for another cluster: %v", err)
	}
	list, _ := kube.CoreV1().ConfigMaps("decrees").List(ctx, metav1.ListOptions{})
	var man corev1.ConfigMap
	for _, cm := range list.Items {
		if cm.Name == BackupName(testCluster) {
			man = cm
		}
	}
	man.Data[keyBackup] = `{"meta":{"cluster_id":"c1"},"parts":0}`
	if _, err := BackupFromConfigMaps(testCluster, []corev1.ConfigMap{man}); err == nil {
		t.Fatal("a manifest naming no parts")
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

// signRaw signs a decree as is, without SignDecree's normalization.
func signRaw(t *testing.T, d Decree, k *ecdsa.PrivateKey) SignedDecree {
	t.Helper()
	msg, err := d.signedBytes()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return SignedDecree{Decree: d, Signature: sig}
}

func TestVerifyDecreeEdges(t *testing.T) {
	k, pub := operatorKey(t)
	tail := PreGenesis(testCluster, pub)
	exp := time.Now().Add(time.Hour)
	for name, d := range map[string]Decree{
		"empty intent_id":    {ClusterID: testCluster, Kind: UpdateMeasurements, Measurements: []string{"m"}, ExpiresAt: exp},
		"non-canonical pins": {ClusterID: testCluster, IntentID: "i", Kind: UpdateMeasurements, Measurements: []string{"m2", "m1"}, ExpiresAt: exp},
		"duplicate pins":     {ClusterID: testCluster, IntentID: "i", Kind: UpdateMeasurements, Measurements: []string{"m1", "m1"}, ExpiresAt: exp},
	} {
		if err := CheckDecree(signRaw(t, d, k), tail, time.Now()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := signRaw(t, Decree{ClusterID: testCluster, IntentID: "i", Kind: UpdateMeasurements, Measurements: []string{"m1", "m2"}, ExpiresAt: exp}, k)
	if err := CheckDecree(ok, tail, time.Now()); err != nil {
		t.Fatalf("canonical decree refused: %v", err)
	}
	if err := VerifyDecreeSignature(ok, []byte("junk")); err == nil || !strings.Contains(err.Error(), "decree key") {
		t.Fatalf("junk decree key: %v", err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	if err := VerifyDecreeSignature(ok, edDER); err == nil || !strings.Contains(err.Error(), "not ECDSA") {
		t.Fatalf("Ed25519 decree key: %v", err)
	}
	if err := VerifyDecreeSignature(ok, pub); err != nil {
		t.Fatalf("good signature: %v", err)
	}
}
