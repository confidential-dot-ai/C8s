package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

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
	if _, err := OpenBackup(rk, Backup{Meta: meta, Ciphertext: b.Ciphertext[:10]}); err == nil {
		t.Fatal("opened a truncated backup")
	}
	if got, err := OpenBackup(rk, b); err != nil || string(got) != "snap" {
		t.Fatalf("round trip %q: %v", got, err)
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
