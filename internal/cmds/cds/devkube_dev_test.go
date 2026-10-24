//go:build c8s_dev

package cds

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// The dev Kubernetes stand-in must not keep what it was asked to store: a
// replica writes every backup through it, for hours. 256 MiB of ConfigMap
// writes leave the heap far below that.
func TestDirKubeDoesNotRetainWrites(t *testing.T) {
	saved := dirKubeClearEvery
	dirKubeClearEvery = 20 * time.Millisecond
	t.Cleanup(func() { dirKubeClearEvery = saved })
	cs := dirKube(t.TempDir())
	cms := cs.CoreV1().ConfigMaps("ns")
	part := make([]byte, 1<<20)
	ctx := context.Background()
	for i := range 256 {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("part-%d", i%4), Namespace: "ns"}, BinaryData: map[string][]byte{"part": part}}
		if i < 4 {
			if _, err := cms.Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		} else if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if i%32 == 31 {
			time.Sleep(3 * dirKubeClearEvery) // writes go on for hours, not in one burst
		}
	}
	time.Sleep(3 * dirKubeClearEvery)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if n := len(cs.(*fake.Clientset).Actions()); n > 64 || ms.HeapAlloc > 96<<20 {
		t.Fatalf("after 256 MiB of writes: %d actions kept, heap %d MiB", n, ms.HeapAlloc>>20)
	}
	t.Logf("after 256 MiB of writes: heap %d MiB", ms.HeapAlloc>>20)
}
