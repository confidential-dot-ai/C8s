package cdsha

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// TestStoreContract runs the four calls' contract on every backend; etcd
// runs against a real etcd at C8S_TEST_ETCD_URL.
func TestStoreContract(t *testing.T) {
	stores := map[string]Store{
		"memory": NewMemory(),
		"kube":   &Kube{ConfigMaps: fake.NewClientset().CoreV1().ConfigMaps("c8s-cds"), Cluster: "lane"},
	}
	if url := os.Getenv("C8S_TEST_ETCD_URL"); url != "" {
		e, err := OpenEtcd(clientv3.Config{Endpoints: []string{url}, DialTimeout: 5 * time.Second}, "contract-"+strings.ToLower(time.Now().Format("150405.000000")))
		if err != nil {
			t.Fatal(err)
		}
		stores["etcd"] = e
	}
	ctx := context.Background()
	for name, st := range stores {
		t.Run(name, func(t *testing.T) {
			if head, err := st.GetHead(ctx); err != nil || head != nil {
				t.Fatalf("empty store head = %q, %v", head, err)
			}
			if err := st.CASHead(ctx, []byte("x"), []byte("a")); !errors.Is(err, ErrConflict) {
				t.Fatalf("CAS on an absent head from a value: %v", err)
			}
			if err := st.CASHead(ctx, nil, []byte("a")); err != nil {
				t.Fatal(err)
			}
			if err := st.CASHead(ctx, nil, []byte("b")); !errors.Is(err, ErrConflict) {
				t.Fatalf("create over a head: %v", err)
			}
			if err := st.CASHead(ctx, []byte("b"), []byte("c")); !errors.Is(err, ErrConflict) {
				t.Fatalf("CAS from another head: %v", err)
			}
			if err := st.CASHead(ctx, []byte("a"), []byte("c")); err != nil {
				t.Fatal(err)
			}
			if head, _ := st.GetHead(ctx); string(head) != "c" {
				t.Fatalf("head = %q", head)
			}
			h := cdschain.Hash{9}
			if data, err := st.GetEntry(ctx, h); err != nil || data != nil {
				t.Fatalf("absent entry = %q, %v", data, err)
			}
			for range 2 {
				if err := st.PutEntry(ctx, h, []byte("entry")); err != nil {
					t.Fatalf("put (idempotent): %v", err)
				}
			}
			if data, _ := st.GetEntry(ctx, h); string(data) != "entry" {
				t.Fatalf("entry = %q", data)
			}
		})
	}
}
