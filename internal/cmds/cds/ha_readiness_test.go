package cds

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A replica that has not joined is never Ready, not even once it awaits a
// restore: Ready puts it in the client Service, and from the inside a
// partition looks like a total loss. Status and
// restore stay reachable for the operator.
func TestPreJoinNeverReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pin, err := cdsha.DecreeImage{MRTD: strings.Repeat("a", 96), RTMR1: strings.Repeat("b", 96), RTMR2: strings.Repeat("c", 96)}.Pin()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := testKeyPEM(t)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	timing := cdsha.Timing{Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, Lease: time.Second,
		DeadAfter: time.Second, Stabilize: 200 * time.Millisecond, Apply: 3 * time.Second, Tick: 50 * time.Millisecond, Backup: time.Second}
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", freePort(t)), fmt.Sprintf("127.0.0.1:%d", freePort(t))}
	var nodes []*cdsha.Node
	var done []chan struct{}
	t.Cleanup(func() {
		cancel()
		for _, d := range done {
			<-d
		}
	})
	for i, addr := range addrs {
		other := addrs[1-i]
		al, _ := allowlist.OpenInMemory()
		t.Cleanup(func() { al.Close() })
		node, err := cdsha.NewNode(cdsha.Config{ClusterID: "c1", NodeName: fmt.Sprintf("n%d", i), Bind: addr, Advertise: addr,
			Attestor: fakeAttestor{pin}, BakedPins: []string{pin}, OperatorPubKey: pub, Seats: 3, Timing: timing,
			Decrees:   cdsha.KubeDecrees{Client: fake.NewClientset(), Namespace: "ns", ClusterID: "c1"},
			Peers:     func(context.Context) ([]string, error) { return []string{other}, nil },
			Allowlist: &al, Secrets: secrets.NewMemoryStore(4, 2, 64), Ledger: sandboxledger.New(time.Hour, 4)})
		if err != nil {
			t.Fatal(err)
		}
		if err := node.Start(); err != nil {
			t.Fatal(err)
		}
		d := make(chan struct{})
		go func() { defer close(d); _ = node.Run(ctx) }()
		nodes, done = append(nodes, node), append(done, d)
	}
	srv := httptest.NewServer(preJoinMux(nodes[0]))
	t.Cleanup(srv.Close)
	get := func(path string) (int, []byte) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	eventually(t, 20*time.Second, "both blank replicas await a restore", func() bool {
		if code, body := get("/readyz"); code != http.StatusServiceUnavailable {
			t.Fatalf("an unjoined replica answered /readyz %d %s", code, body)
		}
		return nodes[0].AwaitingRestore()
	})
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("a replica awaiting a restore answered /readyz %d %s", code, body)
	}
	code, raw := get("/ha/status")
	var st cdsha.Status
	if code != http.StatusOK || json.Unmarshal(raw, &st) != nil || !st.AwaitingRestore || st.Joined {
		t.Fatalf("/ha/status of a replica awaiting a restore: %d %s", code, raw)
	}
	// The restore route answers (here: refuses a body that is no request).
	resp, err := http.Post(srv.URL+"/ha/restore", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/ha/restore on a replica awaiting a restore: %d", resp.StatusCode)
	}
}
