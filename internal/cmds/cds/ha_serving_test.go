package cds

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A serving one-seat replica publishes its decree record and, once a decree
// with images set the pins, the signed decree behind them.
func TestHAServingReplicaPublishesDecrees(t *testing.T) {
	ctx := context.Background()
	h := func(c string) string { return strings.Repeat(c, 96) }
	img := cdsha.DecreeImage{MRTD: h("a"), RTMR1: h("b"), RTMR2: h("c")}
	pin, err := img.Pin()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := testKeyPEM(t)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	kube := fake.NewClientset()
	src := cdsha.KubeDecrees{Client: kube, Namespace: "ns", ClusterID: "c1"}
	put := func(d cdsha.Decree) {
		t.Helper()
		d.ClusterID, d.ExpiresAt = "c1", time.Now().Add(time.Hour)
		sd, err := cdsha.SignDecree(d, key)
		if err != nil {
			t.Fatal(err)
		}
		cm, _ := cdsha.DecreeConfigMap("ns", sd)
		if _, err := kube.CoreV1().ConfigMaps("ns").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	al, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { al.Close() })
	timing := cdsha.Timing{Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, Lease: time.Second,
		DeadAfter: 1500 * time.Millisecond, Stabilize: 200 * time.Millisecond, Apply: 3 * time.Second, Tick: 50 * time.Millisecond, Backup: time.Second}
	node, err := cdsha.NewNode(cdsha.Config{ClusterID: "c1", NodeName: "n0", Bind: addr, Advertise: addr,
		Attestor: fakeAttestor{pin}, BakedPins: []string{pin}, OperatorPubKey: pub, Seats: 1, Decrees: src, Timing: timing,
		Peers:     func(context.Context) ([]string, error) { return nil, nil },
		Allowlist: &al, Secrets: secrets.NewMemoryStore(4, 2, 64), Ledger: sandboxledger.New(time.Hour, 4)})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = node.Run(runCtx) }()
	t.Cleanup(func() { cancel(); <-done })
	settled := func(what string) {
		t.Helper()
		eventually(t, 10*time.Second, what+": decrees applied and serving", func() bool {
			pending, err := src.PendingDecrees(ctx)
			return err == nil && len(pending) == 0 && node.Serving()
		})
	}
	put(cdsha.Decree{IntentID: "g", Kind: cdsha.Genesis, BootstrapNode: "n0"})
	settled("genesis")
	// Issuance and /secrets challenges must not be redeemable against each other.
	if iss := haChallengeKey(node, "issuance")(); iss == nil || bytes.Equal(iss, haChallengeKey(node, "secrets")()) {
		t.Fatal("a serving replica derives no challenge key, or one key for both pools")
	}
	get := func(hf http.HandlerFunc) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		hf(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w
	}
	if w := get(haPins(node)); w.Code != http.StatusNotFound {
		t.Fatalf("pins after Genesis: %d", w.Code)
	}
	put(cdsha.Decree{IntentID: "u", Kind: cdsha.UpdateMeasurements, BaseEpoch: 1, Images: []cdsha.DecreeImage{img}, Measurements: []string{pin}})
	settled("update measurements")
	w := get(haPins(node))
	var sd cdsha.SignedDecree
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &sd) != nil || sd.Decree.IntentID != "u" {
		t.Fatalf("pins: %d %s", w.Code, w.Body.String())
	}
	if err := cdsha.VerifyPinDecree(sd, "c1", pub); err != nil {
		t.Fatalf("served pin decree does not verify: %v", err)
	}
	var records []cdsha.DecreeRecord
	w = get(serveJSON(node.Decrees))
	if err := json.Unmarshal(w.Body.Bytes(), &records); err != nil || len(records) != 2 || records[0].Decree.Decree.Kind != cdsha.Genesis ||
		records[1].Decree.Decree.IntentID != "u" || records[1].Epoch != 2 {
		t.Fatalf("decree record %s: %v", w.Body.String(), err)
	}
}
