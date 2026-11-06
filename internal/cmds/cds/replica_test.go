package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A replica serves at its own address, because its peers, the nodes and the
// operator all reach it there and its cluster's replica entries resolve to it.
func TestAReplicaServesAtItsOwnAddress(t *testing.T) {
	own, err := peerAddress(config{host: "10.1.2.3"})
	if err != nil {
		t.Fatalf("peerAddress = %v", err)
	}
	if own.String() != "10.1.2.3:8444" {
		t.Errorf("peer address = %s, want the VM's address at the peer port", own)
	}
	for name, host := range map[string]string{
		"every address": "0.0.0.0",
		"a name":        "cds.example.com",
		"nothing":       "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := peerAddress(config{host: host}); err == nil {
				t.Errorf("peerAddress(%q) = nil error, want a refusal", host)
			}
		})
	}
}

// A replica's allowlist is the cluster's, so a configuration that also claims
// a durable database is refused rather than served from both.
func TestAReplicaRefusesADurableAllowlist(t *testing.T) {
	cfg, state := replicatedRunConfig(t, mockapi.New(t).URL())
	cfg.allowlistPersistent = true

	_, err := newReplica(context.Background(), cfg, state)
	if err == nil || !strings.Contains(err.Error(), "--allowlist-persistent") {
		t.Fatalf("newReplica = %v, want the durable allowlist refused", err)
	}
}

// Before it joins, a replica answers health and the reports a Genesis decree
// is written from, and nothing else: the operator reads the member id this
// process minted and the mesh CA it would install.
func TestAReplicaReportsItselfWhileItJoins(t *testing.T) {
	cfg, state := replicatedRunConfig(t, attestingAPI(t))
	cfg.host = "127.0.0.1"
	cfg.port = freePort(t)

	ctx, stopJoining := context.WithCancel(context.Background())
	defer stopJoining()
	joined := startReplica(t, ctx, cfg, state)

	base := "https://" + clientAddress(cfg)
	client := armTLSClient(nil)
	waitForReplica(t, client, base)

	for path, want := range map[string]int{
		"/healthz":    http.StatusOK,
		"/readyz":     http.StatusServiceUnavailable,
		"/ha/status":  http.StatusOK,
		"/ha/decrees": http.StatusOK,
		// No decree pins the cluster's CDS images yet.
		"/ha/pins": http.StatusNotFound,
		// Everything a joined replica serves waits for the cluster.
		"/allowlist": http.StatusServiceUnavailable,
		"/ca":        http.StatusServiceUnavailable,
	} {
		if code := statusOf(t, client, base+path); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}

	var reported cdsha.Status
	if err := json.Unmarshal(fetch(t, client, base+"/ha/status"), &reported); err != nil {
		t.Fatalf("decode /ha/status: %v", err)
	}
	if reported.ClusterID != cfg.measured.ClusterID || reported.Joined {
		t.Errorf("status = %+v, want this cluster, unjoined", reported)
	}
	if reported.ID == "" || reported.GenesisCA == "" {
		t.Errorf("status = %+v, want the member id and the mesh CA a Genesis decree names", reported)
	}
	// A decree is taken on no word but the operator's signature over it.
	unsigned := []byte(`{"decree":{"kind":"genesis"},"signature":"","key_id":""}`)
	if code := postStatus(t, client, base+"/ha/decrees", unsigned); code != http.StatusBadRequest {
		t.Errorf("POST /ha/decrees with a decree no operator signed = %d, want %d", code, http.StatusBadRequest)
	}

	stopJoining()
	if err := <-joined; !errors.Is(err, context.Canceled) {
		t.Fatalf("newReplica = %v, want it to end with the process", err)
	}
}

// While a replica may not serve its cluster it answers health, the reports an
// operator reads and nothing else: a replica out of contact must not issue a
// leaf, release a secret or hand out policy its cluster has moved past.
func TestTheGateRefusesWhatAReplicaMayNotServe(t *testing.T) {
	// What the router behind the gate answers for every route it is asked.
	const answered = http.StatusTeapot
	routed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(answered)
	})
	for path, unserved := range map[string]int{
		"/healthz":          answered,
		"/readyz":           answered,
		"/metrics":          answered,
		"/ha/status":        answered,
		"/ha/pins":          answered,
		"/ha/decrees":       answered,
		"/attest":           http.StatusServiceUnavailable,
		"/allowlist":        http.StatusServiceUnavailable,
		"/ca":               http.StatusServiceUnavailable,
		"/measurements":     http.StatusServiceUnavailable,
		"/secrets/a/secret": http.StatusServiceUnavailable,
	} {
		for serving, want := range map[bool]int{true: answered, false: unserved} {
			gated := haGate(func() bool { return serving }, routed)
			w := httptest.NewRecorder()
			gated.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != want {
				t.Errorf("GET %s with serving=%v = %d, want %d", path, serving, w.Code, want)
			}
		}
	}
}

func TestAReplicaCertifiesTheNodeImagesOfItsCluster(t *testing.T) {
	cfg, state := replicatedRunConfig(t, attestingAPI(t))
	if len(cfg.measured.Nodes.Images) == 0 {
		t.Fatal("the configuration under test names no node image")
	}
	node, err := newMember(cfg, state)
	if err != nil {
		t.Fatal(err)
	}

	certified := clusterNodeImages{node: node}
	if images := certified.Current().Images; len(images) != 0 {
		t.Errorf("a replica that holds no cluster certifies %+v", images)
	}
	if certified.Generation() != 0 {
		t.Errorf("a replica that holds no cluster names node image version %d", certified.Generation())
	}
}

// startReplica joins on a goroutine of its own and answers with why it stopped.
func startReplica(t *testing.T, ctx context.Context, cfg config, state stores) <-chan error {
	t.Helper()
	joined := make(chan error, 1)
	go func() {
		back, err := newReplica(ctx, cfg, state)
		if back != nil {
			back.Stop()
		}
		joined <- err
	}()
	return joined
}

// replicatedRunConfig is a CDS VM launched with a replica set's configuration.
func replicatedRunConfig(t *testing.T, attestationURL string) (config, stores) {
	t.Helper()
	cfg, err := withMeasuredConfig(
		validRunConfig(t, attestationURL),
		replicatedDocument(t, operatorKeysPEM(t)),
		teetypes.FamilySNP,
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := openStores(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.close)
	return cfg, state
}

// attestingAPI is the attestation-api on this VM's loopback, reporting one CDS image.
func attestingAPI(t *testing.T) string {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	stub.SetVerdict(mockapi.PassingVerdict(testutil.TestMeasurement))
	return stub.URL()
}

// waitForReplica waits until the replica's listener answers.
func waitForReplica(t *testing.T, client *http.Client, base string) {
	t.Helper()
	for range 100 {
		if resp, err := client.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the replica answered nothing while it joined")
}

// postStatus is how a replica answered one posted body.
func postStatus(t *testing.T, client *http.Client, url string, body []byte) int {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func statusOf(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
