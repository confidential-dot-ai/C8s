package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

func opToken(t *testing.T, key *ecdsa.PrivateKey, method, path string, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"htm": method, "htu": path, "pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func do(t *testing.T, method, url, token string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// Three complete CDS processes in HA mode, driven through the HTTP API: one
// cluster from a Genesis decree, one mesh CA, and every operator write made
// at one replica served by all, with its single-use token spent everywhere.
func TestRunHAReplicasServeOneState(t *testing.T) {
	origKube, origAtt := newInClusterKubeClientset, newHAAttestor
	t.Cleanup(func() { newInClusterKubeClientset, newHAAttestor = origKube, origAtt })
	kube := fake.NewClientset()
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return kube, nil }
	newHAAttestor = func(string, cdsha.AttestorOptions) (cdsha.Attestor, error) { return fakeAttestor{"m1"}, nil }

	api := newHealthyAttestationApi(t)
	opKey, keysPath := writeOperatorKeyPair(t)
	httpPort, peerPort := freePort(t), freePort(t)
	hosts := []string{"127.0.3.10", "127.0.3.11", "127.0.3.12"}

	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "genesis", Kind: cdsha.Genesis,
		BootstrapNode: "n0", ExpiresAt: time.Now().Add(time.Hour)}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	cm, _ := cdsha.DecreeConfigMap("ns", sd)
	if _, err := kube.CoreV1().ConfigMaps("ns").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, len(hosts))
	bases := make([]string, len(hosts))
	for i, host := range hosts {
		cfg := validRunConfig(t, api.URL)
		cfg.host, cfg.port, cfg.operatorKeys = host, httpPort, keysPath
		cfg.jwtClockSkew = 1
		var peers []string
		for j, h := range hosts {
			if j != i {
				peers = append(peers, fmt.Sprintf("%s:%d", h, peerPort))
			}
		}
		cfg.ha = haConfig{clusterID: "c1", decreeNS: "ns", peers: peers, advertiseIP: host, port: peerPort,
			nodeName: fmt.Sprintf("n%d", i), attestor: "test", pins: []string{"m1"}, operatorKey: keysPath,
			seats: 3, maxNonVoters: 4, timing: cdsha.DefaultTiming}
		bases[i] = fmt.Sprintf("http://%s:%d", host, httpPort)
		go func() { errs <- run(cfg) }()
	}
	t.Cleanup(func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		for range hosts {
			select {
			case <-errs:
			case <-time.After(20 * time.Second):
				t.Error("a replica did not stop")
			}
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for _, b := range bases {
		for {
			if time.Now().After(deadline) {
				t.Fatalf("%s never became healthy", b)
			}
			if resp, err := http.Get(b + "/ha/status"); err == nil {
				var st cdsha.Status
				_ = json.NewDecoder(resp.Body).Decode(&st)
				resp.Body.Close()
				if st.Serving {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Tokens are refused until the clock skew has passed since Genesis: an
	// earlier life of the cluster may have spent older ones.
	time.Sleep(2500 * time.Millisecond)

	// One mesh CA, served by every replica.
	var ca []byte
	for _, b := range bases {
		code, _, body := do(t, http.MethodGet, b+"/ca", "", nil)
		if code != http.StatusOK || (ca != nil && !bytes.Equal(body, ca)) {
			t.Fatalf("%s /ca: %d, same=%v", b, code, bytes.Equal(body, ca))
		}
		ca = body
	}

	// A whole-document write at replica 0, served by 1 and 2 with one ETag.
	doc := []byte(anySeed(map[string]string{"web": digestA}))
	tok := opToken(t, opKey, http.MethodPut, "/allowlist", doc)
	if code, _, body := do(t, http.MethodPut, bases[0]+"/allowlist", tok, doc); code != http.StatusNoContent {
		t.Fatalf("PUT /allowlist at replica 0: %d %s", code, body)
	}
	_, h0, _ := do(t, http.MethodGet, bases[0]+"/allowlist", "", nil)
	for _, b := range bases[1:] {
		code, h, body := do(t, http.MethodGet, b+"/allowlist", "", nil)
		if code != http.StatusOK || h.Get("ETag") != h0.Get("ETag") || !strings.Contains(string(body), digestA) {
			t.Fatalf("%s serves another allowlist: %d etag %q vs %q", b, code, h.Get("ETag"), h0.Get("ETag"))
		}
	}
	// The same token replayed at another replica is refused.
	if code, _, _ := do(t, http.MethodPut, bases[2]+"/allowlist", tok, doc); code < 400 {
		t.Fatalf("a spent operator token was accepted at another replica: %d", code)
	}
	// A per-entry write at replica 1 reaches replica 0.
	entry := []byte(`{"label":"ghcr.io/x/api:v1","containers":[{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","command":{"policy":"any"},"args":{"policy":"any"}}]}`)
	if code, _, body := do(t, http.MethodPut, bases[1]+"/allowlist/workloads/api", opToken(t, opKey, http.MethodPut, "/allowlist/workloads/api", entry), entry); code != http.StatusNoContent {
		t.Fatalf("PUT workload at replica 1: %d %s", code, body)
	}
	if _, _, body := do(t, http.MethodGet, bases[0]+"/allowlist", "", nil); !strings.Contains(string(body), "2222222222") {
		t.Fatal("replica 0 does not serve the entry written at replica 1")
	}
	// Every replica serves the same history, signature included.
	_, _, hist0 := do(t, http.MethodGet, bases[0]+"/allowlist/history", "", nil)
	for _, b := range bases[1:] {
		if _, _, h := do(t, http.MethodGet, b+"/allowlist/history", "", nil); !bytes.Equal(h, hist0) {
			t.Fatalf("%s serves another history:\n%s\nvs\n%s", b, h, hist0)
		}
	}
}
