package getvolume

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const flowSandbox = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// stubResolver is an inventory that vouches for one sandbox. The token route
// binds its caller by peer credentials, which a unix socket supplies.
type stubResolver struct{}

func (stubResolver) SandboxForPeer(workloadclaims.Peer) (string, error) { return flowSandbox, nil }
func (stubResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// startInventory serves the real token route on a unix socket and returns its
// endpoint.
func startInventory(t *testing.T) string {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go workloadclaims.ServeTokens(ctx, l, stubResolver{}, signer)
	t.Cleanup(func() { cancel(); l.Close() })

	return "unix://" + sock
}

// fakeCDS records what it was asked and answers from a scripted sequence.
type fakeCDS struct {
	mu         sync.Mutex
	challenges int
	requests   []string // "METHOD /path"
	tokens     []string // the Authorization header of each store request
	replies    map[string][]reply
}

type reply struct {
	status int
	value  []byte // raw value; encoded as base64 in the response
}

func newFakeCDS(t *testing.T, replies map[string][]reply) (*fakeCDS, string) {
	t.Helper()
	f := &fakeCDS{replies: replies}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Method == http.MethodPost && r.URL.Path == secrets.ChallengeRoute {
		f.challenges++
		nonce := make([]byte, 32)
		rand.Read(nonce)
		json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(nonce)})
		return
	}

	key := r.Method + " " + r.URL.Path
	f.requests = append(f.requests, key)
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	if r.Header.Get(secrets.ChallengeHeader) == "" {
		http.Error(w, "no challenge", http.StatusBadRequest)
		return
	}

	queue := f.replies[key]
	if len(queue) == 0 {
		http.Error(w, "unscripted", http.StatusTeapot)
		return
	}
	next := queue[0]
	f.replies[key] = queue[1:]
	if next.status != http.StatusOK {
		w.WriteHeader(next.status)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"value": base64.StdEncoding.EncodeToString(next.value)})
}

func (f *fakeCDS) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func testBlob(t *testing.T) volume.Blob {
	t.Helper()
	key := make([]byte, volume.KeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	blob, err := volume.NewBlob(key, volume.Verity{
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 4,
		HashOffset: 4 * volume.VerityBlockSize,
	})
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	return blob
}

func testBlobJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(testBlob(t))
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}
	return raw
}

func testMutableBlobJSON(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, volume.KeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	blob, err := volume.NewMutableBlob(key)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	raw, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}
	return raw
}

func flowConfig(t *testing.T, url string) config {
	t.Helper()
	return config{
		SecretsURL:       url,
		Attempts:         3,
		RetryInterval:    time.Millisecond,
		RequestTimeout:   5 * time.Second,
		InventoryTimeout: 5 * time.Second,
		SocketDir:        t.TempDir(),
		Volumes:          []volumeRequest{{Name: "weights", Path: "/tenant-a/volumes/weights"}},
	}
}

func testKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

func TestFetchBlobReadsTheStore(t *testing.T) {
	endpoint := startInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: testBlobJSON(t)}},
	})

	got, err := fetchBlob(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), endpoint, "/tenant-a/volumes/weights")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Key != testBlob(t).Key {
		t.Fatalf("blob key = %q, want the stored one", got.Key)
	}
}

// get-secret POSTs on 404 to mint a value, because the first pod of a workload
// to ask is the one that defines it. A volume key is never minted: a POST here
// would squat the path with random bytes that decrypt nothing and leave the
// real key unwritable behind a 409.
func TestFetchBlobNeverCreates(t *testing.T) {
	endpoint := startInventory(t)
	f, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusNotFound}},
	})

	if _, err := fetchBlob(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), endpoint, "/tenant-a/volumes/weights"); err == nil {
		t.Fatal("an absent key was accepted")
	}
	for _, req := range f.seen() {
		if strings.HasPrefix(req, http.MethodPost) {
			t.Errorf("get-volume wrote to the store: %s", req)
		}
	}
}

// A denial is not a reason to write either: release is refused until every main
// container is admitted, so 403 is the normal early answer.
func TestFetchBlobDoesNotWriteOnDenial(t *testing.T) {
	endpoint := startInventory(t)
	f, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusForbidden}},
	})

	if _, err := fetchBlob(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), endpoint, "/tenant-a/volumes/weights"); err == nil {
		t.Fatal("a denial was accepted")
	}
	if got := f.seen(); len(got) != 1 || got[0] != "GET /secrets/tenant-a/volumes/weights" {
		t.Errorf("requests = %v, want one GET", got)
	}
}

// A value that is not a key blob is refused rather than handed to the daemon.
func TestFetchBlobRejectsANonBlob(t *testing.T) {
	endpoint := startInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: []byte(`{"type":"something/else"}`)}},
	})

	if _, err := fetchBlob(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), endpoint, "/tenant-a/volumes/weights"); err == nil {
		t.Fatal("a foreign document was accepted as a key blob")
	}
}

// Each request carries its own challenge and its own token; both are single-use
// at CDS, so a reused pair is a replayed request.
func TestEveryRequestTakesAFreshChallengeAndToken(t *testing.T) {
	endpoint := startInventory(t)
	f, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {
			{status: http.StatusForbidden},
			{status: http.StatusOK, value: testBlobJSON(t)},
		},
	})
	cfg := flowConfig(t, url)

	for range 2 {
		_, _ = fetchBlob(context.Background(), cfg, http.DefaultClient, testKey(t), endpoint, "/tenant-a/volumes/weights")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.challenges != 2 {
		t.Errorf("challenges = %d, want one per request", f.challenges)
	}
	if len(f.tokens) == 2 && f.tokens[0] == f.tokens[1] {
		t.Error("the same sandbox token was presented twice")
	}
}
