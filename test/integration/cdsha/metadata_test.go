//go:build integration && linux

package cdsha_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

// A separate executable owns the SQLite file. The TLS proxy only injects
// latency, outages and a lost response; it stores no authoritative state.
type metadataFixture struct {
	owner     *cluster
	process   *process
	args      []string
	upstream  string
	endpoint  string
	client    *http.Client
	namespace string
	token     string
	outage    atomic.Bool
	delayNS   atomic.Int64
	dropNext  atomic.Bool
	dropped   atomic.Uint64
}

func attachMetadata(t *testing.T, f *objectFixture) {
	t.Helper()
	m := &metadataFixture{owner: &cluster{t: t}, namespace: f.config.Prefix}
	proxy := httptest.NewTLSServer(http.HandlerFunc(m.serve))
	t.Cleanup(proxy.Close)
	m.client = proxy.Client()
	m.client.Timeout = 7 * time.Second
	m.endpoint = proxy.URL
	dir := t.TempDir()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	private, err := x509.MarshalPKCS8PrivateKey(proxy.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile, tokenFile := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls-key.pem"), filepath.Join(dir, "token")
	write(t, certFile, cert)
	write(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	m.token = hex.EncodeToString(token[:])
	write(t, tokenFile, []byte(m.token))
	if err := os.Chmod(tokenFile, 0600); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	m.upstream = fmt.Sprintf("https://127.0.0.1:%d", port)
	m.args = []string{"--listen", fmt.Sprintf("127.0.0.1:%d", port), "--db", filepath.Join(dir, "state.db"), "--namespace", m.namespace, "--token-file", tokenFile, "--tls-cert", certFile, "--tls-key", keyFile}
	m.restart()
	// Preserve the object server's trust anchor as well as the metadata proxy's.
	var roots []byte
	if f.certificate != "" {
		roots, err = os.ReadFile(f.certificate)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.certificate = filepath.Join(dir, "roots.pem")
	write(t, f.certificate, append(roots, cert...))
	f.config.MetadataEndpoint = proxy.URL
	var provision cdsobject.Provision
	if err := json.Unmarshal(f.provision, &provision); err != nil {
		t.Fatal(err)
	}
	provision.MetadataToken = m.token
	f.provision, err = json.Marshal(provision)
	if err != nil {
		t.Fatal(err)
	}
	f.metadata = m
}

func (m *metadataFixture) restart() {
	m.process = m.owner.run("metadata", built.metadata, m.args, nil)
	m.owner.waitFor("transactional metadata service", 10*time.Second, func() bool {
		response, err := m.request(m.upstream, "/v1/stats")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
}

func (m *metadataFixture) request(origin, path string) (*http.Response, error) {
	r, err := http.NewRequest(http.MethodGet, origin+path, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+m.token)
	r.Header.Set("X-CDS-Namespace", m.namespace)
	return m.client.Do(r)
}

func (m *metadataFixture) stats() metadatapilot.Stats {
	m.owner.t.Helper()
	response, err := m.request(m.upstream, "/v1/stats")
	if err != nil {
		m.owner.t.Fatal(err)
	}
	defer response.Body.Close()
	var stats metadatapilot.Stats
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&stats) != nil {
		m.owner.t.Fatal("metadata stats unavailable")
	}
	return stats
}

func (m *metadataFixture) serve(w http.ResponseWriter, r *http.Request) {
	if delay := time.Duration(m.delayNS.Load()); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	if m.outage.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, m.upstream+r.URL.RequestURI(), r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	request.Header = r.Header.Clone()
	request.GetBody = nil
	response, err := m.client.Do(request)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	if (r.Method == http.MethodPut || r.URL.Path == metadatapilot.StateCommitPath) && response.StatusCode == http.StatusNoContent && m.dropNext.CompareAndSwap(true, false) {
		m.dropped.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func TestMetadataProcessCrashAndAmbiguousCommit(t *testing.T) {
	f := newObjectFixture(t)
	attachMetadata(t, f)
	c := newClusterWithObjects(t, threeReplicas, f)
	c.replaceAllowlist(c.replicas[0], "before-metadata-crash")
	f.metadata.dropNext.Store(true)
	if code, body := c.put(c.replicas[1], "/allowlist", allowlistDocument("lost-reply-committed")); code != http.StatusNoContent {
		t.Fatalf("lost reply: HTTP %d %s", code, body)
	}
	if f.metadata.dropped.Load() != 1 {
		t.Fatal("did not drop a committed response")
	}
	c.waitFor("committed policy on all replicas", time.Minute, func() bool { return c.allServe("lost-reply-committed") })
	before := f.metadata.stats()
	if before.Commits == 0 {
		t.Fatal("metadata did not commit")
	}
	f.metadata.process.kill()
	for _, r := range c.replicas {
		if code, _ := c.get(r, "/allowlist"); code != http.StatusServiceUnavailable {
			t.Fatalf("served without metadata authority: %d", code)
		}
	}
	f.metadata.restart()
	c.waitServing(time.Minute)
	if !c.allServe("lost-reply-committed") {
		t.Fatal("metadata restart lost acknowledged policy")
	}
	// A cold CDS recovery must use the persisted metadata and immutable objects.
	for _, r := range c.replicas {
		c.kill(r)
	}
	for _, r := range c.replicas {
		c.restart(r)
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	if !c.allServe("lost-reply-committed") {
		t.Fatal("cold replay lost acknowledged policy")
	}
	// With a current metadata head and a fully applied replica, an immutable
	// object outage need not prevent reads. It must prevent new state commits.
	f.outage.Store(true)
	if code, _ := c.put(c.replicas[0], "/allowlist", allowlistDocument("must-not-commit")); code != http.StatusServiceUnavailable {
		t.Fatalf("acknowledged write without durable object: HTTP %d", code)
	}
	if !c.allServe("lost-reply-committed") {
		t.Fatal("object outage changed committed policy or prevented an already-current read")
	}
	f.outage.Store(false)
	c.replaceAllowlist(c.replicas[1], "objects-recovered")
	for i := range f.shards {
		shard := &f.shards[i]
		shard.mu.Lock()
		_, hasHead := shard.objects["/pilot/integration/head"]
		shard.mu.Unlock()
		if hasHead {
			t.Fatal("third arm also published an object-store head")
		}
	}
	t.Log("lost commit response recovered; metadata process crash failed closed; durable restart and cold CDS replay preserved state")
}
