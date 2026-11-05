//go:build integration && linux

package cdsha_test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

// One TLS object endpoint, with an immutable prefix-to-fixture routing table.
// Each history has its own encryption key, prefix and existing sharded fixture.
// This is a latency/correctness fixture, not a storage durability or IAM test.
func scaleObjectFixtures(t *testing.T, count int) []*objectFixture {
	t.Helper()
	fixtures := make([]*objectFixture, count)
	byPrefix := make(map[string]*objectFixture, count)
	for i := range fixtures {
		f := &objectFixture{}
		for j := range f.shards {
			f.shards[j].objects = make(map[string]objectwal.Object)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(key)
		f.config = cdsconfig.ObjectWALPilot{Bucket: "pilot", Region: "us-east-2", Prefix: fmt.Sprintf("scale-%d", i), PathStyle: true, KeySHA256: hex.EncodeToString(h[:])}
		f.config.AtomicOperatorWrites = atomicOperatorWritesEnabled()
		f.provision = jsonBody(t, cdsobject.Provision{Key: key, Credentials: objectwal.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "test-only"}})
		fixtures[i], byPrefix[f.config.Prefix] = f, f
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ok := strings.CutPrefix(r.URL.Path, "/pilot/")
		prefix, _, _ := strings.Cut(path, "/")
		if f := byPrefix[prefix]; ok && f != nil {
			f.serve(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "objects.pem")
	write(t, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	for _, f := range fixtures {
		f.certificate, f.config.Endpoint, f.client = cert, server.URL, server.Client()
	}
	return fixtures
}

// The metadata comparison shares ONE service process across every cluster.
// Its existing Fleet owns separate actors, credentials, budgets and SQLite
// files. The shared CPU/disk and the lack of replicated metadata HA are explicit.
func scaleMetadataFleet(t *testing.T, fixtures []*objectFixture) {
	t.Helper()
	dir := t.TempDir()
	owner := &cluster{t: t}
	byNamespace := make(map[string]*metadataFixture, len(fixtures))
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := byNamespace[r.Header.Get("X-CDS-Namespace")]; m != nil {
			m.serve(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(proxy.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	private, err := x509.MarshalPKCS8PrivateKey(proxy.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "key.pem")
	write(t, certFile, cert)
	write(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	var configs []map[string]string
	port := freePort(t)
	for i, f := range fixtures {
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			t.Fatal(err)
		}
		m := &metadataFixture{owner: owner, client: proxy.Client(), endpoint: proxy.URL,
			upstream: fmt.Sprintf("https://127.0.0.1:%d", port), namespace: f.config.Prefix, token: hex.EncodeToString(token[:])}
		m.client.Timeout = 7 * time.Second
		tokenFile := filepath.Join(dir, fmt.Sprintf("token-%d", i))
		write(t, tokenFile, []byte(m.token))
		if err := os.Chmod(tokenFile, 0600); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, map[string]string{"namespace": m.namespace, "token_file": tokenFile})
		roots, err := os.ReadFile(f.certificate)
		if err != nil {
			t.Fatal(err)
		}
		f.certificate = filepath.Join(dir, fmt.Sprintf("roots-%d.pem", i))
		write(t, f.certificate, append(roots, cert...))
		f.config.MetadataEndpoint = proxy.URL
		var provision cdsobject.Provision
		if err := json.Unmarshal(f.provision, &provision); err != nil {
			t.Fatal(err)
		}
		provision.MetadataToken = m.token
		f.provision = jsonBody(t, provision)
		f.metadata, byNamespace[m.namespace] = m, m
	}
	manifest := filepath.Join(dir, "clusters.json")
	write(t, manifest, jsonBody(t, configs))
	if err := os.Chmod(manifest, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--listen", fmt.Sprintf("127.0.0.1:%d", port), "--clusters-file", manifest, "--db-dir", filepath.Join(dir, "db"), "--tls-cert", certFile, "--tls-key", keyFile}
	process := owner.run("metadata-fleet", built.metadata, args, nil)
	for _, f := range fixtures {
		m := f.metadata
		m.args, m.process = args, process
		owner.waitFor("metadata fleet namespace", 10*time.Second, func() bool {
			r, err := m.request(m.upstream, "/v1/stats")
			if err != nil {
				return false
			}
			defer r.Body.Close()
			return r.StatusCode == http.StatusOK
		})
	}
}
