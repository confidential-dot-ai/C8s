//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

// This fixture checks the real SDK, TLS, process bootstrap and HTTP serving
// path. It is a local conditional-object server, not an AWS performance model.
type objectFixture struct {
	config      cdsconfig.ObjectWALPilot
	certificate string
	provision   []byte
	outage      atomic.Bool
	delayNS     atomic.Int64
	shards      [32]objectShard
	version     atomic.Uint64
	metadata    *metadataFixture
	gets        atomic.Uint64
	puts        atomic.Uint64
	recovery    *recoveryFixture
	client      *http.Client // TLS client pinned to this local object's fixture CA.
}

type objectShard struct {
	mu      sync.Mutex
	objects map[string]objectwal.Object
}

func (f *objectFixture) setAuthorityOutage(outage bool) {
	if f.metadata != nil {
		f.metadata.outage.Store(outage)
	} else {
		f.outage.Store(outage)
	}
}

func (f *objectFixture) shard(key string) *objectShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &f.shards[h.Sum32()%uint32(len(f.shards))]
}

func newObjectFixture(t *testing.T) *objectFixture {
	t.Helper()
	f := &objectFixture{}
	for i := range f.shards {
		f.shards[i].objects = map[string]objectwal.Object{}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.client = server.Client()
	t.Cleanup(server.Close)
	f.certificate = filepath.Join(t.TempDir(), "object-server.pem")
	write(t, f.certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	key := bytes.Repeat([]byte{7}, 32)
	hash := sha256.Sum256(key)
	f.config = cdsconfig.ObjectWALPilot{Bucket: "pilot", Region: "us-east-2", Prefix: "integration", Endpoint: server.URL, PathStyle: true, KeySHA256: hex.EncodeToString(hash[:])}
	var err error
	f.provision, err = json.Marshal(cdsobject.Provision{Key: key, Credentials: objectwal.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "test-only"}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *objectFixture) serve(w http.ResponseWriter, r *http.Request) {
	if delay := time.Duration(f.delayNS.Load()); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	if f.outage.Load() {
		http.Error(w, "injected outage", http.StatusServiceUnavailable)
		return
	}
	shard := f.shard(r.URL.Path)
	switch r.Method {
	case http.MethodGet:
		f.gets.Add(1)
		shard.mu.Lock()
		old, exists := shard.objects[r.URL.Path]
		shard.mu.Unlock()
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		w.Header().Set("ETag", old.ETag)
		_, _ = w.Write(old.Data)
	case http.MethodPut:
		f.puts.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, objectwal.MaxObjectBytes+1))
		if err != nil || len(body) > objectwal.MaxObjectBytes {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		shard.mu.Lock()
		old, exists := shard.objects[r.URL.Path]
		if (r.Header.Get("If-None-Match") == "*" && exists) || (r.Header.Get("If-Match") != "" && (!exists || r.Header.Get("If-Match") != old.ETag)) {
			shard.mu.Unlock()
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
			return
		}
		if r.Header.Get("If-None-Match") == "" && r.Header.Get("If-Match") == "" {
			shard.mu.Unlock()
			http.Error(w, "conditional write required", http.StatusBadRequest)
			return
		}
		etag := fmt.Sprintf(`"%d"`, f.version.Add(1))
		shard.objects[r.URL.Path] = objectwal.Object{Data: body, ETag: etag}
		shard.mu.Unlock()
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *cluster) provisionObjects(r *replica) {
	c.t.Helper()
	c.awaitStatus(r)
	payload := c.objectWAL.provision
	if f := c.objectWAL.recovery; f != nil {
		if f.authority == nil {
			c.t.Fatal("authority must restore existing registration before recovery")
		}
		grant, err := f.authority.Release(c.t.Context(), r.base)
		if err != nil {
			c.t.Fatal(err)
		}
		payload = f.payload(c, grant)
		f.last[r.index] = payload
	}
	code, _ := c.send(r, http.MethodPost, "/ha/object-wal/provision", payload, nil)
	if code != http.StatusNoContent {
		c.t.Fatalf("attested provisioning returned HTTP %d", code)
	}
}

// Both backends run the same binary, process count, signed policy workload and
// client. Timings are diagnostic; no local timing is an AWS latency claim.
func TestStorageBackendParity(t *testing.T) {
	for _, backend := range []string{"raft", "object-wal", "transactional-metadata"} {
		t.Run(backend, func(t *testing.T) {
			var objects *objectFixture
			if backend != "raft" {
				objects = newObjectFixture(t)
				if backend == "transactional-metadata" {
					attachMetadata(t, objects)
				}
			}
			c := newClusterWithObjects(t, threeReplicas, objects)
			ca := c.servedCA(c.replicas[0])
			// This also waits out the startup operator-token floor in both arms.
			c.replaceAllowlist(c.replicas[0], "pilot-warmup")
			var latencies []time.Duration
			for i := range 12 {
				start := time.Now()
				code, body := c.put(c.replicas[i%3], "/allowlist", allowlistDocument(fmt.Sprintf("pilot-%d", i)))
				latencies = append(latencies, time.Since(start))
				if code != http.StatusNoContent {
					t.Fatalf("write %d: HTTP %d %s", i, code, body)
				}
			}
			c.waitFor("every replica to expose the last acknowledged write", 30*time.Second, func() bool { return c.allServe("pilot-11") })
			slices.Sort(latencies)
			t.Logf("%s local policy writes: n=%d p50=%s p95=%s (loopback fixture, not cloud performance)", backend, len(latencies), latencies[5], latencies[11])
			for _, r := range c.replicas {
				if c.servedCA(r) != ca {
					t.Fatal("CA diverged")
				}
			}
		})
	}
}

func TestObjectWALWholeClusterRestartAndOutage(t *testing.T) {
	objects := newObjectFixture(t)
	c := newClusterWithObjects(t, threeReplicas, objects)
	ca := c.servedCA(c.replicas[0])
	c.replaceAllowlist(c.replicas[1], "survives-total-process-loss")
	for _, r := range c.replicas {
		c.kill(r)
	}
	for _, r := range c.replicas {
		c.restart(r)
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	if !c.allServe("survives-total-process-loss") {
		t.Fatal("restart lost acknowledged policy")
	}
	for _, r := range c.replicas {
		if c.servedCA(r) != ca {
			t.Fatal("restart replaced the mesh CA")
		}
	}

	objects.outage.Store(true)
	for _, r := range c.replicas {
		for _, path := range []string{"/ca", "/allowlist", "/measurements"} {
			if code, _ := c.get(r, path); code != http.StatusServiceUnavailable {
				t.Fatalf("served %s during storage outage: %d", path, code)
			}
		}
	}
	objects.outage.Store(false)
	c.waitServing(30 * time.Second)
	if !c.allServe("survives-total-process-loss") {
		t.Fatal("outage recovery lost policy")
	}
	for i := range objects.shards {
		shard := &objects.shards[i]
		shard.mu.Lock()
		for key, obj := range shard.objects {
			if strings.Contains(string(obj.Data), "survives-total-process-loss") || strings.Contains(string(obj.Data), "BEGIN PRIVATE KEY") {
				shard.mu.Unlock()
				t.Fatalf("plaintext persisted at %s", key)
			}
		}
		shard.mu.Unlock()
	}
}
