package allowlist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// newOperatorKeypair writes an operator EC private key to dir and returns its
// path plus the matching public key (what CDS would pin).
func newOperatorKeypair(t *testing.T, dir, name string) (keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPath = filepath.Join(dir, name)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath, &key.PublicKey
}

// fakeCDS serves the allowlist HTTP contract over an in-memory allowlist, gated
// by the real operatorauth.Verifier (so the body-bound token path is exercised
// end to end). It stands in for CDS's handler, which lives in a package being
// rewritten concurrently on this branch.
type fakeCDS struct {
	mu       sync.Mutex
	al       pkgallowlist.Allowlist
	version  int
	verifier operatorauth.Verifier
}

func newFakeCDS(pinned []*ecdsa.PublicKey) *fakeCDS {
	return &fakeCDS{
		al: pkgallowlist.Allowlist{
			Schema:    pkgallowlist.Schema,
			Workloads: map[string]pkgallowlist.Workload{},
		},
		version:  1,
		verifier: operatorauth.Verifier{Keys: pinned, ClockSkew: 30 * time.Second},
	}
}

func (f *fakeCDS) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /allowlist", f.handleList)
	mux.HandleFunc("PUT /allowlist", f.handleReplace)
	mux.HandleFunc("PUT /allowlist/workloads/{name}", f.handlePutWorkload)
	mux.HandleFunc("DELETE /allowlist/workloads/{name}", f.handleDeleteWorkload)
	return mux
}

func (f *fakeCDS) handleList(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	body, err := f.al.Canonical()
	version := f.version
	f.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `W/"`+strconv.Itoa(version)+`"`)
	w.Write(body)
}

func (f *fakeCDS) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, _ := io.ReadAll(r.Body)
	if err := f.verifier.Authorize(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

func (f *fakeCDS) handleReplace(w http.ResponseWriter, r *http.Request) {
	body, ok := f.authorize(w, r)
	if !ok {
		return
	}
	parsed, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	f.mu.Lock()
	f.al = *parsed
	if f.al.Workloads == nil {
		f.al.Workloads = map[string]pkgallowlist.Workload{}
	}
	f.version++
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCDS) handlePutWorkload(w http.ResponseWriter, r *http.Request) {
	body, ok := f.authorize(w, r)
	if !ok {
		return
	}
	wl, err := pkgallowlist.ParseWorkloadJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	f.mu.Lock()
	f.al.Workloads[r.PathValue("name")] = *wl
	f.version++
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCDS) handleDeleteWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.authorize(w, r); !ok {
		return
	}
	name := r.PathValue("name")
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.al.Workloads[name]; !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	delete(f.al.Workloads, name)
	f.version++
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCDS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.al.Workloads)
}

func (f *fakeCDS) workload(name string) (pkgallowlist.Workload, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	wl, ok := f.al.Workloads[name]
	return wl, ok
}

func (f *fakeCDS) seedWorkload(name string, w pkgallowlist.Workload) {
	f.mu.Lock()
	f.al.Workloads[name] = w
	f.mu.Unlock()
}

// cdsTestServer wires the fake CDS behind an httptest server.
func cdsTestServer(t *testing.T, pinned []*ecdsa.PublicKey) (*httptest.Server, *fakeCDS) {
	t.Helper()
	f := newFakeCDS(pinned)
	srv := httptest.NewServer(f.mux())
	t.Cleanup(srv.Close)
	return srv, f
}

// TestUploadEndToEndWithPinnedKey drives the real CLI against the fake CDS +
// real verifier. It proves the operator token the client mints is accepted
// (signature under the pinned key + body binding) and the replace lands.
func TestUploadEndToEndWithPinnedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})

	images := coreImages()
	file := writeAllowlistFile(t, dir, images)

	if _, _, err := runCmd("upload", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if got := cds.count(); got != len(images) {
		t.Fatalf("store has %d entries after upload, want %d", got, len(images))
	}
}

// TestUploadRejectedWhenKeyNotPinned proves the auth boundary: an operator key
// whose public half CDS has not pinned is rejected, and the store is untouched.
func TestUploadRejectedWhenKeyNotPinned(t *testing.T) {
	dir := t.TempDir()
	_, pinnedPub := newOperatorKeypair(t, dir, "pinned.key") // pinned on CDS
	unpinnedKeyPath, _ := newOperatorKeypair(t, dir, "unpinned.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pinnedPub})

	file := writeAllowlistFile(t, dir, coreImages())
	if _, _, err := runCmd("upload", file, "--url", srv.URL, "--insecure", "--operator-key", unpinnedKeyPath); err == nil {
		t.Fatal("expected upload with an unpinned operator key to be rejected")
	}
	if got := cds.count(); got != 0 {
		t.Fatalf("store mutated despite rejected auth: %d entries", got)
	}
}

// TestWorkloadApplyGetRoundTrip drives the real CLI through the fake CDS +
// verifier: apply a workload entry, then read it back via 'workload get'
// and from the store. PutWorkload's body binding is the fragile path.
func TestWorkloadApplyGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})

	entry := map[string]any{
		"api": map[string]any{
			"containers": []map[string]any{{
				"digest":  digA,
				"image":   "registry.example.com/team/api@" + digA,
				"command": map[string]any{"policy": "exact", "argv": []string{"/app/server"}},
				"args":    map[string]any{"policy": "exact", "argv": []string{"--port=8080"}},
			}},
		},
	}
	data, _ := json.Marshal(entry)
	file := filepath.Join(dir, "entry.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("workload apply failed: %v", err)
	}

	wl, ok := cds.workload("api")
	if !ok {
		t.Fatal("workload 'api' not stored")
	}
	if len(wl.Containers) != 1 || wl.Containers[0].Digest.String() != digA {
		t.Fatalf("stored workload has unexpected containers: %#v", wl.Containers)
	}
	if wl.Containers[0].Command.Policy != "exact" {
		t.Fatalf("command policy = %q, want exact", wl.Containers[0].Command.Policy)
	}

	out, _, err := runCmd("get", "api", "--url", srv.URL, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("workload get failed: %v", err)
	}
	if !strings.Contains(out, digA) || !strings.Contains(out, "/app/server") {
		t.Fatalf("get output missing expected content:\n%s", out)
	}
}

// TestWorkloadDeleteRoundTrip proves delete removes an entry and 404s for an
// absent one.
func TestWorkloadDeleteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})

	cds.seedWorkload("api", pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digA)}},
	})

	if _, _, err := runCmd("delete", "api", "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, ok := cds.workload("api"); ok {
		t.Fatal("workload 'api' still present after delete")
	}
	if _, _, err := runCmd("delete", "missing", "--url", srv.URL, "--insecure", "--operator-key", keyPath); err == nil {
		t.Fatal("expected delete of an absent workload to fail (404)")
	}
}

func TestNodeRootExecutableWritesRemainAuthorized(t *testing.T) {
	for _, command := range []string{"upload", "apply"} {
		for _, mode := range []string{"node-root", "path only", "unpinned operator key"} {
			t.Run(command+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				key, pub := newOperatorKeypair(t, dir, "operator.key")
				srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
				if mode == "unpinned operator key" {
					key, _ = newOperatorKeypair(t, dir, "untrusted.key")
				}
				kind := "nodeRootFile"
				if mode == "path only" {
					kind = "host"
				}
				entries := `{"worker":{"containers":[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"env":{"policy":"exact","values":{"PATH":"/usr/bin:/bin"}},"mounts":{"policy":"exact","rules":[{"destination":"/usr/bin/nvidia-smi","kind":"` + kind + `","source":"/usr/bin/nvidia-smi","readOnly":true}]}}]}}`
				body := entries
				if command == "upload" {
					body = `{"schema":"c8s.allowlist/v1","workloads":` + entries + `}`
				}
				file := writeFile(t, "worker.json", body)
				args := []string{command, file, "--url", srv.URL, "--insecure", "--operator-key", key}
				if command == "upload" {
					// Missing components only; lint still applies.
					args = append(args, "--force")
				}
				_, _, err := runCmd(args...)
				if mode != "node-root" {
					if err == nil || cds.count() != 0 {
						t.Fatalf("unsafe or unauthorized policy written: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("node-root %s: %v", command, err)
				}
				worker, ok := cds.workload("worker")
				if !ok || worker.Containers[0].Mounts.Rules[0].Kind != pkgallowlist.MountNodeRootFile {
					t.Fatal("lost the nodeRootFile kind on the signed write path")
				}
			})
		}
	}
}
