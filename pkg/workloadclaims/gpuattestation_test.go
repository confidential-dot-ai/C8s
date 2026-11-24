package workloadclaims

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGPUCacheBelongsToTheStagedWorker(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "kubelet.env")
	record := filepath.Join(dir, "gpu-attestation.json")
	if err := os.WriteFile(env, []byte("NODE_NAME=n-10-3-1-10\nNODE_IP=10.3.1.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+GPUAttestationPrefix+"{host}", serveGPUAttestation(record, env))
	read := func(host string, want int, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", GPUAttestationPrefix+host, nil))
		if w.Code != want || want == 200 && w.Body.String() != body {
			t.Fatalf("%s: HTTP %d: %q", host, w.Code, w.Body.String())
		}
	}
	read("10.3.1.10", 503, "")
	body := `{"status":"no_gpu","boot_id":"efbe0594-08f0-47bb-a837-dd96ddada42e"}`
	if err := os.WriteFile(record, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	read("10.3.1.10", 200, body)
	read("10.3.1.1", 404, "")
	read("localhost", 400, "")
	if err := os.Truncate(record, MaxGPUAttestationBytes+1); err != nil {
		t.Fatal(err)
	}
	read("10.3.1.10", 503, "")
}
