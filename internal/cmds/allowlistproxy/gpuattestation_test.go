package allowlistproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func TestGPUReadDialsOnlyTheFixedWorkerRoute(t *testing.T) {
	const route = workloadclaims.GPUAttestationPrefix + "10.12.0.3"
	const body = `{"status":"no_gpu","boot_id":"9f4b6a6a-cbaa-44f5-9f8a-a6b26e4f452c"}`
	calls := 0
	ta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.RequestURI() != route || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected worker request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Write([]byte(body))
	}))
	defer ta.Close()
	target, err := url.Parse(ta.URL)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+workloadclaims.GPUAttestationPrefix+"{host}", relayWorkerEvidence(target, ta.Client()))
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", route + "?unused=true", 200},
		{"GET", workloadclaims.GPUAttestationPrefix + "localhost", 400},
		{"POST", route, 405},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("Authorization", "customer")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status || w.Code == 200 && w.Body.String() != body {
			t.Fatalf("%s %s: got %d, %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("relayed %d requests", calls)
	}
}
