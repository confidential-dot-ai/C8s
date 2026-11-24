package gpuattestations

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func listedNode(name, address string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q},"status":{"addresses":[{"type":"InternalIP","address":%q}]}}`, name, address)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestWorkerSnapshot(t *testing.T) {
	list := `{"items":[` + strings.Join([]string{
		listedNode("n-10-0-0-5", "10.0.0.5"),
		listedNode("n-10-0-0-4", "invalid"),
		listedNode("n-10-0-0-3", "10.0.0.3"),
		listedNode("n-10-0-0-2", "10.0.0.2"),
		listedNode("n-10-0-0-1", "10.0.0.1"),
		listedNode("control-plane", "10.0.0.6"),
		listedNode("n-10.0.0.6", "10.0.0.6"),
	}, ",") + `]}`
	api := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/nodes" {
			t.Errorf("discovery path %q", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(list))}, nil
	})}
	node2 := noGPU(boot2)
	node1 := withGPU(boot1, "snp", cpuFixture(t, "snp-evidence-genoa"))
	var calls atomic.Int32
	client := &http.Client{CheckRedirect: refuseRedirect, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		w := httptest.NewRecorder()
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %q", r.Method)
		}
		switch r.URL.String() {
		case relayURL + "10.0.0.1":
			fmt.Fprint(w, node1)
		case relayURL + "10.0.0.2":
			fmt.Fprint(w, node2)
		case relayURL + "10.0.0.3":
			http.Redirect(w, r, "http://another.example", http.StatusFound)
		case relayURL + "10.0.0.5":
			fmt.Fprint(w, noGPU("50000000-0000-4000-8000-000000000005"), strings.Repeat(" ", 2<<20))
		default:
			t.Errorf("unexpected relay request %s", r.URL)
		}
		return w.Result(), nil
	})}
	c := &collector{nodesURL: "https://kubernetes/api/v1/nodes", api: api, relay: client}
	get := func(status int) []worker {
		t.Helper()
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, publicPath, nil))
		if w.Code != status {
			t.Fatalf("status = %d, want %d: %s", w.Code, status, w.Body.String())
		}
		if status != http.StatusOK {
			return nil
		}
		var result struct {
			Workers []worker `json:"workers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Workers == nil {
			t.Fatalf("workers: %v, %s", err, w.Body.String())
		}
		return result.Workers
	}
	get(http.StatusServiceUnavailable)
	c.refresh(t.Context())
	got := get(http.StatusOK)
	if len(got) != 5 {
		t.Fatalf("workers: %+v", got)
	}
	for i, status := range []string{"attested", "no_gpu", "unavailable", "unavailable", "unavailable"} {
		if got[i].Status != status || got[i].Name != fmt.Sprintf("n-10-0-0-%d", i+1) {
			t.Fatalf("worker %d: %+v", i, got[i])
		}
	}
	if string(got[0].NVIDIAGPU) != bundle || got[0].Nonce != nonce || string(got[0].Collateral) != `{"cert":"def"}` {
		t.Fatal("original evidence missing")
	}
	get(http.StatusOK)
	if calls.Load() != 4 {
		t.Fatalf("relay calls %d", calls.Load())
	}
	node2 = noGPU(boot1)
	c.refresh(t.Context())
	for _, w := range get(http.StatusOK) {
		if w.Status != "unavailable" || w.BootID != "" {
			t.Fatalf("duplicate boot published: %+v", w)
		}
	}
	node2 = noGPU("30000000-0000-4000-8000-000000000003")
	c.refresh(t.Context())
	if next := get(http.StatusOK)[1]; next.BootID == boot1 || next.BootID == boot2 || next.Status != "no_gpu" {
		t.Fatalf("reboot: %+v", next)
	}
	node2 = "{}"
	c.refresh(t.Context())
	if got := get(http.StatusOK)[1]; got.Status != "unavailable" || got.BootID != "" {
		t.Fatalf("failed read retained evidence: %+v", got)
	}
	for _, bad := range []string{`{"metadata":{"continue":"token"},"items":[]}`, `{}`, `invalid`} {
		list = bad
		c.refresh(t.Context())
		get(http.StatusServiceUnavailable)
	}
	list = `{"items":[]}`
	c.refresh(t.Context())
	if len(get(http.StatusOK)) != 0 {
		t.Fatal("departed workers retained")
	}
}

func TestExactRoute(t *testing.T) {
	c := &collector{}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"HEAD", publicPath, 405}, {"GET", publicPath + "/", 404}, {"GET", "/another", 404},
	} {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
}
