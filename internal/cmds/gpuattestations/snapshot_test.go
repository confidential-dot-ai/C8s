package gpuattestations

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestSlowWorkersCannotStarveTheNextWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes := []string{listedNode("n-2-0-0-1", "2.0.0.1")}
		for i := range 3 * concurrentReads {
			nodes = append(nodes, listedNode(fmt.Sprintf("n-1-0-0-%d", i), fmt.Sprintf("1.0.0.%d", i)))
		}
		api := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"items":[` + strings.Join(nodes, ",") + `]}`))}, nil
		})}
		relay := &http.Client{Timeout: workerTimeout, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() == relayURL+"2.0.0.1" && r.Context().Err() == nil {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(noGPU(boot1)))}, nil
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		c := &collector{nodesURL: "https://kubernetes/api/v1/nodes", api: api, relay: relay}
		get := func() string {
			w := httptest.NewRecorder()
			c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, publicPath, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("GET returned %d", w.Code)
			}
			last, err := http.ParseTime(w.Header().Get("Last-Modified"))
			if err != nil || !last.Equal(c.snapshot.Load().refreshed.Truncate(time.Second)) {
				t.Fatalf("Last-Modified %v, %v", last, err)
			}
			return w.Body.String()
		}
		sweep := func() {
			start := time.Now()
			c.refresh(t.Context())
			if time.Since(start) > sweepTimeout {
				t.Fatal("sweep exceeded its deadline")
			}
		}
		for range 3 {
			sweep()
			if strings.Contains(get(), boot1) {
				t.Fatal("slow workers did not fill the sweep")
			}
		}
		sweep()
		if !strings.Contains(get(), boot1) {
			t.Fatal("healthy worker starved")
		}
		first := c.snapshot.Load().entries["n-2-0-0-1"].expires
		sweep()
		if !strings.Contains(get(), boot1) || c.snapshot.Load().entries["n-2-0-0-1"].expires != first {
			t.Fatal("unattempted worker did not retain original observation")
		}
		time.Sleep(time.Until(first))
		if strings.Contains(get(), boot1) {
			t.Fatal("expired evidence served between sweeps")
		}
	})
}

func TestDiscoveryAndSnapshotFailureReasons(t *testing.T) {
	const name = "n-10-0-0-1"
	response := "invalid JSON"
	c := &collector{nodesURL: "https://kubernetes/api/v1/nodes", api: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}}
	check := func(reason string) {
		t.Helper()
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, publicPath, nil))
		if w.Code != 503 || strings.TrimSpace(w.Body.String()) != reason {
			t.Fatalf("response %d %s", w.Code, w.Body)
		}
	}
	check("worker inventory is initializing")
	c.refresh(t.Context())
	check("worker discovery failed")
	response = `{"metadata":{"continue":"next"},"items":[]}`
	c.refresh(t.Context())
	check("worker inventory exceeds discovery limits")
	response = `{"items":[` + listedNode(name, "10.0.0.1") + `]}`
	c.snapshot.Store(&snapshot{entries: map[string]*entry{name: {
		slot:        slot{address: netip.MustParseAddr("10.0.0.1")},
		observation: observation{expires: time.Now().Add(observationTTL), body: make([]byte, maxSnapshot)},
	}}})
	c.refresh(t.Context())
	check("worker evidence exceeds snapshot limit")
}

func TestUnattemptedReplacementsLoseOldEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const name = "n-2-0-0-1"
		nodes := []string{strings.Replace(listedNode(name, "2.0.0.1"), `"metadata":{`, `"metadata":{"uid":"new",`, 1)}
		for i := range concurrentReads {
			nodes = append(nodes, listedNode(fmt.Sprintf("n-1-0-0-%d", i), fmt.Sprintf("1.0.0.%d", i)))
		}
		c := &collector{nodesURL: "https://kubernetes/api/v1/nodes", api: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"items":[` + strings.Join(nodes, ",") + `]}`))}, nil
		})}, relay: &http.Client{Timeout: workerTimeout, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() == relayURL+"2.0.0.1" {
				t.Error("replacement should await next sweep")
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}}
		c.snapshot.Store(&snapshot{entries: map[string]*entry{name: {
			slot:        slot{address: netip.MustParseAddr("2.0.0.1"), uid: "old"},
			observation: observation{expires: time.Now().Add(observationTTL), bootID: boot1, body: []byte(noGPU(boot1))},
		}}})
		c.refresh(t.Context())
		if e := c.snapshot.Load().entries[name]; e.uid != "new" || len(e.body) != 0 {
			t.Fatal("replacement inherited old evidence")
		}
	})
}
