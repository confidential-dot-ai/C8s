package metadatapilot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func fleetRequest(f *Fleet, cfg ClusterConfig, method, body, etag string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://metadata"+HeadPath, strings.NewReader(body))
	r.Header.Set("X-CDS-Namespace", cfg.Namespace)
	r.Header.Set("Authorization", "Bearer "+cfg.Token)
	if method == http.MethodPut {
		if etag == "" {
			r.Header.Set("If-None-Match", "*")
		} else {
			r.Header.Set("If-Match", etag)
		}
	}
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	return w
}

func TestFleetBackpressureIsolationAndAcknowledgedStateSurvivesRestart(t *testing.T) {
	const clusters = 16
	configs := make([]ClusterConfig, clusters)
	for i := range configs {
		configs[i] = ClusterConfig{Namespace: "cluster-" + strconv.Itoa(i), Token: fmt.Sprintf("synthetic-separate-cluster-token-%04d", i)}
	}
	directory := t.TempDir()
	f, err := OpenFleet(directory, configs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	noisy := f.clusters[configs[0].Namespace]
	// Occupy this cluster's database connection, simulating a slow storage
	// operation. Its actor and all admitted requests must wait; other clusters
	// use independent databases and mailboxes.
	held, err := noisy.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var flood sync.WaitGroup
	for range Capacity {
		flood.Go(func() {
			r := httptest.NewRequestWithContext(ctx, "GET", "https://metadata"+HeadPath, nil)
			r.Header.Set("X-CDS-Namespace", configs[0].Namespace)
			r.Header.Set("Authorization", "Bearer "+configs[0].Token)
			f.ServeHTTP(httptest.NewRecorder(), r)
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for noisy.Stats().Admitted != Capacity {
		if time.Now().After(deadline) {
			t.Fatal("noisy cluster did not fill its budget")
		}
		time.Sleep(time.Millisecond)
	}
	if w := fleetRequest(f, configs[0], "GET", "", ""); w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("noisy cluster did not apply backpressure: HTTP %d", w.Code)
	}
	wrong := configs[1]
	wrong.Token = configs[0].Token
	if w := fleetRequest(f, wrong, "PUT", "cross-cluster", ""); w.Code != 401 {
		t.Fatalf("cross-cluster credential: HTTP %d", w.Code)
	}
	unknown := configs[0]
	unknown.Namespace = "../../unconfigured"
	if w := fleetRequest(f, unknown, "PUT", "forged", ""); w.Code != 401 {
		t.Fatalf("unknown namespace: HTTP %d", w.Code)
	}
	etags := make([]string, clusters)
	var writes sync.WaitGroup
	for i := 1; i < clusters; i++ {
		i := i
		writes.Go(func() {
			w := fleetRequest(f, configs[i], "PUT", "encrypted-head-"+configs[i].Namespace, "")
			if w.Code != 204 {
				t.Errorf("cluster %d blocked by noisy neighbor: HTTP %d", i, w.Code)
				return
			}
			etags[i] = w.Header().Get("ETag")
		})
	}
	writes.Wait()
	if noisy.Stats().Admitted != Capacity {
		t.Fatal("other clusters only progressed after noisy requests escaped")
	}
	cancel()
	flood.Wait()
	_ = held.Close()
	f.Close()
	reopened, err := OpenFleet(directory, configs)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for i := 1; i < clusters; i++ {
		w := fleetRequest(reopened, configs[i], "GET", "", "")
		if w.Code != 200 || w.Header().Get("ETag") != etags[i] || w.Body.String() != "encrypted-head-"+configs[i].Namespace {
			t.Fatalf("cluster %d lost or crossed acknowledged state: HTTP %d", i, w.Code)
		}
		if w := fleetRequest(reopened, configs[i], "PUT", "stale publication", ""); w.Code != 412 {
			t.Fatalf("restart lost conditional publication history: HTTP %d", w.Code)
		}
	}
}

func TestFleetRejectsSharedCredentialsAndUnboundedConfiguration(t *testing.T) {
	for _, configs := range [][]ClusterConfig{
		nil,
		make([]ClusterConfig, MaxClusters+1),
		{{Namespace: "a", Token: testToken}, {Namespace: "b", Token: testToken}},
		{{Namespace: "a", Token: testToken}, {Namespace: "a", Token: testToken + "2"}},
	} {
		if f, err := OpenFleet(t.TempDir(), configs); err == nil {
			f.Close()
			t.Fatal("accepted invalid fleet")
		}
	}
}
