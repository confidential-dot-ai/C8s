package cdsattest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

func getPublication(t *testing.T, srv *Server) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + routes.PublicationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestE4RoutePublication(t *testing.T) {
	state := routing.NewState(routing.StateConfig{MeshCAs: noMeshCAs})
	newServer := func(publish, attestOff bool) *Server {
		return NewServer(Config{Routes: testRouter{State: state, backendFunc: echoBackend}, PublishRoutes: publish, DisableAttestEndpoints: attestOff})
	}

	resp, _ := getPublication(t, newServer(true, false))
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("before the first apply = %d, Cache-Control %q, want 404 no-store", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}

	env, keys := signManifest(t, testManifest)
	if _, err := state.Accept(env, keys); err != nil {
		t.Fatal(err)
	}
	resp, body := getPublication(t, newServer(true, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after apply = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	// The CDS serves GET /routes as json.Marshal of the stored envelope.
	want, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("published envelope = %s, want the CDS envelope %s", body, want)
	}
	var got routes.Envelope
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if _, err := routes.VerifySigned(got, keys, nil); err != nil {
		t.Fatalf("published envelope does not verify: %v", err)
	}

	for _, tc := range []struct {
		name               string
		publish, attestOff bool
	}{
		{name: "publication disabled", publish: false},
		{name: "attest endpoints disabled", publish: true, attestOff: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if resp, _ := getPublication(t, newServer(tc.publish, tc.attestOff)); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404", routes.PublicationPath, resp.StatusCode)
			}
		})
	}
}

func TestPublishRoutesFlagDefaultsOff(t *testing.T) {
	f := NewCmd().Flags().Lookup("publish-routes")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("--publish-routes = %+v, want a flag defaulting to false", f)
	}
}
