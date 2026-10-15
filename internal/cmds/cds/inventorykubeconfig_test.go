package cds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInventoryExplicitKubeconfigFailsClosed(t *testing.T) {
	if _, err := buildInventoryHosts(t.Context(), nil, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing kubeconfig silently fell back to empty inventory")
	}
}

func TestInventoryUsesHostKubeconfig(t *testing.T) {
	previous := nodeCacheSyncTimeout
	nodeCacheSyncTimeout = 3 * time.Second
	t.Cleanup(func() { nodeCacheSyncTimeout = previous })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			w.WriteHeader(http.StatusOK)
			if r.URL.Query().Get("sendInitialEvents") == "true" {
				_, _ = fmt.Fprintln(w, `{"type":"ADDED","object":{"apiVersion":"v1","kind":"Node","metadata":{"name":"leader","resourceVersion":"1"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.10"}]}}}`)
				_, _ = fmt.Fprintln(w, `{"type":"BOOKMARK","object":{"apiVersion":"v1","kind":"Node","metadata":{"resourceVersion":"1","annotations":{"k8s.io/initial-events-end":"true"}}}}`)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = fmt.Fprint(w, `{"apiVersion":"v1","kind":"NodeList","metadata":{"resourceVersion":"1"},"items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"leader"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.10"}]}}]}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	config := filepath.Join(t.TempDir(), "kubeconfig")
	text := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: node\n  cluster:\n    server: %s\ncontexts:\n- name: node\n  context:\n    cluster: node\ncurrent-context: node\n", server.URL)
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := buildInventoryHosts(ctx, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if !hosts.Contains("192.0.2.10") || hosts.Contains("192.0.2.11") {
		t.Fatal("host kubeconfig did not bound callbacks to its live node list")
	}
}

func TestInventoryKubeconfigRejectsAuthenticationPlugins(t *testing.T) {
	for _, auth := range []string{
		`{"exec":{"apiVersion":"client.authentication.k8s.io/v1","command":"/operator/evil","interactiveMode":"Never"}}`,
		`{"auth-provider":{"name":"oidc","config":{"cmd-path":"/operator/evil"}}}`,
	} {
		path := filepath.Join(t.TempDir(), "config")
		text := `{"apiVersion":"v1","kind":"Config","clusters":[{"name":"c","cluster":{"server":"https://127.0.0.1:1"}}],"contexts":[{"name":"c","context":{"cluster":"c","user":"u"}}],"current-context":"c","users":[{"name":"u","user":` + auth + `}]}`
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if client, err := newKubeClientsetFromFile(path); err == nil || client != nil {
			t.Fatalf("authentication plugin accepted: %v %v", client, err)
		}
	}
}
