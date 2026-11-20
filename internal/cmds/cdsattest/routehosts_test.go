package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// hostedManifest routes two hosts and one agent pattern.
const hostedManifest = `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2020-01-01T00:00:00Z","maxAgeSeconds":3600,` +
	`"hosts":{"b.example":{"routes":[{"path":"/","match":"prefix","backend":{"address":"web.c8s.svc:8443","workload":"web"}}]},` +
	`"a.example":{"routes":[{"path":"/","match":"prefix","backend":{"address":"web.c8s.svc:8443","workload":"web"}}]}},` +
	`"patterns":[{"hostSuffix":"agents.example","workload":"opencode","port":4096}]}`

// stubCDS serves one envelope and the keys it was signed under.
type stubCDS struct {
	env  routes.Envelope
	keys []*ecdsa.PublicKey
}

func (s *stubCDS) Routes(context.Context) (routes.Envelope, error) { return s.env, nil }

func (s *stubCDS) OperatorKeys(context.Context) ([]*ecdsa.PublicKey, error) { return s.keys, nil }

// Only a verified manifest publishes hosts, and never its patterns.
func TestRouteHostsFollowTheVerifiedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	env, keys := signManifest(t, hostedManifest)
	cds := &stubCDS{env: routes.Envelope{Manifest: []byte(strings.Replace(hostedManifest, `"revision":1`, `"revision":2`, 1)), Token: env.Token}, keys: keys}
	poller := routing.NewPoller(routing.PollerConfig{
		State:   routing.NewState(routing.StateConfig{MeshCAs: noMeshCAs}),
		Fetcher: cds,
		Keys:    cds,
		Applied: routeHostsWriter(path),
	})

	if err := poller.Poll(t.Context()); err == nil {
		t.Fatal("a manifest its token does not cover was applied")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hosts file after a refused manifest: %v, want none", err)
	}

	cds.env = env
	if err := poller.Poll(t.Context()); err != nil {
		t.Fatalf("poll of the signed manifest: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "a.example\nb.example\n"; got != want {
		t.Fatalf("published hosts = %q, want %q", got, want)
	}
}

// A router with no hosts file named publishes none: the cds front door orders
// no certificate of its own.
func TestRouteHostsWriterIsOffWithoutAFile(t *testing.T) {
	if routeHostsWriter("") != nil {
		t.Error("an unnamed hosts file still publishes")
	}
}
