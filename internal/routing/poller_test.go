package routing

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/routes"
)

// testTA serves GET /routes and GET /operator-keys like the Trust Authority (C1).
type testTA struct {
	mu      sync.Mutex
	status  int
	body    []byte
	keysPEM []byte
	ts      *httptest.Server
}

func startTA(t *testing.T) *testTA {
	t.Helper()
	c := &testTA{status: http.StatusNotFound}
	c.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		switch r.URL.Path {
		case routes.Path:
			if c.status != http.StatusOK {
				w.WriteHeader(c.status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(c.body)
		case "/operator-keys":
			if c.keysPEM == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(c.keysPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(c.ts.Close)
	return c
}

func (c *testTA) serve(t *testing.T, env routes.Envelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.body = http.StatusOK, b
}

func (c *testTA) fail(status int, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.body = status, body
}

func (c *testTA) client(t *testing.T) *CDSClient {
	t.Helper()
	client, err := NewCDSClient(c.ts.URL, c.ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func publicKeysPEM(t *testing.T, o operator) []byte {
	t.Helper()
	var out []byte
	for _, k := range o.keys {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	return out
}

func TestA1A3PollAppliesFromCDS(t *testing.T) {
	f := newFixture(t)
	ta := startTA(t)
	ta.keysPEM = publicKeysPEM(t, f.op)
	client := ta.client(t)
	p := NewPoller(PollerConfig{State: f.state, Fetcher: client, Keys: client, Transports: f.transports})

	if err := p.Poll(context.Background()); !errors.Is(err, errNoManifest) {
		t.Fatalf("poll() with no stored manifest = %v, want %v", err, errNoManifest)
	}
	ta.serve(t, f.op.sign(t, simpleManifest(3, "127.0.0.1:1").bytes(t)))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll() = %v, want nil", err)
	}
	if got := f.state.Current(); got == nil || got.Manifest.Revision != 3 {
		t.Fatalf("Current() after poll = %v, want revision 3", got)
	}
}

func TestA6PollFailuresKeepApplied(t *testing.T) {
	f := newFixture(t)
	ta := startTA(t)
	client := ta.client(t)
	p := NewPoller(PollerConfig{State: f.state, Fetcher: client, Keys: KeyFile(writeFile(t, "keys.pem", publicKeysPEM(t, f.op)))})
	ta.serve(t, f.op.sign(t, simpleManifest(1, "127.0.0.1:1").bytes(t)))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll() = %v, want nil", err)
	}
	before := f.state.Current()

	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		{"A6 Trust Authority 404", http.StatusNotFound, nil},
		{"A6 Trust Authority 500", http.StatusInternalServerError, nil},
		{"A6 malformed envelope", http.StatusOK, []byte(`{"manifest":1}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ta.fail(tc.status, tc.body)
			if err := p.Poll(context.Background()); err == nil {
				t.Fatal("poll() = nil, want an error")
			}
			if f.state.Current() != before {
				t.Fatal("Current() changed after a failed poll, want the applied manifest kept")
			}
		})
	}
	t.Run("A6 Trust Authority unreachable", func(t *testing.T) {
		ta.ts.Close()
		if err := p.Poll(context.Background()); err == nil {
			t.Fatal("poll() = nil, want an error")
		}
		if f.state.Current() != before {
			t.Fatal("Current() changed with the Trust Authority unreachable")
		}
	})
}

func TestW6CDSKeySourceWithoutKeys(t *testing.T) {
	f := newFixture(t)
	ta := startTA(t)
	client := ta.client(t)
	ta.serve(t, f.op.sign(t, simpleManifest(1, "127.0.0.1:1").bytes(t)))
	p := NewPoller(PollerConfig{State: f.state, Fetcher: client, Keys: client})
	if err := p.Poll(context.Background()); !errors.Is(err, operatorauth.ErrNoPublishedKeys) {
		t.Fatalf("poll() with no operator keys on the Trust Authority = %v, want %v", err, operatorauth.ErrNoPublishedKeys)
	}
	if f.state.Current() != nil {
		t.Fatal("Current() != nil without operator keys, want nothing applied")
	}
}

func TestNewCDSClientRejectsNonOrigins(t *testing.T) {
	for _, base := range []string{"http://cds:8443", "https://cds:8443/x", "https://u@cds", "cds:8443", "https://cds?q"} {
		if _, err := NewCDSClient(base, http.DefaultClient); err == nil {
			t.Errorf("NewCDSClient(%q) = nil error, want one", base)
		}
	}
}

// duringFetch runs hook while a fetch is in flight.
type duringFetch struct {
	Fetcher
	hook func()
}

func (d duringFetch) Routes(ctx context.Context) (routes.Envelope, error) {
	d.hook()
	return d.Fetcher.Routes(ctx)
}

// TestB3PollRetiresPoolsOnBundleChangeDuringFetch: the mesh CA bundle changes
// while the manifest fetch is in flight. Accept refuses the refresh, and the
// pooled connection to the now-forbidden address backend must not survive
// the poll.
func TestB3PollRetiresPoolsOnBundleChangeDuringFetch(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	b := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"), webPKI)
	m := manifestSpec{revision: 1, hosts: map[string][]route{
		testHost: {addressRoute("/", "prefix", b.addr(), "admin.ops.svc", caPEM(external))},
	}}
	ta := startTA(t)
	ta.serve(t, f.op.sign(t, m.bytes(t)))
	var rotate bool
	p := NewPoller(PollerConfig{
		State: f.state,
		Fetcher: duringFetch{Fetcher: ta.client(t), hook: func() {
			if !rotate {
				return
			}
			f.publish(t, caPEM(f.mesh, external))
		}},
		Keys:       KeyFile(writeFile(t, "keys.pem", publicKeysPEM(t, f.op))),
		Transports: f.transports,
	})
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll() = %v, want nil", err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
	}

	rotate = true
	if err := p.Poll(context.Background()); err == nil {
		t.Fatal("Poll() with the anchor rotated into the mesh bundle = nil, want an error (B3)")
	}
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / after the poll = %d, want %d (B3)", got, http.StatusBadGateway)
	}
}

// TestPollRetainsOnUnchanged: a transport rebuilt for a backend the applied
// manifest no longer names is dropped by the next poll, even an unchanged one.
func TestPollRetainsOnUnchanged(t *testing.T) {
	f := newFixture(t)
	ta := startTA(t)
	ta.serve(t, f.op.sign(t, simpleManifest(1, "127.0.0.1:1").bytes(t)))
	p := NewPoller(PollerConfig{State: f.state, Fetcher: ta.client(t), Keys: KeyFile(writeFile(t, "keys.pem", publicKeysPEM(t, f.op))), Transports: f.transports})
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll() = %v, want nil", err)
	}
	gone := routes.Backend{Address: "127.0.0.1:2", Workload: "gone"}
	f.transports.For(gone)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll() unchanged = %v, want nil", err)
	}
	f.transports.mu.Lock()
	defer f.transports.mu.Unlock()
	if _, ok := f.transports.cache[poolKey{backend: backendKey(gone)}]; ok {
		t.Fatal("transport of an unnamed backend survived an unchanged poll")
	}
}
