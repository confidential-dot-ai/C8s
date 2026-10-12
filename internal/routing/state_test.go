package routing

import (
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

func simpleManifest(revision uint64, address string) manifestSpec {
	return manifestSpec{revision: revision, hosts: map[string][]route{
		testHost: {workloadRoute("/", "prefix", address, "web")},
	}}
}

func TestA2NotAppliedThenApplied(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))

	if got := f.get("/").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("GET / before the first apply = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if _, err := f.state.Session(); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("Session() before the first apply = %v, want %v", err, ErrNotApplied)
	}
	f.apply(t, simpleManifest(1, web.addr()))
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / after the first apply = %d, want %d", got, http.StatusOK)
	}
	if _, err := f.state.Session(); err != nil {
		t.Fatalf("Session() after the first apply = %v, want nil", err)
	}
}

func TestA3W4RejectsRollback(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(5, "127.0.0.1:1"))
	before := f.state.Current()

	tests := []struct {
		name string
		m    manifestSpec
		want error
	}{
		{"W4 lower revision", simpleManifest(4, "127.0.0.1:1"), routes.ErrRollback},
		{"W4 equal revision other digest", simpleManifest(5, "127.0.0.1:2"), routes.ErrRevisionConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.state.Accept(f.op.sign(t, tc.m.bytes(t)), f.op.keys)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Accept(revision %d) = %v, want %v", tc.m.revision, err, tc.want)
			}
			if f.state.Current() != before {
				t.Fatal("Current() changed after a rejected manifest, want the applied one kept (A6)")
			}
		})
	}
}

// TestA4W4StagedRevisionBounds: a staged revision is accepted, so W4 holds
// against it before it applies, a refused manifest does not refresh, and the
// staged revision applies at the first fetch at or after its notBefore.
func TestA4W4StagedRevisionBounds(t *testing.T) {
	f := newFixture(t)
	applied := simpleManifest(5, "127.0.0.1:1")
	applied.maxAge = time.Minute
	f.apply(t, applied)
	staged := simpleManifest(10, "127.0.0.1:2")
	staged.notBefore = f.clock.Now().Add(time.Hour)
	staged.maxAge = time.Minute
	if outcome, err := f.state.Accept(f.op.sign(t, staged.bytes(t)), f.op.keys); err != nil || outcome != OutcomeStaged {
		t.Fatalf("Accept(revision 10, notBefore in an hour) = %v, %v, want %v, nil", outcome, err, OutcomeStaged)
	}
	conflicting := simpleManifest(10, "127.0.0.1:3")
	conflicting.notBefore = staged.notBefore
	tests := []struct {
		name string
		m    manifestSpec
		want error
	}{
		{"W4 applied revision", applied, routes.ErrRollback},
		{"W4 between applied and staged", simpleManifest(6, "127.0.0.1:1"), routes.ErrRollback},
		{"W4 staged revision other digest", conflicting, routes.ErrRevisionConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.clock.Advance(40 * time.Second)
			_, err := f.state.Accept(f.op.sign(t, tc.m.bytes(t)), f.op.keys)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Accept(revision %d) = %v, want %v", tc.m.revision, err, tc.want)
			}
			if got := f.state.Current().Manifest.Revision; got != 5 {
				t.Fatalf("Current() revision = %d, want 5", got)
			}
		})
	}
	if f.state.Status() != routes.Stale {
		t.Fatal("Stale() = false after maxAgeSeconds of refused manifests, want true (F1)")
	}
	// Refetching the applied revision left the staged one in place (A3).
	f.clock.Advance(time.Hour)
	if outcome, err := f.state.Accept(f.op.sign(t, staged.bytes(t)), f.op.keys); err != nil || outcome != OutcomeApplied {
		t.Fatalf("Accept(revision 10) at its notBefore = %v, %v, want %v, nil", outcome, err, OutcomeApplied)
	}
}

func TestA3W2RejectsUnknownKey(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	before := f.state.Current()
	other := newOperator(t)
	if _, err := f.state.Accept(other.sign(t, simpleManifest(2, "127.0.0.1:1").bytes(t)), f.op.keys); err == nil {
		t.Fatal("Accept(signed by an untrusted key) = nil, want an error")
	}
	if f.state.Current() != before {
		t.Fatal("Current() changed after a manifest under an untrusted key (A6)")
	}
}

func TestA4NotBeforeKeepsTableAndRefreshes(t *testing.T) {
	f := newFixture(t)
	f.apply(t, manifestSpec{revision: 1, maxAge: time.Minute, hosts: simpleManifest(1, "127.0.0.1:1").hosts})
	before := f.state.Current()

	f.clock.Advance(50 * time.Second)
	staged := simpleManifest(2, "127.0.0.1:2")
	staged.notBefore = f.clock.Now().Add(time.Hour)
	staged.maxAge = time.Minute
	outcome, err := f.state.Accept(f.op.sign(t, staged.bytes(t)), f.op.keys)
	if err != nil || outcome != OutcomeStaged {
		t.Fatalf("Accept(notBefore in an hour) = %v, %v, want %v, nil", outcome, err, OutcomeStaged)
	}
	if f.state.Current() != before {
		t.Fatal("Current() changed before the new manifest's notBefore")
	}
	// 50s after the staged fetch is 100s after the apply: fresh only because
	// the staged fetch counted as a refresh.
	f.clock.Advance(50 * time.Second)
	if f.state.Status() == routes.Stale {
		t.Fatal("Stale() = true 50s after verifying a staged newer revision, want false (A4, F1)")
	}

	f.clock.Advance(time.Hour)
	outcome, err = f.state.Accept(f.op.sign(t, staged.bytes(t)), f.op.keys)
	if err != nil || outcome != OutcomeApplied {
		t.Fatalf("Accept(after notBefore) = %v, %v, want %v, nil", outcome, err, OutcomeApplied)
	}
	if got := f.state.Current().Manifest.Revision; got != 2 {
		t.Fatalf("Current() revision = %d, want 2", got)
	}
}

func TestA6BadManifestKeepsApplied(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	before := f.state.Current()
	tests := []struct {
		name string
		env  routes.Envelope
	}{
		{"A6 invalid manifest", f.op.sign(t, []byte(`{"schema":"c8s.routes/v1"}`))},
		{"A6 token for other bytes", routes.Envelope{
			Manifest: simpleManifest(2, "127.0.0.1:1").bytes(t),
			Token:    f.op.sign(t, simpleManifest(3, "127.0.0.1:1").bytes(t)).Token,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.state.Accept(tc.env, f.op.keys); err == nil {
				t.Fatal("Accept() = nil, want an error")
			}
			if f.state.Current() != before {
				t.Fatal("Current() changed after a failed Accept, want the applied manifest kept")
			}
		})
	}
}

func TestB3RejectsMeshCAAnchor(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	before := f.state.Current()
	bad := manifestSpec{revision: 2, hosts: map[string][]route{
		testHost: {addressRoute("/", "prefix", "127.0.0.1:1", "admin.ops.svc", caPEM(newCA(t, "other"), f.mesh))},
	}}
	if _, err := f.state.Accept(f.op.sign(t, bad.bytes(t)), f.op.keys); err == nil {
		t.Fatal("Accept(ca holding the mesh CA) = nil, want an error (B3)")
	}
	if f.state.Current() != before {
		t.Fatal("Current() changed after a manifest anchored to the mesh CA")
	}
}

func TestF1F2F3Freshness(t *testing.T) {
	f := newFixture(t)
	m := simpleManifest(1, "127.0.0.1:1")
	m.maxAge = time.Minute
	f.apply(t, m)

	f.clock.Advance(59 * time.Second)
	if f.state.Status() == routes.Stale {
		t.Fatal("Stale() = true before maxAgeSeconds, want false")
	}
	f.clock.Advance(time.Second)
	if f.state.Status() != routes.Stale {
		t.Fatal("Stale() = false at maxAgeSeconds since the last refresh, want true (F1)")
	}
	if _, err := f.state.Session(); !errors.Is(err, ErrStale) {
		t.Fatalf("Session() when stale = %v, want %v (F2)", err, ErrStale)
	}
	if got := f.get("/app").Code; got == http.StatusServiceUnavailable {
		t.Fatalf("public path when stale = %d, want it still routed (F2 MAY)", got)
	}

	// A failed fetch does not refresh.
	if _, err := f.state.Accept(f.op.sign(t, []byte("{}")), f.op.keys); err == nil {
		t.Fatal("Accept(invalid) = nil, want an error")
	}
	if f.state.Status() != routes.Stale {
		t.Fatal("Stale() = false after a failed fetch, want true")
	}

	outcome, err := f.state.Accept(f.op.sign(t, m.bytes(t)), f.op.keys)
	if err != nil || outcome != OutcomeUnchanged {
		t.Fatalf("Accept(same revision and digest) = %v, %v, want %v, nil", outcome, err, OutcomeUnchanged)
	}
	if f.state.Status() == routes.Stale {
		t.Fatal("Stale() = true after a successful fetch of the same revision, want false (F3)")
	}
	if _, err := f.state.Session(); err != nil {
		t.Fatalf("Session() after F3 refresh = %v, want nil", err)
	}
}

// TestB3MeshCARotatedIntoAnchor: a CA an applied address backend anchors to
// joins the mesh bundle. New connections to that backend fail, and refetching
// the same manifest no longer refreshes it.
func TestB3MeshCARotatedIntoAnchor(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	b := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"))
	m := manifestSpec{revision: 1, hosts: map[string][]route{
		testHost: {addressRoute("/", "prefix", b.addr(), "admin.ops.svc", caPEM(external))},
	}}
	f.apply(t, m)
	if err := f.transports.dropMeshPools(); err != nil { // records the bundle
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
	}

	if err := os.WriteFile(f.meshCAFile, []byte(caPEM(f.mesh, external)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The next poll notices the new bundle and drops the pooled connection.
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / after the anchor joined the mesh bundle = %d, want %d (B3)", got, http.StatusBadGateway)
	}
	if _, err := f.state.Accept(f.op.sign(t, m.bytes(t)), f.op.keys); err == nil {
		t.Fatal("Accept(same manifest, anchor now a mesh CA) = nil, want an error (B3)")
	}
}

// TestB3MeshIssuedIntermediateAnchor: an address backend's ca is an
// intermediate a mesh CA issued. Accept refuses it, and so does the handshake
// when that mesh CA joins the bundle after apply.
func TestB3MeshIssuedIntermediateAnchor(t *testing.T) {
	f := newFixture(t)
	root := newCA(t, "mesh-2")
	intermediate := newIntermediate(t, root, "intermediate")
	b := startBackend(t, "admin", issueLeaf(t, intermediate, "", "admin.ops.svc"))
	m := manifestSpec{revision: 1, hosts: map[string][]route{
		testHost: {addressRoute("/", "prefix", b.addr(), "admin.ops.svc", caPEM(intermediate))},
	}}
	f.apply(t, m)
	if err := f.transports.dropMeshPools(); err != nil { // records the bundle
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
	}

	if err := os.WriteFile(f.meshCAFile, []byte(caPEM(f.mesh, root)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / after the intermediate's issuer joined the mesh bundle = %d, want %d (B3)", got, http.StatusBadGateway)
	}
	m.revision = 2
	if _, err := f.state.Accept(f.op.sign(t, m.bytes(t)), f.op.keys); err == nil {
		t.Fatal("Accept(ca issued by a mesh CA) = nil, want an error (B3)")
	}
}

func TestB1UnreadableMeshCADropsPool(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
	}
	if err := os.WriteFile(f.meshCAFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.transports.dropMeshPools(); err == nil {
		t.Fatal("dropMeshPools() with an unreadable bundle = nil, want an error")
	}
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / after the bundle became unreadable = %d, want %d", got, http.StatusBadGateway)
	}
}

// TestB1RotationRetiresInFlightConnection: a connection in flight across a
// mesh CA rotation must not return to a pool later requests use, even after
// another request reached the backend in between.
func TestB1RotationRetiresInFlightConnection(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil { // records the bundle
		t.Fatal(err)
	}

	done := make(chan int)
	go func() { done <- f.get("/slow").Code }()
	<-web.entered
	inFlight := web.seen().remoteAddr
	if err := os.WriteFile(f.meshCAFile, []byte(caPEM(f.mesh, newCA(t, "mesh-2"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
	}
	close(web.release)
	if got := <-done; got != http.StatusOK {
		t.Fatalf("GET /slow = %d, want %d", got, http.StatusOK)
	}
	for range 3 {
		if got := f.get("/").Code; got != http.StatusOK {
			t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
		}
		if got := web.seen().remoteAddr; got == inFlight {
			t.Fatalf("GET / after the rotation reused connection %s, verified under the old bundle", got)
		}
	}
}

// TestB3A4StagedFetchRechecksApplied: a staged manifest refreshes the applied
// one only while the applied one still passes B3.
func TestB3A4StagedFetchRechecksApplied(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	applied := manifestSpec{revision: 1, maxAge: time.Minute, hosts: map[string][]route{
		testHost: {addressRoute("/", "prefix", "127.0.0.1:1", "admin.ops.svc", caPEM(external))},
	}}
	f.apply(t, applied)
	if err := os.WriteFile(f.meshCAFile, []byte(caPEM(f.mesh, external)), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := simpleManifest(2, "127.0.0.1:1")
	staged.notBefore = f.clock.Now().Add(time.Hour)
	staged.maxAge = time.Minute
	for range 2 {
		f.clock.Advance(40 * time.Second)
		if _, err := f.state.Accept(f.op.sign(t, staged.bytes(t)), f.op.keys); err == nil {
			t.Fatal("Accept(staged, applied anchor now a mesh CA) = nil, want an error (B3)")
		}
	}
	if f.state.Status() != routes.Stale {
		t.Fatal("Stale() = false after maxAgeSeconds of refused refreshes, want true (F1)")
	}
}
