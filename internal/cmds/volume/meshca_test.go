package volume

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

func writeBundle(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(path, testutil.PEMCerts(der), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// keyStore counts the secret writes a fake CDS receives.
type keyStore struct {
	mu     sync.Mutex
	writes int
}

func (k *keyStore) serve(w http.ResponseWriter, _ *http.Request) {
	k.mu.Lock()
	k.writes++
	k.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func (k *keyStore) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.writes
}

// newAttestedCDS serves GET /ca with one mesh CA, and the secret store, over
// armTLS.
func newAttestedCDS(t *testing.T, caDER []byte) (*keyStore, *httptest.Server) {
	t.Helper()
	k := &keyStore{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(testutil.PEMCerts(caDER)) })
	mux.HandleFunc("/secrets/", k.serve)
	return k, testutil.NewARMTLSServer(t, mux)
}

// attestedOptions reaches url over armTLS with a verifier that approves, so the
// only thing under test is the mesh-CA gate.
func attestedOptions(t *testing.T, url, dir string) *options {
	t.Helper()
	return &options{Options: cdsconn.Options{
		URL:          url,
		Measurements: []string{testutil.TestMeasurement},
		Timeout:      5 * time.Second,
		OperatorKey:  operatorKeyFile(t, dir),
		Verifier:     testutil.ApproveAll(),
		DirectCDS:    true,
	}}
}

func assertNothingWritten(t *testing.T, f flowFixture) {
	t.Helper()
	for _, p := range []string{f.out, f.escrow} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was written despite the refusal", p)
		}
	}
}

// A measurement pin does not identify a CDS, so a volume key is refused with
// no --mesh-ca — and refused before the build, so nothing is left on disk.
func TestRunCreateRefusesWithoutMeshCA(t *testing.T) {
	f := newFlowFixture(t)
	keys, srv := newAttestedCDS(t, testutil.MeshCA(t, "cds-m"))

	cmd, _ := captureCmd()
	err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), f.config(newFake()))
	if err == nil || !strings.Contains(err.Error(), "--mesh-ca") {
		t.Fatalf("got %v, want a refusal naming --mesh-ca", err)
	}
	if keys.count() != 0 {
		t.Fatal("the refused key still reached CDS")
	}
	assertNothingWritten(t, f)
}

// Every refusal that needs no network lands before the build.
func TestRunCreateRefusesBeforeBuilding(t *testing.T) {
	ca := testutil.MeshCA(t, "cds-m")
	for name, mutate := range map[string]func(o *options){
		"no operator key":            func(o *options) { o.OperatorKey = "" },
		"plaintext without insecure": func(o *options) { o.URL = "http://cds.example" },
		"unpinned endpoint":          func(o *options) { o.Measurements = nil },
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(cdsconn.EnvOperatorKey, "")
			f := newFlowFixture(t)
			_, srv := newAttestedCDS(t, ca)
			o := attestedOptions(t, srv.URL, f.dir)
			mutate(o)
			cfg := f.config(newFake())
			cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, ca)}

			cmd, _ := captureCmd()
			if err := runCreate(cmd, o, cfg); err == nil {
				t.Fatal("create was accepted")
			}
			assertNothingWritten(t, f)
		})
	}
}

// A router front door does not relay /secrets, so it is refused before the
// build rather than after the image and escrow exist.
func TestRunCreateRefusesARouterBeforeBuilding(t *testing.T) {
	f := newFlowFixture(t)
	ca := testutil.MeshCA(t, "cds-m")
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, ca)}
	router := testutil.NewRouterServer(t)

	cmd, _ := captureCmd()
	err := runCreate(cmd, attestedOptions(t, router.URL, f.dir), cfg)
	if err == nil || !strings.Contains(err.Error(), "router front door") {
		t.Fatalf("runCreate(%s) = %v, want a router front door refusal", router.URL, err)
	}
	assertNothingWritten(t, f)
}

// An attested CDS serving a CA the operator never pinned is not their CDS: the
// key is withheld, and the error says how to store the escrowed key later.
func TestRunCreateRefusesAnotherCDSsMeshCA(t *testing.T) {
	f := newFlowFixture(t)
	keys, srv := newAttestedCDS(t, testutil.MeshCA(t, "cds-n"))
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, testutil.MeshCA(t, "cds-m"))}

	cmd, _ := captureCmd()
	err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), cfg)
	if err == nil || !strings.Contains(err.Error(), "not in --mesh-ca") {
		t.Fatalf("got %v, want a mesh CA mismatch", err)
	}
	for _, want := range []string{
		"the key was not stored",
		"once you reach the CDS your bundle names",
		"c8s secrets put /tenant-a/volumes/weights --from-file " + f.escrow,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q: %v", want, err)
		}
	}
	if keys.count() != 0 {
		t.Fatal("the key reached a CDS serving an unpinned mesh CA")
	}
}

// A /ca that cannot be read is not a mismatch; the hint says to retry.
func TestRunCreateUnreadableCAHintsARetry(t *testing.T) {
	f := newFlowFixture(t)
	ca := testutil.MeshCA(t, "cds-m")
	srv := testutil.NewARMTLSServer(t, http.NotFoundHandler())
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, ca)}

	cmd, _ := captureCmd()
	err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), cfg)
	if err == nil || !strings.Contains(err.Error(), "returned 404") || !strings.Contains(err.Error(), "retry with") {
		t.Fatalf("got %v, want a 404 with a retry hint", err)
	}
}

func TestRunCreateAcceptsThePinnedMeshCA(t *testing.T) {
	f := newFlowFixture(t)
	ca := testutil.MeshCA(t, "cds-m")
	keys, srv := newAttestedCDS(t, ca)
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, ca)}

	cmd, out := captureCmd()
	if err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), cfg); err != nil {
		t.Fatalf("create against the pinned CDS: %v", err)
	}
	if keys.count() != 1 {
		t.Fatalf("sent %d writes, want 1", keys.count())
	}
	if !strings.Contains(out.String(), "key stored at /tenant-a/volumes/weights") {
		t.Errorf("output = %s", out.String())
	}
}

// The key goes to the peer whose CA was checked, or nowhere: a redial that
// reaches another attested server at the same measurement is refused at the
// handshake, before the key is sent.
func TestRunCreateRefusesAWriteThatRedialsToAnotherPeer(t *testing.T) {
	f := newFlowFixture(t)
	ca := testutil.MeshCA(t, "cds-m")
	impostor, impostorSrv := newAttestedCDS(t, ca)

	var proxy *testutil.ReroutingProxy
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		proxy.Reroute(impostorSrv)
		w.Header().Set("Connection", "close")
		_, _ = w.Write(testutil.PEMCerts(ca))
	})
	proxy = testutil.NewReroutingProxy(t, testutil.NewARMTLSServer(t, mux))
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: writeBundle(t, ca)}

	cmd, _ := captureCmd()
	err := runCreate(cmd, attestedOptions(t, proxy.URL, f.dir), cfg)
	if err == nil || !strings.Contains(err.Error(), "different serving certificate") {
		t.Fatalf("got %v, want the redial refused", err)
	}
	if impostor.count() != 0 {
		t.Fatal("the key reached a peer other than the one whose CA was checked")
	}
}

// --force writes, and says on stderr that it skipped the check.
func TestRunCreateForceSkipsTheCheckLoudly(t *testing.T) {
	f := newFlowFixture(t)
	keys, srv := newAttestedCDS(t, testutil.MeshCA(t, "cds-n"))
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Force: true}

	cmd, out := captureCmd()
	if err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), cfg); err != nil {
		t.Fatalf("--force did not write: %v", err)
	}
	if !strings.Contains(out.String(), "--force: writing this volume key without checking the CDS mesh CA") {
		t.Fatalf("--force wrote without announcing the skipped check: %s", out.String())
	}
	if keys.count() != 1 {
		t.Fatalf("sent %d writes, want 1", keys.count())
	}
}

// A bundle that names no certificate is caught before the build too.
func TestRunCreateRefusesAnUnusableBundleBeforeBuilding(t *testing.T) {
	f := newFlowFixture(t)
	_, srv := newAttestedCDS(t, testutil.MeshCA(t, "cds-m"))
	cfg := f.config(newFake())
	cfg.gate = cdsconn.MeshCAGate{What: "volume key", Bundle: filepath.Join(f.dir, "nope.pem")}

	cmd, _ := captureCmd()
	if err := runCreate(cmd, attestedOptions(t, srv.URL, f.dir), cfg); err == nil {
		t.Fatal("an absent bundle was accepted")
	}
	assertNothingWritten(t, f)
}

// --dry-run never reaches CDS, so it needs no --mesh-ca; the plaintext dev path
// is exempt as it is for `secrets put` (TestRunCreateStoresBlobAndPrintsGuidance
// covers it, with --insecure and no bundle).
func TestCreateBindsTheGateFlags(t *testing.T) {
	cmd := newCreateCmd(&options{})
	for _, name := range []string{"mesh-ca", "force"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("volume create has no --%s", name)
		}
	}
}
