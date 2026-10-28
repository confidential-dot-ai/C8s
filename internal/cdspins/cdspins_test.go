package cdspins

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

const cluster = "c1"

// key is a P-256 key and its PKIX DER.
func key() (*ecdsa.PrivateKey, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return k, der
}

func img(b byte) cdsha.DecreeImage {
	h := func(c byte) string { return strings.Repeat(string("0123456789abcdef"[c%16]), 96) }
	return cdsha.DecreeImage{MRTD: h(b), RTMR1: h(b + 1), RTMR2: h(b + 2)}
}

func pinDecree(t *testing.T, k *ecdsa.PrivateKey, clusterID string, base uint64, images ...cdsha.DecreeImage) *cdsha.SignedDecree {
	t.Helper()
	var pins []string
	for _, i := range images {
		p, err := i.Pin()
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, p)
	}
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "i", BaseEpoch: base, Kind: cdsha.UpdateMeasurements,
		ExpiresAt: time.Now().Add(-time.Hour), Measurements: pins, Images: images}, k)
	if err != nil {
		t.Fatal(err)
	}
	return &sd
}

var serverKey, cdsKey = pemKey(), pemKey()

func pemKey() []byte {
	_, der := key()
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// bootstrap is a launch document's cds.json: the server and one cds node,
// each pinned to image A under its own launch key.
func bootstrap() refvalues.ReferenceValues {
	a := img(1)
	pol, err := Policy(refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{
		{Name: "server", Anchor: serverKey}, {Name: "cds-1", Anchor: cdsKey}}}, []cdsha.DecreeImage{a})
	if err != nil {
		panic(err)
	}
	for i := range pol.Images {
		pol.Images[i].Name = strings.Split(pol.Images[i].Name, "@")[0]
	}
	return pol
}

type served struct{ sd *cdsha.SignedDecree }

func (s *served) fetch(context.Context) (*cdsha.SignedDecree, error) { return s.sd, nil }

func TestRefreshFollowsNewerSignedDecrees(t *testing.T) {
	k, pub := key()
	srv := &served{}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch, MinInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing served yet: the bootstrap set stays.
	if changed, err := src.Refresh(t.Context()); changed || err != nil || len(src.Current().Images) != 2 {
		t.Fatalf("no decree: %v %v %d", changed, err, len(src.Current().Images))
	}
	// Accept A and B: both images under both launch keys. Expiry does not
	// matter to clients.
	srv.sd = pinDecree(t, k, cluster, 3, img(1), img(5))
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("A+B: %v %v", changed, err)
	}
	cur := src.Current()
	if len(cur.Images) != 4 {
		t.Fatalf("A+B under two keys: %d pins", len(cur.Images))
	}
	// Each launch key pins each image's own MRTD, RTMR1 and RTMR2.
	want := map[string]bool{}
	for _, i := range []cdsha.DecreeImage{img(1), img(5)} {
		for _, a := range [][]byte{serverKey, cdsKey} {
			want[string(a)+i.MRTD+i.RTMR1+i.RTMR2] = true
		}
	}
	for _, p := range cur.Images {
		delete(want, string(p.Anchor)+hex.EncodeToString(p.Digest)+hex.EncodeToString(p.Registers[1])+hex.EncodeToString(p.Registers[2]))
	}
	if len(want) != 0 {
		t.Fatalf("%d of 4 anchor/image pins missing or wrong", len(want))
	}
	// B only.
	srv.sd = pinDecree(t, k, cluster, 4, img(5))
	if changed, _ := src.Refresh(t.Context()); !changed || len(src.Current().Images) != 2 {
		t.Fatal("B only not taken")
	}
	// The same decree again: not a change, so clients keep their transports.
	gen := src.Generation()
	if changed, err := src.Refresh(t.Context()); changed || err != nil || src.Generation() != gen {
		t.Fatalf("same decree: %v %v, generation %d -> %d", changed, err, gen, src.Generation())
	}
	// The host replays the A+B decree: refused, B only stays.
	srv.sd = pinDecree(t, k, cluster, 3, img(1), img(5))
	if changed, err := src.Refresh(t.Context()); changed || err != nil || len(src.Current().Images) != 2 {
		t.Fatalf("replayed older decree: %v %v", changed, err)
	}
	if e, ok := src.Epoch(); !ok || e != 4 {
		t.Fatalf("epoch %d %v", e, ok)
	}
}

// Refresh checks the decree (cdsha.VerifyPinDecree has the per-field
// cases): one signed by another key leaves the pin set alone.
func TestRefreshRefusesWhatTheOperatorDidNotSign(t *testing.T) {
	_, pub := key()
	other, _ := key()
	srv := &served{sd: pinDecree(t, other, cluster, 9, img(5))}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); changed || err == nil {
		t.Fatalf("taken: %v %v", changed, err)
	}
	if len(src.Current().Images) != 2 {
		t.Fatal("pin set changed")
	}
}

// The node remembers the newest decree across restarts, so a replay after
// a restart is refused too.
func TestStateSurvivesRestart(t *testing.T) {
	k, pub := key()
	cfg := Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond,
		StateFile: filepath.Join(t.TempDir(), "state.json")}
	srv := &served{sd: pinDecree(t, k, cluster, 4, img(5))}
	cfg.Fetch = srv.fetch
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatal(changed, err)
	}
	again, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := again.Epoch(); !ok || e != 4 {
		t.Fatalf("after restart: epoch %d %v", e, ok)
	}
	srv.sd = pinDecree(t, k, cluster, 3, img(1), img(5))
	if changed, _ := again.Refresh(t.Context()); changed {
		t.Fatal("replay taken after a restart")
	}
}

func TestHTTPFetch(t *testing.T) {
	k, _ := key()
	sd := pinDecree(t, k, cluster, 4, img(5))
	var serve *cdsha.SignedDecree
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ha/pins" {
			http.NotFound(w, r)
			return
		}
		if serve == nil {
			http.Error(w, "genesis", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(serve)
	}))
	defer ts.Close()
	fetch := HTTPFetch(ts.URL)
	if got, err := fetch(t.Context()); got != nil || err != nil {
		t.Fatalf("404: %v %v", got, err)
	}
	serve = sd
	got, err := fetch(t.Context())
	if err != nil || got == nil || got.Decree.BaseEpoch != 4 || len(got.Decree.Images) != 1 {
		t.Fatalf("200: %+v %v", got, err)
	}
}

func TestHTTPFetchErrors(t *testing.T) {
	code, body := http.StatusServiceUnavailable, "x"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	if _, err := HTTPFetch(ts.URL)(t.Context()); err == nil {
		t.Fatal("503 accepted")
	}
	code = http.StatusOK
	if _, err := HTTPFetch(ts.URL)(t.Context()); err == nil {
		t.Fatal("non-JSON accepted")
	}
}

func TestNewAndPolicyErrors(t *testing.T) {
	k, pub := key()
	if _, err := New(Config{DecreeKey: pub}); err == nil {
		t.Fatal("no cluster id accepted")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), StateFile: state}); err == nil {
		t.Fatal("corrupt state accepted")
	}
	other, _ := key()
	bad, _ := json.Marshal(pinState{InForce: pinDecree(t, other, cluster, 3, img(5))})
	if err := os.WriteFile(state, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), StateFile: state}); err == nil {
		t.Fatal("a state decree with a foreign signature accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), StateFile: filepath.Join(dir, "dir")}); err == nil {
		t.Fatal("unreadable state accepted")
	}
	if _, err := Policy(refvalues.ReferenceValues{Family: teetypes.FamilySNP}, []cdsha.DecreeImage{img(1)}); err == nil {
		t.Fatal("SNP bootstrap accepted")
	}
	if _, err := Policy(bootstrap(), nil); err == nil {
		t.Fatal("no images accepted")
	}
	// Every pin carries a launch-key anchor: a bootstrap set without one,
	// or with one image that has none, is refused rather than pinned
	// without a launch-key check.
	if pol, err := Policy(refvalues.ReferenceValues{Family: teetypes.FamilyTDX}, []cdsha.DecreeImage{img(1)}); err == nil {
		t.Fatalf("anchorless bootstrap accepted: %+v", pol)
	}
	mixed := bootstrap()
	mixed.Images = append(mixed.Images, remote.ImagePin{Name: "bare", Digest: mixed.Images[0].Digest, Registers: mixed.Images[0].Registers})
	if pol, err := Policy(mixed, []cdsha.DecreeImage{img(1)}); err == nil {
		t.Fatalf("bootstrap image without an anchor accepted: %+v", pol)
	}
	// Fetches are spaced: a burst of misses fetches once.
	srv := &served{sd: pinDecree(t, k, cluster, 4, img(5))}
	calls := 0
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Hour,
		Fetch: func(ctx context.Context) (*cdsha.SignedDecree, error) { calls++; return srv.fetch(ctx) }})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, _ = src.Refresh(t.Context())
	}
	if calls != 1 || src.Generation() != 1 {
		t.Fatalf("calls %d generation %d", calls, src.Generation())
	}
}

func TestPersistAndFetchFailures(t *testing.T) {
	k, pub := key()
	dir := t.TempDir()
	srv := &served{sd: pinDecree(t, k, cluster, 4, img(5))}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch, MinInterval: time.Nanosecond,
		StateFile: filepath.Join(dir, "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	// The state file cannot be written: the decree is not taken.
	if err := os.Mkdir(filepath.Join(dir, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); changed || err == nil {
		t.Fatalf("a decree that could not be persisted was taken: %v %v", changed, err)
	}
	if _, ok := src.Epoch(); ok || src.Generation() != 0 {
		t.Fatal("pins moved")
	}
	failing, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond,
		Fetch: func(context.Context) (*cdsha.SignedDecree, error) { return nil, errors.New("down") }})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := failing.Refresh(t.Context()); changed || err == nil {
		t.Fatal("a failed fetch changed the pins")
	}
}

// A node launched after a decree carries its base epoch as a floor: an older
// decree the operator also signed, replayed by the control plane, is refused
// although the node has no state of its own yet.
func TestPinFloorRefusesOlderDecrees(t *testing.T) {
	k, pub := key()
	srv := &served{sd: pinDecree(t, k, cluster, 3, img(1), img(5))}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch, MinInterval: time.Nanosecond, MinEpoch: 4})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); changed || !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("replayed older decree: %v %v", changed, err)
	}
	srv.sd = pinDecree(t, k, cluster, 4, img(5))
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("decree at the floor: %v %v", changed, err)
	}
	// A state file from before a relaunch with a higher floor is ignored,
	// not fatal.
	state := filepath.Join(t.TempDir(), "state.json")
	old, _ := json.Marshal(pinState{InForce: pinDecree(t, k, cluster, 3, img(1))})
	if err := os.WriteFile(state, old, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch, StateFile: state, MinEpoch: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Epoch(); ok {
		t.Fatal("a state decree below the floor was taken")
	}
}

// Two images built on one firmware share their MRTD and differ only in their
// RTMRs (found on TDX: the "A and B" decree was refused for duplicate pin
// names, so nodes never trusted B until "B only").
func TestImagesSharingAnMRTD(t *testing.T) {
	k, pub := key()
	a, b := img(1), img(1)
	b.RTMR1, b.RTMR2 = img(7).RTMR1, img(7).RTMR2
	srv := &served{sd: pinDecree(t, k, cluster, 3, a, b)}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Fetch: srv.fetch, MinInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("A and B of one firmware: %v %v", changed, err)
	}
	if n := len(src.Current().Images); n != 4 {
		t.Fatalf("%d pins, want 2 images under 2 keys", n)
	}
}

// A node takes the decree the replicas applied: it asks a replica it pins
// first, and fetches unverified only when none answers. A decree taken
// unverified that the replicas never applied (signed, then rejected) is
// replaced by theirs at the next attested fetch, though both name one base
// epoch; an unverified fetch never moves sideways or back.
func TestRefreshPrefersTheReplicasDecree(t *testing.T) {
	k, pub := key()
	var (
		attested   *cdsha.SignedDecree
		attestErr  error
		unverified = &served{}
		asked      refvalues.ReferenceValues
		fetches    int
	)
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond,
		Attested: func(_ context.Context, pins refvalues.ReferenceValues) (*cdsha.SignedDecree, error) {
			asked = pins
			return attested, attestErr
		},
		Fetch: func(ctx context.Context) (*cdsha.SignedDecree, error) { fetches++; return unverified.fetch(ctx) }})
	if err != nil {
		t.Fatal(err)
	}
	held := pinDecree(t, k, cluster, 4, img(1))
	attested = held
	if changed, err := src.Refresh(t.Context()); !changed || err != nil || fetches != 0 {
		t.Fatalf("attested decree: %v %v, unverified fetches %d", changed, err, fetches)
	}
	// No replica under the current pins answers: the unverified fetch
	// serves a decree the replicas rejected. It is newer, so it is taken.
	rejected := pinDecree(t, k, cluster, 5, img(9))
	attested, attestErr, unverified.sd = nil, errors.New("handshake: not pinned"), rejected
	if changed, err := src.Refresh(t.Context()); !changed || err != nil || fetches != 1 {
		t.Fatalf("fallback: %v %v, fetches %d", changed, err, fetches)
	}
	// A replica under the taken pins answers with the decree it applied at
	// the same base epoch: that one wins.
	applied := pinDecree(t, k, cluster, 5, img(5))
	attested, attestErr = applied, nil
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("replicas' decree at the same epoch: %v %v", changed, err)
	}
	if len(asked.Images) != 2 || hex.EncodeToString(asked.Images[0].Digest) != img(9).MRTD {
		t.Fatalf("attested fetch asked under %+v, want the taken decree's pins", asked.Images)
	}
	if cur := src.Current(); hex.EncodeToString(cur.Images[0].Digest) != img(5).MRTD {
		t.Fatal("the replicas' decree is not in force")
	}
	// Negative controls.
	gen := src.Generation()
	for name, c := range map[string]struct {
		attested  *cdsha.SignedDecree
		attestErr error
		served    *cdsha.SignedDecree
	}{
		"same decree again":                 {attested: applied},
		"older decree from a replica":       {attested: held},
		"replica serves none":               {attested: nil, served: pinDecree(t, k, cluster, 9, img(9))},
		"unverified, same epoch, other one": {attestErr: errors.New("down"), served: rejected},
		"unverified, older":                 {attestErr: errors.New("down"), served: held},
	} {
		attested, attestErr, unverified.sd = c.attested, c.attestErr, c.served
		if changed, err := src.Refresh(t.Context()); changed || err != nil || src.Generation() != gen {
			t.Fatalf("%s: changed %v, %v", name, changed, err)
		}
	}
	// The floor holds on the attested path too.
	floored, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond, MinEpoch: 5,
		Attested: func(context.Context, refvalues.ReferenceValues) (*cdsha.SignedDecree, error) { return held, nil },
		Fetch:    unverified.fetch})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := floored.Refresh(t.Context()); changed || !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("attested decree below the floor: %v %v", changed, err)
	}
}

// The attested fetch takes no answer from a CDS that does not pass the
// pins: a plain TLS server that the unverified fetch reads is refused.
func TestAttestedHTTPFetchRefusesAnUnattestedCDS(t *testing.T) {
	k, _ := key()
	sd := pinDecree(t, k, cluster, 4, img(5))
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(sd) }))
	defer ts.Close()
	if got, err := HTTPFetch(ts.URL)(t.Context()); err != nil || got == nil {
		t.Fatalf("unverified fetch: %v %v", got, err)
	}
	if got, err := AttestedHTTPFetch(ts.URL, "http://127.0.0.1:1")(t.Context(), bootstrap()); err == nil || got != nil {
		t.Fatalf("attested fetch took an unattested answer: %+v", got)
	}
}

// A signed decree the replicas never applied, with a base epoch above
// theirs, taken over the unverified path while the attested one is blocked,
// is replaced by the replicas' decree at the next attested fetch.
func TestAttestedReplacesAnUnverifiedHigherEpoch(t *testing.T) {
	k, pub := key()
	host := &served{}
	var attestedUp bool
	replicas := pinDecree(t, k, cluster, 7, img(5))
	attested := func(context.Context, refvalues.ReferenceValues) (*cdsha.SignedDecree, error) {
		if !attestedUp {
			return nil, errors.New("host blocks the pinned CDS")
		}
		return replicas, nil
	}
	src, err := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Attested: attested, Fetch: host.fetch, MinInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	host.sd = pinDecree(t, k, cluster, 1000, img(9))
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("unverified high epoch not taken: %v %v", changed, err)
	}
	attestedUp = true
	changed, err := src.Refresh(t.Context())
	if e, _ := src.Epoch(); e != 7 || !changed || err != nil {
		t.Fatalf("replicas serve epoch 7 over the attested path, node keeps epoch %d (changed=%v err=%v)", e, changed, err)
	}
	// Now attested: the unverified path takes only a newer one again.
	host.sd = pinDecree(t, k, cluster, 6, img(9))
	attestedUp = false
	if changed, _ := src.Refresh(t.Context()); changed {
		t.Fatal("unverified older decree taken over an attested one")
	}
}

// The provisional decree pins images no replica runs, so no handshake under
// it succeeds: the client asks under the last attested pins, and takes that
// answer only at or above the last attested base epoch.
func TestProvisionalDecreeAskedUnderTheLastAttestedPins(t *testing.T) {
	k, pub := key()
	host := &served{}
	running := img(5) // the image the replicas run
	var answer *cdsha.SignedDecree
	var asked []string
	attested := func(_ context.Context, pins refvalues.ReferenceValues) (*cdsha.SignedDecree, error) {
		for _, p := range pins.Images {
			if hex.EncodeToString(p.Digest) == running.MRTD {
				asked = append(asked, "running")
				return answer, nil
			}
		}
		asked = append(asked, "other")
		return nil, errors.New("handshake: not pinned")
	}
	cfg := Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), Attested: attested, Fetch: host.fetch, MinInterval: time.Nanosecond,
		StateFile: filepath.Join(t.TempDir(), "state.json")}
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Bootstrap pins image 1, the replicas run 5: the unverified path
	// delivers their decree, then the attested path confirms it.
	answer = pinDecree(t, k, cluster, 7, running)
	host.sd = answer
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("rollout decree: %v %v", changed, err)
	}
	if changed, err := src.Refresh(t.Context()); changed || err != nil {
		t.Fatalf("confirming the same decree changed the pins: %v %v", changed, err)
	}
	// The host blocks the replicas and serves a signed decree pinning only
	// image 9 at a higher epoch.
	host.sd = pinDecree(t, k, cluster, 1000, img(9))
	block := answer
	answer = nil
	running = img(14) // nothing passes: every attested ask fails
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("unverified high epoch: %v %v", changed, err)
	}
	running = img(5)
	// A replica under the last attested pins replays an older decree:
	// refused, also after a restart of the client.
	answer = pinDecree(t, k, cluster, 6, running)
	for _, s := range []*Source{src, mustNew(t, cfg)} {
		asked = nil
		if changed, _ := s.Refresh(t.Context()); changed {
			t.Fatal("attested decree below the last attested epoch taken")
		}
		if e, _ := s.Epoch(); e != 1000 {
			t.Fatalf("epoch %d", e)
		}
		if len(asked) != 2 || asked[0] != "other" || asked[1] != "running" {
			t.Fatalf("asked %v, want the provisional pins, then the last attested ones", asked)
		}
	}
	// The replicas' decree, at the last attested epoch, replaces it; the
	// restarted client too.
	answer = block
	for _, s := range []*Source{mustNew(t, cfg), src} {
		if changed, err := s.Refresh(t.Context()); !changed || err != nil {
			t.Fatalf("replicas' decree under the last attested pins: %v %v", changed, err)
		}
		if e, _ := s.Epoch(); e != 7 {
			t.Fatalf("epoch %d, want the replicas' 7", e)
		}
	}
}

func mustNew(t *testing.T, cfg Config) *Source {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
