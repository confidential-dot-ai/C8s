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

func TestRefreshRefusesWhatTheOperatorDidNotSign(t *testing.T) {
	k, pub := key()
	other, _ := key()
	for name, sd := range map[string]*cdsha.SignedDecree{
		"other key":     pinDecree(t, other, cluster, 9, img(5)),
		"other cluster": pinDecree(t, k, "c2", 9, img(5)),
		"tampered": func() *cdsha.SignedDecree {
			sd := pinDecree(t, k, cluster, 9, img(5))
			sd.Decree.Images = []cdsha.DecreeImage{img(7)}
			return sd
		}(),
		"no images": func() *cdsha.SignedDecree {
			sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: cluster, IntentID: "i", BaseEpoch: 9, Kind: cdsha.UpdateMeasurements,
				ExpiresAt: time.Now().Add(time.Hour), Measurements: []string{"aa"}}, k)
			if err != nil {
				t.Fatal(err)
			}
			return &sd
		}(),
		"pins not the images": func() *cdsha.SignedDecree {
			p, _ := img(1).Pin()
			sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: cluster, IntentID: "i", BaseEpoch: 9, Kind: cdsha.UpdateMeasurements,
				ExpiresAt: time.Now().Add(time.Hour), Measurements: []string{p}, Images: []cdsha.DecreeImage{img(5)}}, k)
			if err != nil {
				t.Fatal(err)
			}
			return &sd
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			srv := &served{sd: sd}
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
		})
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
	bad, _ := json.Marshal(pinDecree(t, other, cluster, 3, img(5)))
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
	// No anchors in the bootstrap: images are pinned without one.
	pol, err := Policy(refvalues.ReferenceValues{Family: teetypes.FamilyTDX}, []cdsha.DecreeImage{img(1)})
	if err != nil || len(pol.Images) != 1 || pol.Images[0].Anchor != nil {
		t.Fatalf("anchorless: %+v %v", pol, err)
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
	old, _ := json.Marshal(pinDecree(t, k, cluster, 3, img(1)))
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
