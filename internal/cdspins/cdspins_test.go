package cdspins

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func key(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
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
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
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
	k, pub := key(t)
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
	anchors := map[string]int{}
	for _, p := range cur.Images {
		anchors[string(p.Anchor)]++
		if len(p.Registers) != 2 {
			t.Fatalf("pin %s registers %v", p.Name, p.Registers)
		}
	}
	if anchors[string(serverKey)] != 2 || anchors[string(cdsKey)] != 2 {
		t.Fatalf("anchors %v", anchors)
	}
	// B only.
	srv.sd = pinDecree(t, k, cluster, 4, img(5))
	if changed, _ := src.Refresh(t.Context()); !changed || len(src.Current().Images) != 2 {
		t.Fatal("B only not taken")
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
	k, pub := key(t)
	other, _ := key(t)
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
// a restart is refused too, and readers of the policy file see the set.
func TestStateSurvivesRestart(t *testing.T) {
	k, pub := key(t)
	dir := t.TempDir()
	cfg := Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond,
		StateFile: filepath.Join(dir, "state.json"), PolicyFile: filepath.Join(dir, "cds.json")}
	srv := &served{sd: pinDecree(t, k, cluster, 4, img(5))}
	cfg.Fetch = srv.fetch
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatal(changed, err)
	}
	onDisk, err := refvalues.Load(cfg.PolicyFile)
	if err != nil || len(onDisk.Images) != 2 {
		t.Fatalf("policy file: %v %d", err, len(onDisk.Images))
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
	k, _ := key(t)
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
	if _, err := HTTPFetch("https://127.0.0.1:1")(t.Context()); err == nil {
		t.Fatal("unreachable accepted")
	}
	if _, err := HTTPFetch("::bad")(t.Context()); err == nil {
		t.Fatal("bad URL accepted")
	}
}

func TestNewAndPolicyErrors(t *testing.T) {
	k, pub := key(t)
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
	other, _ := key(t)
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
	// The policy file cannot be written: the decree is not taken.
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	src2, _ := New(Config{ClusterID: cluster, DecreeKey: pub, Bootstrap: bootstrap(), MinInterval: time.Nanosecond,
		Fetch: srv.fetch, PolicyFile: filepath.Join(ro, "sub", "cds.json")})
	if changed, err := src2.Refresh(t.Context()); changed || err == nil {
		if os.Geteuid() != 0 {
			t.Fatalf("unwritable policy file: %v %v", changed, err)
		}
	}
}
