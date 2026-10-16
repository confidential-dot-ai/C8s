package cdsha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

const testCluster = "tenant-a"

func mustCA(t *testing.T) *issuer.CA {
	t.Helper()
	ca, err := issuer.NewCAWithCurve("test", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func operatorKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

// genesisDecree signs a Genesis decree with the test operator key.
func genesisDecree(t *testing.T) SignedDecree {
	t.Helper()
	opKey, _ := testOp()
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: fmt.Sprint("g", intentSeq.Add(1)), ExpiresAt: time.Now().Add(time.Hour), Kind: Genesis}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

// genesisState builds an epoch-0 state the way genesis does. op must be the
// test operator key for the chain to verify.
func genesisState(t *testing.T, term uint64, op []byte) State {
	t.Helper()
	ca := mustCA(t)
	g := genesisDecree(t)
	s, err := SignRecord(Record{ClusterID: testCluster, Term: term, RootCert: ca.Cert.Raw, Measurements: []string{"m1"}, OperatorPubKey: op,
		AppliedDecrees: []string{g.Decree.IntentID}, Decree: &g}, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return State{Chain: Chain{s}, Key: ca.Key}
}

// testOp is the operator key every test chain is born with.
var testOp = sync.OnceValues(func() (*ecdsa.PrivateKey, []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, der
})

func opPub() []byte { _, p := testOp(); return p }

var intentSeq atomic.Int64

// extend applies a decree the way the writer does (nextState).
func extend(t *testing.T, st State, rotate bool, pins ...string) State {
	t.Helper()
	prev := st.Chain[len(st.Chain)-1]
	kind := UpdateMeasurements
	if rotate {
		kind = RotateKey
	} else if len(pins) == 0 {
		pins = prev.Record.Measurements
	}
	opKey, _ := testOp()
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: fmt.Sprint("i", intentSeq.Add(1)), BaseEpoch: prev.Record.Epoch,
		ExpiresAt: time.Now().Add(time.Hour), Kind: kind, Measurements: pins}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	rec := prev.Record
	rec.Epoch++
	rec.PrevEpochHash = prev.Hash()
	rec.AppliedDecrees = append(slices.Clone(rec.AppliedDecrees), sd.Decree.IntentID)
	rec.Decree = &sd
	if len(sd.Decree.Measurements) > 0 {
		rec.Measurements = sd.Decree.Measurements
	}
	key := st.Key
	if rotate {
		ca := mustCA(t)
		rec.RootCert, key = ca.Cert.Raw, ca.Key
	}
	s, err := SignRecord(rec, st.Key)
	if err != nil {
		t.Fatal(err)
	}
	return State{Chain: append(append(Chain{}, st.Chain...), s), Key: key}
}

func TestChainVerifyAcceptsGenuineChain(t *testing.T) {
	st := extend(t, extend(t, genesisState(t, 0, opPub()), false, "m1", "m2"), true)
	if err := st.Chain.Verify(testCluster); err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifyRejectsTampering(t *testing.T) {
	base := extend(t, extend(t, genesisState(t, 0, opPub()), false, "m1", "m2"), true)
	other := genesisState(t, 0, opPub())
	cases := map[string]func(c Chain){
		"field changed after signing": func(c Chain) { c[1].Record.Measurements = []string{"evil"} },
		"wrong cluster":               func(c Chain) { c[0].Record.ClusterID = "tenant-b" },
		"record dropped":              func(c Chain) { c[1] = c[2] },
		"root swapped at epoch 0":     func(c Chain) { c[0] = other.Chain[0] },
		"signature stripped":          func(c Chain) { c[2].Signature = nil },
		"decree stripped":             func(c Chain) { c[1].Record.Decree = nil },
		"genesis decree stripped":     func(c Chain) { c[0].Record.Decree = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := append(Chain{}, base.Chain...)
			mutate(c)
			if err := c.Verify(testCluster); err == nil {
				t.Fatal("tampered chain verified")
			}
		})
	}
	if err := base.Chain.Verify("tenant-b"); err == nil {
		t.Fatal("chain verified for another cluster (CI2)")
	}
}

func TestNextOrdering(t *testing.T) {
	g := genesisState(t, 1, opPub())
	e1 := extend(t, g, false, "m1", "m2")

	if _, out, err := Next(State{}, g, testCluster); err != nil || out != Adopted {
		t.Fatalf("cold start: %v %v", out, err)
	}
	if _, out, err := Next(g, e1, testCluster); err != nil || out != Extended {
		t.Fatalf("extend: %v %v", out, err)
	}
	if _, _, err := Next(e1, g, testCluster); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("rollback accepted: %v", err) // E1, E5
	}
	if _, _, err := Next(e1, e1, testCluster); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("equal tuple accepted: %v", err)
	}
	// A joined replica never adopts a fork, however high its tuple (Q1
	// interim, review #1/#5): neither another genesis nor a sibling epoch.
	otherGenesis := extend(t, extend(t, genesisState(t, 9, opPub()), false), false)
	if _, _, err := Next(e1, otherGenesis, testCluster); !errors.Is(err, ErrFork) {
		t.Fatalf("higher fork from another genesis: %v", err)
	}
	sibling := extend(t, g, true) // a rival RotateKey at epoch 1
	sibling = extend(t, sibling, false)
	if _, _, err := Next(e1, sibling, testCluster); !errors.Is(err, ErrFork) {
		t.Fatalf("higher sibling branch: %v", err)
	}
}

func TestNextRequiresKeyForTail(t *testing.T) {
	g := genesisState(t, 0, opPub())
	rot := extend(t, g, true)
	// The CDSEpoch path offers a chain without a key: fine without rotation,
	// refused across a rotation (L3).
	if _, _, err := Next(g, State{Chain: extend(t, g, false, "m1", "m2").Chain}, testCluster); err != nil {
		t.Fatalf("keyless UpdateMeasurements epoch: %v", err)
	}
	if _, _, err := Next(g, State{Chain: rot.Chain}, testCluster); err == nil {
		t.Fatal("accepted a rotated epoch without its key")
	}
	if _, _, err := Next(g, State{Chain: rot.Chain, Key: mustCA(t).Key}, testCluster); err == nil {
		t.Fatal("accepted a key that does not match root_cert (K2)")
	}
	if _, _, err := Next(State{}, State{Chain: g.Chain}, testCluster); err == nil {
		t.Fatal("cold start without a key")
	}
}

// TestHolderOfOldKeyCannotAuthorEpochs: an evicted replica keeps the key
// across UpdateMeasurements, but without an operator decree it can neither
// re-pin itself nor rotate (review #1).
func TestHolderOfOldKeyCannotAuthorEpochs(t *testing.T) {
	st := extend(t, genesisState(t, 0, opPub()), false, "bad", "good")
	st = extend(t, st, false, "good") // bad removed; bad still holds st.Key
	prev := st.Chain[len(st.Chain)-1]
	forge := func(mut func(*Record)) Chain {
		rec := prev.Record
		rec.Epoch++
		rec.PrevEpochHash = prev.Hash()
		rec.Decree = prev.Record.Decree // replay the last decree
		rec.AppliedDecrees = append(slices.Clone(rec.AppliedDecrees), "x")
		mut(&rec)
		s, err := SignRecord(rec, st.Key)
		if err != nil {
			t.Fatal(err)
		}
		return append(slices.Clone(st.Chain), s)
	}
	cases := map[string]Chain{
		"re-pin with replayed decree": forge(func(r *Record) { r.Measurements = []string{"bad", "good"} }),
		"re-pin without decree":       forge(func(r *Record) { r.Measurements = []string{"bad", "good"}; r.Decree = nil }),
		"rotate without decree": forge(func(r *Record) {
			r.Decree = nil
			r.RootCert = mustCA(t).Cert.Raw
		}),
	}
	for name, c := range cases {
		if err := c.Verify(testCluster); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}
