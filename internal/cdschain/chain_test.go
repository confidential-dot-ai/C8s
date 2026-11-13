package cdschain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func key(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PublicKeyPEM(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, p
}

var build = Build{Measurements: testutil.CDSPinDocument(strings.Repeat("a1", 48), "launch"), Version: "v1.0.0"}

type fixture struct {
	op, member *ecdsa.PrivateKey
	opPEM      string
	members    []string
	state      *State
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{}
	f.op, f.opPEM = key(t)
	var mPEM string
	f.member, mPEM = key(t)
	_, m1 := key(t)
	_, m2 := key(t)
	_, ca := key(t)
	f.members = []string{mPEM, m1, m2}
	g, err := Sign(f.op, Body{Cluster: "lane", Type: TypeGenesis, Payload: mustJSON(t, Genesis{
		Endpoints: []string{"a:1", "b:1", "c:1"}, Members: f.members, OperatorKeys: f.opPEM, CAKey: ca, Accepted: []Build{build},
	})})
	if err != nil {
		t.Fatal(err)
	}
	if f.state, err = VerifyGenesis(g); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestApply is one row per rule an entry must pass; each row must refuse.
func TestApply(t *testing.T) {
	f := newFixture(t)
	_, stranger := key(t)
	strangerKey, _ := key(t)
	unbound := Build{Measurements: `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + strings.Repeat("b2", 48) + `"}]}`, Version: "v1.1.0"}
	next := func(typ Type, payload any) Body {
		return Body{Cluster: "lane", Seq: 1, Prev: f.state.Head.Hash, Type: typ, Payload: mustJSON(t, payload)}
	}
	ok := next(TypeOperatorKeys, OperatorKeys{Keys: f.opPEM})
	for _, tc := range []struct {
		name string
		key  *ecdsa.PrivateKey
		body Body
		raw  []byte
	}{
		{"wrong seq", f.op, func() Body { b := ok; b.Seq = 2; return b }(), nil},
		{"wrong prev", f.op, func() Body { b := ok; b.Prev = Hash{1}; return b }(), nil},
		{"other cluster", f.op, func() Body { b := ok; b.Cluster = "other"; return b }(), nil},
		{"not an operator", strangerKey, ok, nil},
		{"member signs a policy", f.member, next(TypeOperatorKeys, OperatorKeys{Keys: f.opPEM}), nil},
		{"member slot out of range", f.member, next(TypeMember, Member{Slot: 3, Key: stranger}), nil},
		{"member key twice", f.op, next(TypeMember, Member{Slot: 1, Key: f.members[0]}), nil},
		{"empty accepted set", f.op, next(TypeAccepted, Accepted{}), nil},
		{"build binds no launch file", f.op, next(TypeAccepted, Accepted{Accepted: []Build{unbound}}), nil},
		{"build twice", f.op, next(TypeAccepted, Accepted{Accepted: []Build{build, build}}), nil},
		{"version not semver", f.op, next(TypeAccepted, Accepted{Accepted: []Build{{Measurements: build.Measurements, Version: "1.0"}}}), nil},
		{"nodes bind no launch", f.op, next(TypeNodes, Nodes{Nodes: unbound.Measurements}), nil},
		{"nodes name no image", f.op, next(TypeNodes, Nodes{Nodes: `{"schema_version":"2","tee":"sev-snp","measurements":[]}`}), nil},
		{"nodes not a measurements document", f.op, next(TypeNodes, Nodes{Nodes: "{}"}), nil},
		{"member writes nodes", f.member, next(TypeNodes, Nodes{Nodes: build.Measurements}), nil},
		{"policy not canonical", f.op, next(TypePolicy, Policy{Allowlist: json.RawMessage(`{"workloads":{} }`)}), nil},
		{"unknown type", f.op, next("raise-floor", Accepted{}), nil},
		{"second genesis", f.op, next(TypeGenesis, Genesis{}), nil},
		{"unknown field", f.op, Body{}, []byte(`{"v":1,"cluster":"lane","seq":1,"prev":"` + f.state.Head.Hash.String() + `","type":"operator-keys","payload":{"keys":` + string(mustJSON(t, f.opPEM)) + `},"x":1}`)},
		{"duplicate key", f.op, Body{}, []byte(`{"v":1,"v":1,"cluster":"lane","seq":1,"prev":"` + f.state.Head.Hash.String() + `","type":"operator-keys","payload":{"keys":` + string(mustJSON(t, f.opPEM)) + `}}`)},
	} {
		e, err := Sign(tc.key, tc.body)
		if err != nil {
			t.Fatal(err)
		}
		if tc.raw != nil {
			e = signRaw(t, tc.key, tc.raw)
		}
		if _, err := f.state.Apply(e); err == nil {
			t.Errorf("%s: applied", tc.name)
		}
	}
	e, _ := Sign(f.op, ok)
	if _, err := f.state.Apply(e); err != nil {
		t.Fatalf("negative control: %v", err)
	}
	raw := signRaw(t, f.op, []byte(`{"v":1,"cluster":"lane","seq":1,"prev":"`+f.state.Head.Hash.String()+`","type":"operator-keys","payload":{"keys":`+string(mustJSON(t, f.opPEM))+`}}`))
	if _, err := f.state.Apply(raw); err != nil {
		t.Fatalf("negative control (raw): %v", err)
	}
	e, _ = Sign(f.op, next(TypeNodes, Nodes{Nodes: build.Measurements}))
	if s, err := f.state.Apply(e); err != nil || s.Nodes != build.Measurements {
		t.Fatalf("a nodes entry binding its launch: %v", err)
	}
	e, _ = Sign(f.member, next(TypeMember, Member{Slot: 1, Key: stranger}))
	if _, err := f.state.Apply(e); err != nil {
		t.Fatalf("a member may name a slot's member: %v", err)
	}
}

func signRaw(t *testing.T, k *ecdsa.PrivateKey, body []byte) Entry {
	t.Helper()
	sig, err := operatorauth.SignDetached(k, append([]byte(signDomain), body...))
	if err != nil {
		t.Fatal(err)
	}
	return Entry{Body: body, Sig: sig}
}

func TestGenesisRules(t *testing.T) {
	op, opPEM := key(t)
	_, m := key(t)
	for name, g := range map[string]Genesis{
		"two endpoints":     {Endpoints: []string{"a:1", "b:1"}, Members: []string{m, m}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}},
		"members short":     {Endpoints: []string{"a:1"}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}},
		"no accepted build": {Endpoints: []string{"a:1"}, Members: []string{m}, OperatorKeys: opPEM, CAKey: m},
	} {
		e, _ := Sign(op, Body{Cluster: "lane", Type: TypeGenesis, Payload: mustJSON(t, g)})
		if _, err := VerifyGenesis(e); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	other, _ := key(t)
	e, _ := Sign(other, Body{Cluster: "lane", Type: TypeGenesis, Payload: mustJSON(t, Genesis{Endpoints: []string{"a:1"}, Members: []string{m}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}})})
	if _, err := VerifyGenesis(e); err == nil {
		t.Error("a genesis not signed by its own operator keys verified")
	}
}

// The hash covers the body only: a second signature names the same entry.
func TestHashIgnoresSignature(t *testing.T) {
	f := newFixture(t)
	b := Body{Cluster: "lane", Seq: 1, Prev: f.state.Head.Hash, Type: TypeOperatorKeys, Payload: mustJSON(t, OperatorKeys{Keys: f.opPEM})}
	e1, _ := Sign(f.op, b)
	e2, _ := Sign(f.op, b)
	if e1.Sig == e2.Sig || e1.Hash() != e2.Hash() {
		t.Fatal("re-signing changed the entry's identity, or ECDSA is deterministic")
	}
}
