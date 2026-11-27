package cdschain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
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

// p384PEM is a key a member never has: replicas make P-256 member keys.
func p384PEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PublicKeyPEM(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var build = Build{Measurements: testutil.TAPinDocument(strings.Repeat("a1", 48), "launch"), Version: "v1.0.0"}

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
	unbound := Build{Measurements: `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"ta","measurement":"` + strings.Repeat("b2", 48) + `"}]}`, Version: "v1.1.0"}
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
		{"member key not P-256", f.op, next(TypeMember, Member{Slot: 1, Key: p384PEM(t)}), nil},
		{"empty accepted set", f.op, next(TypeAccepted, Accepted{}), nil},
		{"build binds no launch file", f.op, next(TypeAccepted, Accepted{Accepted: []Build{unbound}}), nil},
		{"build twice", f.op, next(TypeAccepted, Accepted{Accepted: []Build{build, build}}), nil},
		{"version not semver", f.op, next(TypeAccepted, Accepted{Accepted: []Build{{Measurements: build.Measurements, Version: "1.0"}}}), nil},
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
	e, _ = Sign(f.member, next(TypeMember, Member{Slot: 1, Key: stranger}))
	if _, err := f.state.Apply(e); err != nil {
		t.Fatalf("a member may name a slot's member: %v", err)
	}
}

func TestAcceptedBuildsCheckTheirOwnFamily(t *testing.T) {
	register := `"` + strings.Repeat("b2", 48) + `"`
	tdx := func(rtmr1, rtmr2 string) Build {
		return Build{
			Measurements: fmt.Sprintf(`{"schema_version":"2","tee":"tdx","measurements":[{"name":"ta","mrtd":%q,"rtmr":[null,%s,%s,null],"launch_file":"launch"}]}`, testutil.TestMeasurement, rtmr1, rtmr2),
			Version:      "v1.1.0",
		}
	}
	missing1, missing2 := tdx("null", register), tdx(register, "null")
	complete := tdx(register, register)
	otherLaunch := Build{
		Measurements: testutil.TAPinDocument(testutil.TestMeasurement, "another launch"),
		Version:      "v1.2.0",
	}
	for _, tc := range []struct {
		name   string
		builds []Build
		want   string
	}{
		{
			name:   "missing RTMR1",
			builds: []Build{missing1},
			want:   "RTMR[1]",
		},
		{
			name:   "missing RTMR2",
			builds: []Build{missing2},
			want:   "RTMR[2]",
		},
		{
			name:   "complete TDX",
			builds: []Build{complete},
		},
		{
			name:   "missing RTMR1 before SNP",
			builds: []Build{missing1, build},
			want:   "RTMR[1]",
		},
		{
			name:   "missing RTMR1 after SNP",
			builds: []Build{build, missing1},
			want:   "RTMR[1]",
		},
		{
			name:   "missing RTMR2 before SNP",
			builds: []Build{missing2, build},
			want:   "RTMR[2]",
		},
		{
			name:   "missing RTMR2 after SNP",
			builds: []Build{build, missing2},
			want:   "RTMR[2]",
		},
		{
			name:   "complete TDX before SNP",
			builds: []Build{complete, build},
			want:   "different TEE families",
		},
		{
			name:   "complete TDX after SNP",
			builds: []Build{build, complete},
			want:   "different TEE families",
		},
		{
			name:   "different launch files",
			builds: []Build{build, otherLaunch},
			want:   "another configuration",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			head, accepted := f.state.Head, slices.Clone(f.state.Accepted)
			for _, typ := range []Type{TypeGenesis, TypeAccepted} {
				t.Run(string(typ), func(t *testing.T) {
					body := Body{Cluster: f.state.Cluster, Type: typ}
					if typ == TypeGenesis {
						body.Payload = mustJSON(t, Genesis{
							Endpoints:    f.state.Endpoints,
							Members:      f.members,
							OperatorKeys: f.opPEM,
							CAKey:        f.opPEM,
							Accepted:     tc.builds,
						})
					} else {
						body.Seq, body.Prev = f.state.Head.Seq+1, f.state.Head.Hash
						body.Payload = mustJSON(t, Accepted{Accepted: tc.builds})
					}
					entry, err := Sign(f.op, body)
					if err != nil {
						t.Fatal(err)
					}
					var state *State
					if typ == TypeGenesis {
						state, err = VerifyGenesis(entry)
					} else {
						state, err = f.state.Apply(entry)
					}
					if tc.want == "" {
						if err != nil {
							t.Fatalf("valid accepted builds refused: %v", err)
						}
					} else if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("error = %v, want %q", err, tc.want)
					}
					if tc.want != "" && (state != nil || f.state.Head != head || !slices.Equal(f.state.Accepted, accepted)) {
						t.Fatal("rejected builds returned a state or changed the prior head or accepted builds")
					}
				})
			}
		})
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
	p384 := p384PEM(t)
	for name, g := range map[string]Genesis{
		"member key not P-256": {Endpoints: []string{"a:1"}, Members: []string{p384}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}},
		"two endpoints":        {Endpoints: []string{"a:1", "b:1"}, Members: []string{m, m}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}},
		"members short":        {Endpoints: []string{"a:1"}, OperatorKeys: opPEM, CAKey: m, Accepted: []Build{build}},
		"no accepted build":    {Endpoints: []string{"a:1"}, Members: []string{m}, OperatorKeys: opPEM, CAKey: m},
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
