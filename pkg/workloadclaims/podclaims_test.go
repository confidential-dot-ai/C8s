package workloadclaims

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testPodClaims(t *testing.T) PodClaims {
	t.Helper()
	env, err := allowlist.ObserveEnv([]string{"MESSAGE=<>&\u2028\u2029"})
	if err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	return PodClaims{Version: 1, BootID: strings.Repeat("b", 64), AssignedPodUID: "assigned", RuntimePodUID: "runtime", SandboxID: "sandbox", Revision: 1,
		RuntimeExtensions: []string{d}, Containers: []SandboxContainer{{Digest: d, Argv: []string{"/app", "<>&\u2028\u2029"}, Env: env, Mounts: []allowlist.ObservedMount{{Destination: "/data", Volume: "data", Source: "/private/guest/path", Class: allowlist.MountData, Storage: allowlist.MountMemory}}}}}
}

func TestPodClaimsTransportPreservesExactBindingAndVolume(t *testing.T) {
	p := testPodClaims(t)
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(types.AttestRequestBody{PodClaims: raw})
	if err != nil {
		t.Fatal(err)
	}
	var req types.AttestRequestBody
	if err := json.Unmarshal(encoded, &req); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, req.PodClaims) {
		t.Fatal("outer JSON changed the hashed claims bytes")
	}
	decoded, err := DecodePodClaims(req.PodClaims)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Containers[0].Key() != p.Containers[0].Key() || decoded.Containers[0].Mounts[0].Volume != "data" {
		t.Fatal("volume identity lost in Pod profile")
	}
	if bytes.Contains(raw, []byte("/private/guest")) {
		t.Fatal("host source path leaked")
	}
	legacy, err := json.Marshal(p.Containers[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacy, []byte(`"volume"`)) {
		t.Fatal("Pod adapter changed legacy node callback schema")
	}
	other := testPodClaims(t)
	other.Containers[0].Mounts[0].Volume = "other"
	if other.Containers[0].Key() == p.Containers[0].Key() {
		t.Fatal("different volume collapsed into one historical admission")
	}
}

func TestPodClaimsRejectAmbiguousAndIncompleteHistory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*PodClaims)
	}{
		{"version", func(p *PodClaims) { p.Version++ }},
		{"boot", func(p *PodClaims) { p.BootID = "chosen" }},
		{"missing argv", func(p *PodClaims) { p.Containers[0].Argv = nil }},
		{"missing env", func(p *PodClaims) { p.Containers[0].Env = nil }},
		{"invalid env", func(p *PodClaims) { p.Containers[0].Env.Digest = "invalid" }},
		{"lossy argv", func(p *PodClaims) { p.Containers[0].Argv = []string{string([]byte{0xff})} }},
		{"missing mounts", func(p *PodClaims) { p.Containers[0].Mounts = nil }},
		{"duplicate log", func(p *PodClaims) { p.RuntimeExtensions = append(p.RuntimeExtensions, p.RuntimeExtensions[0]) }},
		{"duplicate admission", func(p *PodClaims) { p.Containers = append(p.Containers, p.Containers[0]) }},
		{"omitted measurement", func(p *PodClaims) { p.RuntimeExtensions = nil }},
		{"unobserved measurement", func(p *PodClaims) {
			p.RuntimeExtensions = append(p.RuntimeExtensions, "sha256:"+strings.Repeat("c", 64))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPodClaims(t)
			tc.change(&p)
			if _, err := p.Canonical(); err == nil {
				t.Fatal("accepted invalid history")
			}
		})
	}
	raw, _ := testPodClaims(t).Canonical()
	for _, malformed := range [][]byte{
		[]byte("null"), append([]byte(" "), raw...), append(append([]byte{}, raw...), []byte("{}")...),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"unknown":1,"version":1`), 1),
	} {
		if _, err := DecodePodClaims(malformed); err == nil {
			t.Fatal("accepted alternate/ambiguous JSON")
		}
	}
}

func TestPodReportDataSeparatesProfilesAndEveryClaim(t *testing.T) {
	p := testPodClaims(t)
	raw, _ := p.Canonical()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, 32)
	bound, err := PodReportData(&key.PublicKey, nonce, raw)
	if err != nil {
		t.Fatal(err)
	}
	node, err := armtls.ReportDataForKey(&key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bound, node[:len(bound)]) {
		t.Fatal("Pod and node profiles collide")
	}
	for _, change := range []func(*PodClaims){
		func(p *PodClaims) { p.AssignedPodUID += "x" }, func(p *PodClaims) { p.RuntimePodUID += "x" }, func(p *PodClaims) { p.SandboxID += "x" },
		func(p *PodClaims) { p.BootID = strings.Repeat("c", 64) }, func(p *PodClaims) { p.Revision++ }, func(p *PodClaims) { p.Containers[0].Argv[0] = "/other" },
		func(p *PodClaims) { p.Containers[0].Mounts[0].Volume = "other" }, func(p *PodClaims) { p.Containers[0].Role = "mesh" },
	} {
		changed := testPodClaims(t)
		change(&changed)
		wire, err := changed.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		got, err := PodReportData(&key.PublicKey, nonce, wire)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, bound) {
			t.Fatal("changed claim retained binding")
		}
	}
	nonce[0]++
	other, _ := PodReportData(&key.PublicKey, nonce, raw)
	if bytes.Equal(other, bound) {
		t.Fatal("nonce not bound")
	}
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ = PodReportData(&key2.PublicKey, nonce, raw)
	if bytes.Equal(other, bound) {
		t.Fatal("CSR key not bound")
	}
	if _, err := PodReportData(&key.PublicKey, nonce[:31], raw); err == nil {
		t.Fatal("short nonce accepted")
	}
}
