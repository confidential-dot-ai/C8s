package workloadclaims

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testPodClaims(t *testing.T) PodClaims {
	t.Helper()
	d := "sha256:" + strings.Repeat("a", 64)
	return PodClaims{Version: 1, BootID: strings.Repeat("b", 64), AssignedPodUID: "assigned", RuntimePodUID: "runtime", SandboxID: "sandbox", Revision: 1,
		RuntimeExtensions: []string{d}, Containers: []PodContainer{{Digest: d}}}
}

// The canonical bytes survive the outer JSON unchanged, carry image digests
// only, and sort the containers by digest whatever order the guest listed.
func TestPodClaimsTransportPreservesExactBytes(t *testing.T) {
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
	if _, err := DecodePodClaims(req.PodClaims); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"argv", "env", "mounts", "role"} {
		if bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatalf("pod claims carry a %s observation", field)
		}
	}
	b := "sha256:" + strings.Repeat("b", 64)
	ordered := testPodClaims(t)
	ordered.RuntimeExtensions = append(ordered.RuntimeExtensions, b)
	ordered.Containers = []PodContainer{{Digest: b}, {Digest: ordered.RuntimeExtensions[0]}}
	wire, err := ordered.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePodClaims(wire); err != nil {
		t.Fatalf("canonical bytes do not decode: %v", err)
	}
	if !bytes.Contains(wire, []byte(`"containers":[{"digest":"`+ordered.RuntimeExtensions[0]+`"},{"digest":"`+b+`"}]`)) {
		t.Fatalf("containers are not sorted by digest: %s", wire)
	}
}

// Incomplete history and alternate, ambiguous or unknown
// JSON are refused.
func TestPodClaimsRejectAmbiguousAndIncompleteHistory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*PodClaims)
	}{
		{"version", func(p *PodClaims) { p.Version++ }},
		{"boot", func(p *PodClaims) { p.BootID = "chosen" }},
		{"invalid digest", func(p *PodClaims) { p.Containers[0].Digest = "sha256:short" }},
		{"no containers", func(p *PodClaims) { p.Containers = nil }},
		{"duplicate log", func(p *PodClaims) { p.RuntimeExtensions = append(p.RuntimeExtensions, p.RuntimeExtensions[0]) }},
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
		bytes.Replace(raw, []byte(`"digest":`), []byte(`"argv":["/app"],"digest":`), 1),
	} {
		if _, err := DecodePodClaims(malformed); err == nil {
			t.Fatal("accepted alternate/ambiguous JSON")
		}
	}
}

// The report-data binding covers the CSR key, the challenge and the
// claims, and a node quote cannot satisfy it.
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
		func(p *PodClaims) { p.Revision++ }, func(p *PodClaims) { p.SandboxID = "other" },
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
