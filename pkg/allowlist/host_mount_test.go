package allowlist

import (
	"encoding/json"
	"testing"
)

func TestHostMountPolicy(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/config", Kind: MountHost, Source: "/etc/service", ReadOnly: true}}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := HostSourceDigest("/etc/service")
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := HostSourceDigest("/etc/other")
	if err != nil {
		t.Fatal(err)
	}
	good := ObservedMount{Destination: "/config", Class: MountHost, Storage: MountUnknown, HostSourceDigest: sourceDigest, ReadOnly: true}
	for _, tc := range []struct {
		name   string
		mutate func(*ObservedMount)
		want   bool
	}{
		{"pinned", func(*ObservedMount) {}, true},
		{"source", func(m *ObservedMount) { m.HostSourceDigest = otherDigest }, false},
		{"missing source", func(m *ObservedMount) { m.HostSourceDigest = "" }, false},
		{"destination", func(m *ObservedMount) { m.Destination = "/other" }, false},
		{"writable", func(m *ObservedMount) { m.ReadOnly = false }, false},
		{"class", func(m *ObservedMount) { m.Class = MountData }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := good
			tc.mutate(&m)
			if policy.admits([]ObservedMount{m}) != tc.want {
				t.Fatalf("unexpected admission for %+v", m)
			}
		})
	}
	encoded, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip ObservedMount
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !policy.admits([]ObservedMount{roundTrip}) {
		t.Fatal("serialized host evidence failed release matching")
	}
	if (mountConstraint{policy: &policy}).hostIndependent() {
		t.Fatal("pinned host content reported host-independent")
	}
	for _, source := range []string{"", "relative", "/etc/../service", "/etc/service/", "/etc/\x00service"} {
		policy.Rules[0].Source = source
		if err := normalizeMounts(&policy); err == nil {
			t.Errorf("accepted source %q", source)
		}
	}
	policy.Rules[0].Kind = MountEmptyDir
	policy.Rules[0].Source = "/etc/service"
	if err := normalizeMounts(&policy); err == nil {
		t.Fatal("accepted host fields on emptyDir")
	}
}

func TestHostSourceDigestRejectsInvalidPaths(t *testing.T) {
	for _, source := range []string{"", "relative", "/etc/../service", "/etc/service/", "/etc/\x00service"} {
		t.Run(source, func(t *testing.T) {
			if _, err := HostSourceDigest(source); err == nil {
				t.Fatalf("accepted invalid host source %q", source)
			}
		})
	}
}

func TestContentPinnedHostMount(t *testing.T) {
	const hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/nvidia-smi", Kind: MountHost, Source: "/usr/bin/nvidia-smi", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	source, _ := HostSourceDigest("/usr/bin/nvidia-smi")
	mount := ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: MountHost, HostSourceDigest: source, ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}
	for _, tc := range []struct {
		name    string
		change  func(*ObservedMount)
		allowed bool
	}{
		{"reviewed bytes", func(*ObservedMount) {}, true},
		{"old node without content evidence", func(m *ObservedMount) { m.VerityDigest = "" }, false},
		{"different bytes", func(m *ObservedMount) {
			m.VerityDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, false},
		{"different source", func(m *ObservedMount) { m.HostSourceDigest = "other" }, false},
		{"writable bind", func(m *ObservedMount) { m.ReadOnly = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := mount
			tc.change(&observed)
			if policy.admits([]ObservedMount{observed}) != tc.allowed {
				t.Fatalf("admission for %+v, want %v", observed, tc.allowed)
			}
		})
	}
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservedMount
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !policy.admits([]ObservedMount{decoded}) {
		t.Fatal("content evidence lost during serialization")
	}
	// Existing rules remain path/mode-only even if a new node supplies bytes.
	policy.Rules[0].VerityDigest = ""
	policy.Rules[0].Provenance = ""
	if !policy.admits([]ObservedMount{mount}) {
		t.Fatal("changed legacy host rule behavior")
	}
}

func TestContentPinRequiresReadOnlyHostAndCanonicalSHA256(t *testing.T) {
	for _, tc := range []struct {
		name, hash string
		kind       MountClass
		readOnly   bool
	}{
		{"short", "abc", MountHost, true},
		{"uppercase", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", MountHost, true},
		{"nonhex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", MountHost, true},
		{"prefixed", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MountHost, true},
		{"writable", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MountHost, false},
		{"emptyDir", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MountEmptyDir, false},
		{"data", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MountData, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := MountRule{Destination: "/mnt/c8s-data/tools", Kind: tc.kind, Provenance: ProvenanceFSVerity, VerityDigest: tc.hash, ReadOnly: tc.readOnly}
			if tc.kind == MountHost {
				rule.Source = "/usr/bin/nvidia-smi"
			}
			p := MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}}
			if err := normalizeMounts(&p); err == nil {
				t.Fatal("accepted invalid content pin")
			}
		})
	}
}

func TestNodeRootHostMount(t *testing.T) {
	rule := MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountHost, Source: "/usr/bin/nvidia-smi", ReadOnly: true, Provenance: ProvenanceNodeRoot}
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	digest, _ := HostSourceDigest(rule.Source)
	mount := ObservedMount{Destination: rule.Destination, Class: MountHost, HostSourceDigest: digest, ReadOnly: true, Provenance: ProvenanceNodeRoot}
	if !policy.admits([]ObservedMount{mount}) {
		t.Fatal("rejected measured-root evidence")
	}
	for _, provenance := range []string{"", ProvenanceFSVerity, "dm-verity"} {
		mount.Provenance = provenance
		if policy.admits([]ObservedMount{mount}) {
			t.Fatalf("accepted provenance %q", provenance)
		}
	}
	rule.Provenance = "arbitrary"
	if err := rule.behavior().validate(); err == nil {
		t.Fatal("accepted unknown provenance")
	}
	rule.Provenance = ProvenanceNodeRoot
	rule.ReadOnly = false
	if err := rule.behavior().validate(); err == nil {
		t.Fatal("accepted writable measured-root mount")
	}
	rule.ReadOnly = true
	rule.VerityDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := rule.behavior().validate(); err == nil {
		t.Fatal("accepted redundant file digest")
	}
}

func TestNodeRootVerityFileMatchesBothProvenanceForms(t *testing.T) {
	const hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	source, _ := HostSourceDigest("/usr/bin/nvidia-smi")
	mount := ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: MountHost, HostSourceDigest: source, ReadOnly: true, Provenance: ProvenanceNodeRoot, VerityDigest: hash}
	for _, tc := range []struct {
		name         string
		provenance   string
		verityDigest string
		want         bool
	}{
		{"node-root", ProvenanceNodeRoot, "", true},
		{"fs-verity", ProvenanceFSVerity, hash, true},
		{"other fs-verity digest", ProvenanceFSVerity, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: mount.Destination, Kind: MountHost, Source: "/usr/bin/nvidia-smi", ReadOnly: true, Provenance: tc.provenance, VerityDigest: tc.verityDigest}}}
			if err := normalizeMounts(&policy); err != nil {
				t.Fatal(err)
			}
			if got := policy.admits([]ObservedMount{mount}); got != tc.want {
				t.Fatalf("admits(%+v) = %t, want %t", mount, got, tc.want)
			}
		})
	}
}

func TestProvenanceHostRuleIsNotPinnedForGrant(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/nvidia-smi", Kind: MountHost, Source: "/usr/bin/nvidia-smi", ReadOnly: true, Provenance: ProvenanceNodeRoot}}}
	if (mountConstraint{policy: &policy}).hostIndependent() {
		t.Fatal("node-root host rule reported host-independent, so a secrets grant would accept it")
	}
}
