package allowlist

import (
	"encoding/json"
	"strings"
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
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservedMount
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !policy.admits([]ObservedMount{decoded}) {
		t.Fatal("provenance lost during serialization")
	}
	for _, tc := range []struct {
		name   string
		change func(*ObservedMount)
	}{
		{"no evidence", func(m *ObservedMount) { m.Provenance = "" }},
		{"other provenance", func(m *ObservedMount) { m.Provenance = "dm-verity" }},
		{"fs-verity evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, strings.Repeat("b", 64) }},
		{"writable bind", func(m *ObservedMount) { m.ReadOnly = false }},
		{"different source", func(m *ObservedMount) { m.HostSourceDigest = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := mount
			tc.change(&observed)
			if policy.admits([]ObservedMount{observed}) {
				t.Fatalf("admits(%+v) = true, want false", observed)
			}
		})
	}
	// A rule without provenance stays path/mode-only when a node supplies evidence.
	policy.Rules[0].Provenance = ""
	if !policy.admits([]ObservedMount{mount}) {
		t.Fatal("changed path-only host rule behavior")
	}
}

func TestHostMountProvenanceValidation(t *testing.T) {
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name string
		rule MountRule
		want string
	}{
		{"unknown provenance", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: "dm-verity"}, `mount provenance "dm-verity" is not supported`},
		{"fs-verity without digest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: ProvenanceFSVerity}, "64 lowercase hexadecimal"},
		{"short digest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: "abc"}, "64 lowercase hexadecimal"},
		{"uppercase digest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: strings.ToUpper(digest)}, "64 lowercase hexadecimal"},
		{"prefixed digest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: "sha256:" + digest}, "64 lowercase hexadecimal"},
		{"writable fs-verity", MountRule{Kind: MountHost, Source: "/usr/bin/tool", Provenance: ProvenanceFSVerity, VerityDigest: digest}, "requires readOnly"},
		{"digest without provenance", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: digest}, "requires fs-verity provenance"},
		{"node-root with digest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: ProvenanceNodeRoot, VerityDigest: digest}, "requires fs-verity provenance"},
		{"writable node-root", MountRule{Kind: MountHost, Source: "/usr/bin/tool", Provenance: ProvenanceNodeRoot}, "requires readOnly"},
		{"emptyDir provenance", MountRule{Kind: MountEmptyDir, Provenance: ProvenanceNodeRoot}, "does not support"},
		{"data digest", MountRule{Kind: MountData, VerityDigest: digest}, "does not support"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.Destination = "/mnt/c8s-data/tools"
			policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{tc.rule}}
			if err := normalizeMounts(&policy); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("normalizeMounts(%+v) = %v, want error containing %q", tc.rule, err, tc.want)
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

func TestFSVerityHostMount(t *testing.T) {
	hash := strings.Repeat("b", 64)
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/tool", Kind: MountHost, Source: "/opt/tools/tool", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	source, _ := HostSourceDigest("/opt/tools/tool")
	mount := ObservedMount{Destination: "/usr/bin/tool", Class: MountHost, HostSourceDigest: source, ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}
	for _, tc := range []struct {
		name   string
		change func(*ObservedMount)
		want   bool
	}{
		{"pinned digest", func(*ObservedMount) {}, true},
		{"no evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = "", "" }, false},
		{"digest without provenance", func(m *ObservedMount) { m.Provenance = "" }, false},
		{"node-root evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceNodeRoot, "" }, false},
		{"other digest", func(m *ObservedMount) { m.VerityDigest = strings.Repeat("a", 64) }, false},
		{"other source", func(m *ObservedMount) { m.HostSourceDigest = "other" }, false},
		{"writable bind", func(m *ObservedMount) { m.ReadOnly = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := mount
			tc.change(&observed)
			if got := policy.admits([]ObservedMount{observed}); got != tc.want {
				t.Fatalf("admits(%+v) = %t, want %t", observed, got, tc.want)
			}
		})
	}
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservedMount
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != mount {
		t.Fatalf("round trip = %+v, %v, want %+v", decoded, err, mount)
	}
}

func TestIndexFSVerityMountRules(t *testing.T) {
	hash := strings.Repeat("b", 64)
	pinned := MountRule{Destination: "/usr/bin/tool", Kind: MountHost, Source: "/opt/tools/tool", ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}
	plain := MountRule{Destination: "/usr/bin/other", Kind: MountHost, Source: "/opt/tools/other", ReadOnly: true}
	digest := mustDigest(t, "sha256:"+strings.Repeat("a", 64))
	al := &Allowlist{Workloads: map[string]Workload{"w": {Containers: []Container{{Digest: digest, Mounts: MountPolicy{Policy: PolicyExact, Rules: []MountRule{pinned, plain}}}}}}}
	idx := al.BuildIndex()
	if !idx.HasFSVerityMountRules() {
		t.Fatal("HasFSVerityMountRules() = false, want true")
	}
	if got := idx.FSVerityMountRules(digest.String()); len(got) != 1 || got[0] != pinned {
		t.Fatalf("FSVerityMountRules() = %+v, want [%+v]", got, pinned)
	}
	if got := idx.FSVerityMountRules("sha256:" + strings.Repeat("c", 64)); got != nil {
		t.Fatalf("FSVerityMountRules(other image) = %+v, want none", got)
	}
	var none *Index
	if none.HasFSVerityMountRules() || none.FSVerityMountRules(digest.String()) != nil {
		t.Fatal("nil index reported fs-verity rules")
	}
}
