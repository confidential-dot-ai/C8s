package workloadclaims

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestMountEvidenceAffectsContainerKey(t *testing.T) {
	base := SandboxContainer{Digest: "sha256:" + strings.Repeat("a", 64), Argv: []string{"/app"}}
	observedEmpty := base
	observedEmpty.Mounts = []allowlist.ObservedMount{}
	if base.Key() == observedEmpty.Key() {
		t.Fatal("missing mount evidence collapsed into observed empty")
	}
	withMount := observedEmpty
	withMount.Mounts = []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountMemory}}
	if observedEmpty.Key() == withMount.Key() {
		t.Fatal("a mount was erased from the inventory key")
	}
	onDisk := withMount
	onDisk.Mounts = []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountUnknown}}
	if withMount.Key() == onDisk.Key() {
		t.Fatal("mount storage was erased from the inventory key")
	}
}

func TestMountSourceStaysNodeLocal(t *testing.T) {
	c := SandboxContainer{Mounts: []allowlist.ObservedMount{{Destination: "/config", Source: "/var/lib/kubelet/pods/private", Class: allowlist.MountData, Storage: allowlist.MountMemory}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/var/lib/kubelet") {
		t.Fatalf("node source escaped in inventory: %s", b)
	}
}

func TestMountEvidenceJSONRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []allowlist.ObservedMount
	}{
		{name: "absent", input: `{}`},
		{name: "null", input: `{"mounts":null}`},
		{name: "observed empty", input: `{"mounts":[]}`, want: []allowlist.ObservedMount{}},
		{name: "observed mount", input: `{"mounts":[{"destination":"/config","class":"data","storage":"memory"}]}`,
			want: []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountMemory}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c SandboxContainer
			if err := json.Unmarshal([]byte(tc.input), &c); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.Mounts, tc.want) {
				t.Fatalf("decoded mounts = %#v, want %#v", c.Mounts, tc.want)
			}
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			mounts, ok := fields["mounts"]
			if !ok {
				t.Fatalf("mounts omitted from inventory: %s", encoded)
			}
			if tc.want == nil && string(mounts) != "null" {
				t.Fatalf("unavailable mounts = %s, want null", mounts)
			}
			if tc.want != nil && len(tc.want) == 0 && string(mounts) != "[]" {
				t.Fatalf("observed empty mounts = %s, want []", mounts)
			}
			var roundTrip SandboxContainer
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(roundTrip.Mounts, tc.want) || roundTrip.Key() != c.Key() {
				t.Fatalf("mount evidence changed on round trip: before=%#v after=%#v", c.Mounts, roundTrip.Mounts)
			}
		})
	}
}

func TestHostMountIdentityRoundTrip(t *testing.T) {
	sourceDigest, err := allowlist.HostSourceDigest("/etc/service")
	if err != nil {
		t.Fatal(err)
	}
	mount := allowlist.ObservedMount{Destination: "/config", Class: allowlist.MountHost, Source: "/etc/service", HostSourceDigest: sourceDigest, ReadOnly: true}
	c := SandboxContainer{Mounts: []allowlist.ObservedMount{mount}}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), mount.Source) {
		t.Fatal("source path escaped into inventory")
	}
	var roundTrip SandboxContainer
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Key() != c.Key() {
		t.Fatal("host identity changed on round trip")
	}
	for _, source := range []string{"/etc/service", "/etc/other"} {
		changed := mount
		changed.HostSourceDigest, err = allowlist.HostSourceDigest(source)
		if err != nil {
			t.Fatal(err)
		}
		changed.ReadOnly = source != "/etc/service"
		if (SandboxContainer{Mounts: []allowlist.ObservedMount{changed}}).Key() == c.Key() {
			t.Fatal("host authority collapsed in inventory key")
		}
	}
}

func TestContainerKeyDistinguishesMissingEnvironment(t *testing.T) {
	missing := SandboxContainer{}
	empty := SandboxContainer{Env: &allowlist.EnvObservation{}}
	if missing.Key() == empty.Key() {
		t.Fatal("missing environment collapsed into present evidence")
	}
}

func TestProvenanceSurvivesInventoryAndChangesIdentity(t *testing.T) {
	mount := allowlist.ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: allowlist.MountHost, ReadOnly: true, Provenance: allowlist.ProvenanceNodeRoot}
	c := SandboxContainer{Mounts: []allowlist.ObservedMount{mount}}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SandboxContainer
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Mounts[0].Provenance != mount.Provenance || decoded.Key() != c.Key() {
		t.Fatal("lost provenance on inventory round trip")
	}
	changed := mount
	changed.Provenance = ""
	if (SandboxContainer{Mounts: []allowlist.ObservedMount{changed}}).Key() == c.Key() {
		t.Fatal("provenance collapsed in history key")
	}
}

func TestVariableEvidenceRoundTrip(t *testing.T) {
	observation, err := allowlist.ObserveEnv([]string{"MODE=production", "GPU_SERIAL=device-1"})
	if err != nil {
		t.Fatal(err)
	}
	c := SandboxContainer{Env: observation}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip SandboxContainer
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Env, roundTrip.Env) || c.Key() != roundTrip.Key() {
		t.Fatal("variable evidence changed on round trip")
	}
}

// The aggregate digest fixes the per-variable digests, so they stay out of the
// key that every inventory sort compares.
func TestContainerKeyOmitsVariableDigests(t *testing.T) {
	env, err := allowlist.ObserveEnv([]string{"MODE=production"})
	if err != nil || env.VariableDigests == nil {
		t.Fatalf("ObserveEnv() = %v, %v; want per-variable evidence", env, err)
	}
	full := SandboxContainer{Digest: "sha256:" + strings.Repeat("a", 64), Env: env}
	aggregate := full
	aggregate.Env = env.Clone()
	aggregate.Env.VariableDigests = nil
	if full.Key() != aggregate.Key() {
		t.Fatalf("Key() = %q with per-variable digests, %q without; want equal", full.Key(), aggregate.Key())
	}
	evicted := aggregate
	evicted.Env = aggregate.Env.Clone()
	evicted.Env.VariableDigestsEvicted = true
	if evicted.Key() == aggregate.Key() {
		t.Fatal("the evicted flag was erased from the inventory key")
	}
	other, _ := allowlist.ObserveEnv([]string{"MODE=debug"})
	changed := full
	changed.Env = other
	if changed.Key() == full.Key() {
		t.Fatal("the aggregate env digest was erased from the inventory key")
	}
}
