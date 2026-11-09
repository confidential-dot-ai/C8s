package allowlist

import (
	"errors"
	"strings"
	"testing"
)

// Only a measured boot config marks a static pod's entry: the strict JSON
// ingest refuses the key and a served document's is ignored.
func TestStaticPodIsYAMLOnly(t *testing.T) {
	doc := `{"schema":"` + Schema + `","workloads":{"entry":{"staticPod":true,"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/x"]},"args":{"policy":"deny"}}]}}}`
	if _, err := ParseJSON([]byte(doc)); err == nil || !strings.Contains(err.Error(), "staticPod") {
		t.Fatalf("ParseJSON = %v, want the staticPod key refused", err)
	}
	served, err := ParseServedJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if served.Workloads["entry"].StaticPod {
		t.Fatal("a served document marked a static pod's entry")
	}
}

// A static pod's entry grants no host ports or capabilities, so a boot config
// whose static-pod entry declares either is refused.
func TestStaticPodEntryDeclaresNoHostPortsOrCapabilities(t *testing.T) {
	ports := grantingEntry(t, []string{"/app"}, HostPort{Protocol: "TCP", HostPort: 443, ContainerPort: 8443})
	capabilities := grantingEntry(t, []string{"/app"})
	capabilities.Containers[0].Capabilities = CapabilityList{"SYS_PTRACE"}
	for name, entry := range map[string]Workload{"host ports": ports, "capabilities": capabilities} {
		entry.StaticPod = true
		a := Allowlist{Schema: Schema, Workloads: map[string]Workload{"static": entry}}
		if err := a.Normalize(); !errors.Is(err, errStaticPodDeclaresGrants) {
			t.Errorf("%s: Normalize = %v, want the declaration refused", name, err)
		}
	}
}
