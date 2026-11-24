package worker

import (
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

const testRouterEntry = "c8s-router-0123456789ab"

// testSetVersion is a release version, as `c8s node-image render` keys the set
// it publishes.
const testSetVersion = "0.43.0"

// routerHostPorts are the router entry's host ports, as the chart seeds them.
const routerHostPorts = `"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"TCP","hostPort":80,"containerPort":8080}]`

// routerSeed is a chart seed holding the router's entry, which reads the
// files named, and another component's.
func routerSeed(files ...string) []byte {
	var args []string
	for _, f := range files {
		args = append(args, `"--file=`+f+`"`)
	}
	return []byte(`{"schema":"c8s.allowlist/v1","workloads":{
  "` + testRouterEntry + `":{` + routerHostPorts + `,"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `",
    "command":{"policy":"exact","argv":["/c8s"]},"args":{"policy":"exact","argv":[` + strings.Join(args, ",") + `]},
    "mounts":{"policy":"exact","rules":[{"destination":"/run/c8s-node","kind":"host","source":"/run/c8s-node","readOnly":true}]},
    "env":{"policy":"exact","values":{"PATH":"/bin"}}}]},
  "c8s-operator-0123":{"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `","command":{"policy":"exact","argv":["/c8s","operator"]},"args":{"policy":"deny"}}]}}}`)
}

// platformRoleEntries are the template's entries, the ones a member pod's
// injected containers and the router's pod run under.
var platformRoleEntries = []string{
	"c8s-acme", "c8s-allowlist-proxy", "c8s-get-cert", "c8s-get-secret", "c8s-get-volume",
	"c8s-mesh-endpoint", "c8s-probe-file", "c8s-router-nginx", "c8s-router-upstream",
}

// The set file a release publishes is one set under the release's version,
// holding the template's role entries as they are and the seed's router entry,
// and it passes every check an operator's write faces.
func TestComponentSetFileCarriesTheTemplateAndTheRouter(t *testing.T) {
	template := renderedTemplate(t)
	seed := routerSeed("/run/c8s-node/cds.json", "/run/c8s-node/operator-pubkey", "/run/c8s-node/router/hostnames")
	file, err := ComponentSetFile(template, seed, testSetVersion)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := allowlist.ParseJSON(file)
	if err != nil {
		t.Fatalf("the published set file does not parse: %v", err)
	}
	if len(doc.Workloads) != 0 || len(doc.Components) != 1 {
		t.Fatalf("set file holds %d workload entries and %d sets, want none and one", len(doc.Workloads), len(doc.Components))
	}
	set, published := doc.Components[testSetVersion]
	if !published {
		t.Fatalf("sets = %v, want one keyed by the release", slices.Sorted(maps.Keys(doc.Components)))
	}
	if !set.Current() {
		t.Error("the published set carries a deadline")
	}
	want := slices.Sorted(slices.Values(append(slices.Clone(platformRoleEntries), testRouterEntry)))
	if got := slices.Sorted(maps.Keys(set.Entries)); !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want the template's role entries and the router's, %v", got, want)
	}
	roles, err := RoleEntries(template)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range platformRoleEntries {
		if !reflect.DeepEqual(set.Entries[name], normalized(t, roles[name])) {
			t.Errorf("entry %s =\n%+v\nwant the template's\n%+v", name, set.Entries[name], roles[name])
		}
	}
	router, err := allowlist.ParseJSON(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set.Entries[testRouterEntry], router.Workloads[testRouterEntry]) {
		t.Errorf("router entry =\n%+v\nwant the seed's\n%+v", set.Entries[testRouterEntry], router.Workloads[testRouterEntry])
	}
	if len(set.Entries[testRouterEntry].HostPorts) != 2 {
		t.Errorf("router host ports = %v, want the seed's two", set.Entries[testRouterEntry].HostPorts)
	}
}

// normalized is the entry as a parsed document carries it, which is what the
// set file's bytes are compared against.
func normalized(t *testing.T, entry allowlist.Workload) allowlist.Workload {
	t.Helper()
	doc := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"entry": entry}}
	if err := doc.Normalize(); err != nil {
		t.Fatal(err)
	}
	return doc.Workloads["entry"]
}

// Every container of the published set holds a role, so a pod of the router's
// namespace and an injected sidecar take their identity from the set alone.
func TestComponentSetFileBindsEveryContainerToARole(t *testing.T) {
	file, err := ComponentSetFile(renderedTemplate(t), routerSeed("/run/c8s-node/cds.json"), testSetVersion)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := allowlist.ParseJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	for name, entry := range doc.Components[testSetVersion].Entries {
		if name == testRouterEntry {
			continue
		}
		for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
			if !slices.Contains(allowlist.KnownRoles, c.Role) {
				t.Errorf("entry %s container %s holds the role %q", name, c.Digest, c.Role)
			}
		}
	}
}

func TestComponentSetFileRefusesWhatItCannotPublish(t *testing.T) {
	template := renderedTemplate(t)
	seed := routerSeed("/run/c8s-node/cds.json")
	// An entry declaring host ports pins its launch, so the open one declares none.
	unpinnedRouter := []byte(strings.Replace(strings.Replace(string(seed), routerHostPorts+",", "", 1), `"env":{"policy":"exact","values":{"PATH":"/bin"}}`, `"env":{"policy":"any"}`, 1))
	for _, tc := range []struct {
		name           string
		template, seed []byte
		version        string
		want           string
	}{
		{"no router entry", template, []byte(strings.ReplaceAll(string(seed), testRouterEntry, "other")), testSetVersion, "want one c8s-router-* entry"},
		{"two router entries", template, []byte(strings.Replace(string(seed), `"c8s-operator-0123"`, `"c8s-router-other"`, 1)), testSetVersion, "want one c8s-router-* entry"},
		{"a router reading a server's file", template, routerSeed("/run/c8s-node/peers.json"), testSetVersion, "/run/c8s-node/peers.json, which worker stage does not publish"},
		{"a router reading a server's file through its environment", template, []byte(strings.Replace(string(seed), `"values":{"PATH":"/bin"}`, `"values":{"PATH":"/bin","PEERS":"/run/c8s-node/peers.json"}`, 1)), testSetVersion, "/run/c8s-node/peers.json"},
		{"a router mounting a server's file", template, []byte(strings.Replace(string(seed), `"source":"/run/c8s-node"`, `"source":"/run/c8s-node/peers.json"`, 1)), testSetVersion, "/run/c8s-node/peers.json"},
		{"a router reading a file by a doubled slash", template, routerSeed("/run//c8s-node/peers.json"), testSetVersion, "which worker stage does not publish"},
		{"a router reading outside by dot-dot", template, routerSeed("/run/c8s-node/../nri-image-policy/x"), testSetVersion, "which worker stage does not publish"},
		{"an open router launch", template, unpinnedRouter, testSetVersion, "does not pin its launch"},
		{"a router mounting operator data", template, []byte(strings.Replace(string(seed), `"rules":[`, `"rules":[{"destination":"/mnt/c8s-data/keys","kind":"data"},`, 1)), testSetVersion, "mounts data, which the control plane fills"},
		{"a router entry named as a platform role", template, []byte(strings.ReplaceAll(string(seed), testRouterEntry, "c8s-router-nginx")), testSetVersion, "a platform role is named c8s-router-nginx"},
		{"an entry without a platform role", regexp.MustCompile(`(?m)^ +role: "acme"\n`).ReplaceAll(template, nil), seed, testSetVersion, "entry c8s-acme container with digest sha256:"},
		{"no platform role at all", regexp.MustCompile(`(?m)^ +role: .*\n`).ReplaceAll(template, nil), seed, testSetVersion, "holds no platform role"},
		{"a version no set is keyed by", template, seed, "0.43", `version "0.43" is not MAJOR.MINOR.PATCH`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ComponentSetFile(tc.template, tc.seed, tc.version); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ComponentSetFile = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
