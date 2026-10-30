package allowlist

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const nodeEntryYAML = `
schema: c8s.allowlist/v1
workloads:
  agent:
    containers:
      - digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        command: {policy: exact, argv: ["agent"]}
        args: {policy: deny}
        mounts:
          policy: exact
          rules:
            - {destination: /var/lib/agent/config, kind: data, source: config, node: true}
        env:
          policy: match
          serviceLinks: true
          variables:
            HOSTNAME: {present: true}
            MODE: {exact: "on"}
`

func nodeEntry(t *testing.T) *Index {
	t.Helper()
	var a Allowlist
	if err := yaml.Unmarshal([]byte(nodeEntryYAML), &a); err != nil {
		t.Fatal(err)
	}
	if err := a.Normalize(); err != nil {
		t.Fatalf("a measured node entry does not normalize: %v", err)
	}
	return a.BuildIndex()
}

func TestServiceLinksAdmitOnlyKubeletServiceVariables(t *testing.T) {
	index := nodeEntry(t)
	for _, tc := range []struct {
		name  string
		extra []string
		want  bool
	}{
		{name: "none", want: true},
		{name: "a service's links", want: true, extra: []string{
			"RKE2_COREDNS_RKE2_COREDNS_SERVICE_HOST=10.53.0.10",
			"RKE2_COREDNS_RKE2_COREDNS_SERVICE_PORT=53",
			"RKE2_COREDNS_RKE2_COREDNS_SERVICE_PORT_UDP_53=53",
			"RKE2_COREDNS_RKE2_COREDNS_PORT=udp://10.53.0.10:53",
			"RKE2_COREDNS_RKE2_COREDNS_PORT_53_UDP=udp://10.53.0.10:53",
			"RKE2_COREDNS_RKE2_COREDNS_PORT_53_UDP_PROTO=udp",
			"RKE2_COREDNS_RKE2_COREDNS_PORT_53_TCP_ADDR=10.53.0.10",
		}},
		{name: "a loader variable", extra: []string{"LD_PRELOAD=/x.so"}},
		{name: "a shell function", extra: []string{"BASH_FUNC_cp%%=() { id; }"}},
		{name: "a shell startup file", extra: []string{"BASH_ENV=/x"}},
		{name: "a listed variable missing its exact value", extra: []string{"MODE=off"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"HOSTNAME=node", "MODE=on"}
			if tc.name == "a listed variable missing its exact value" {
				env = []string{"HOSTNAME=node"}
			}
			obs, err := ObserveEnv(append(env, tc.extra...))
			if err != nil {
				if !tc.want {
					return
				}
				t.Fatal(err)
			}
			got := index.AdmitsContainer(RunningContainer{
				Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Argv:   []string{"agent"},
				Env:    obs,
				Mounts: []ObservedMount{{Destination: "/var/lib/agent/config", Class: MountData, Volume: "config", Storage: MountMemory}},
			})
			if got != tc.want {
				t.Fatalf("admits = %v, want %v", got, tc.want)
			}
		})
	}
}

// A document on the wire can set neither node-only field: the strict ingest
// refuses them and the served ingest drops them. A data rule outside the data
// prefix needs one.
func TestNodeOnlyFieldsStayOutOfServedDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"serviceLinks": `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","command":{"policy":"any"},"args":{"policy":"any"},"env":{"policy":"match","variables":{},"serviceLinks":true}}]}}}`,
		"node":         `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"exact","rules":[{"destination":"/var/lib/x","kind":"data","node":true}]}}]}}}`,
	} {
		if _, err := ParseJSON([]byte(doc)); err == nil {
			t.Errorf("the strict ingest accepted %s", name)
		}
		if a, err := ParseServedJSON([]byte(doc)); err == nil {
			c := a.Workloads["w"].Containers[0]
			if c.Env.ServiceLinks || slices.ContainsFunc(c.Mounts.Rules, func(r MountRule) bool { return r.Node }) {
				t.Errorf("a served document set %s", name)
			}
		}
	}
	var a Allowlist
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(nodeEntryYAML, ", node: true", "")), &a); err != nil {
		t.Fatal(err)
	}
	if err := a.Normalize(); err == nil {
		t.Error("a data rule outside the data prefix normalized without node: true")
	}
	if err := (EnvPolicy{Policy: PolicyAny, ServiceLinks: true}).behaviorErr(); err == nil {
		t.Error("serviceLinks normalized under an any policy")
	}
}

func (p EnvPolicy) behaviorErr() error {
	_, err := p.behavior()
	return err
}
