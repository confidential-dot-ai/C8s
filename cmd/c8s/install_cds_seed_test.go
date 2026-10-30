//go:build !c8s_node

package main

import (
	"os"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A component entry this release renders and the named CDS does not serve is a
// component no node would admit, so the install refuses before it applies
// anything.
func TestCheckSeedServed(t *testing.T) {
	seed, err := pkgallowlist.ParseJSON([]byte(testSeedDocument("app")))
	if err != nil {
		t.Fatal(err)
	}
	served, err := cdsPinConfig(cdsPinDocument(t, []string{"app"}, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(seed, served); err != nil {
		t.Fatalf("checkSeedServed with the same entry = %v", err)
	}
	other, err := cdsPinConfig(cdsPinDocument(t, []string{"other"}, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(seed, other); err == nil {
		t.Fatal("an unserved component entry was accepted")
	}
	// The same name under another policy is a different component shape.
	widened, err := pkgallowlist.ParseJSON([]byte(strings.Replace(testSeedDocument("app"), `"command":{"policy":"any"}`, `"command":{"policy":"exact","argv":["/app"]}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSeedServed(widened, served); err == nil {
		t.Fatal("an entry of another shape was accepted under the same name")
	}
}

// --allowlist-seed-out is the render an operator needs before the CDS exists:
// it writes the component entries and touches neither the cluster nor helm.
func TestInstallWritesTheAllowlistSeedAndStops(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	out := s.f.dir + "/seed.json"
	values := s.f.dir + "/values.yaml"
	if err := os.WriteFile(values, []byte("router:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "-f", values, flagArg(flagSeedOut), out); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The seed is rendered from the values the release carries, the
	// operator's files among them.
	render := lineIndex(s.f.calls(t), "helm template ")
	if render < 0 || !strings.Contains(s.f.calls(t)[render], "-f "+values) {
		t.Fatalf("the seed render does not carry the operator's values: %v", s.f.calls(t))
	}
	document, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pkgallowlist.ParseJSON(document)
	if err != nil {
		t.Fatalf("the written seed does not parse: %v\n%s", err, document)
	}
	if _, ok := seed.Workloads[installSeedEntryName]; !ok {
		t.Fatalf("written seed = %v, want the rendered component entries", seed.Workloads)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm upgrade")
	mustNotContainPrefix(t, calls, "kubectl apply")

	// The render precedes the CDS it is configured into, so it names none.
	err = runC8s(t, "install", "--cvm-mode=bare-metal", "--force", flagArg(flagSeedOut), out,
		flagArg(flagCDSAddress), "10.9.9.9:8443",
		flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "192.0.2.0/24"))
	if err == nil || !strings.Contains(err.Error(), "runs before") {
		t.Fatalf("install = %v, want the refusal to name a CDS while writing its seed", err)
	}
}

// The CDS dials a node's admission inventory inside its configured subnets, so
// a subnet holding pod addresses would let a pod answer as that inventory.
func TestInstallRefusesNodeSubnetsHoldingPodAddresses(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))

	// The stubbed node assigns pod addresses from 10.42.0.0/24.
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force",
		flagArg(flagCDSAddress), "10.9.9.9:8443",
		flagArg(flagCDSPin), cdsPinFile(t, []string{installSeedEntryName}, "10.42.0.0/16"))
	if err == nil || !strings.Contains(err.Error(), "where this cluster's pods answer") {
		t.Fatalf("install = %v, want the overlapping node-subnet refusal", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// flagArg is a flag as its command line spells it.
func flagArg(name string) string {
	return "--" + name
}
