package main

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The cds floor pins the HA replica to the one seed entry with its exact
// argv, keeps DaemonSet entries whole, and refuses what it cannot pin.
func TestBuildCDSFloorRules(t *testing.T) {
	d := func(b byte) types.Digest {
		dg, err := types.ParseDigest("sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64))
		if err != nil {
			t.Fatal(err)
		}
		return dg
	}
	exact := func(dg types.Digest, cmd, args []string) pkgallowlist.Container {
		return pkgallowlist.Container{Digest: dg, Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: cmd},
			Args: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: args}}
	}
	cds, mesh := d(1), d(2)
	seed := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"cds-singleton": {Containers: []pkgallowlist.Container{exact(cds, []string{"/cds"}, []string{"--singleton"})}},
		"cds-ha":        {Containers: []pkgallowlist.Container{exact(cds, []string{"/cds"}, []string{"--ha-config=x"})}},
		"mesh":          {Containers: []pkgallowlist.Container{exact(mesh, []string{"/mesh"}, []string{"run"})}},
	}}
	ha := cdsFloorContainer{key: "DaemonSet/c8s-cds-ha", digest: cds.String(), container: corev1.Container{Name: "cds", Args: []string{"--ha-config=x"}}}
	ds := cdsFloorContainer{key: "DaemonSet/c8s-armtls-mesh", digest: mesh.String(), container: corev1.Container{Name: "mesh"}}
	raw, err := buildCDSFloor(seed, []cdsFloorContainer{ds, ha})
	if err != nil {
		t.Fatal(err)
	}
	var floor pkgallowlist.Allowlist
	if err := json.Unmarshal(raw, &floor); err != nil {
		t.Fatal(err)
	}
	rep := floor.Workloads["cds-ha-replica"].Containers
	if len(rep) != 1 || rep[0].Args.Argv[0] != "--ha-config=x" || len(floor.Workloads["mesh"].Containers) != 1 {
		t.Fatalf("floor %+v", floor.Workloads)
	}
	if _, ok := floor.Workloads["cds-singleton"]; ok {
		t.Fatal("the singleton CDS invocation is in the cds floor")
	}
	unknown := ha
	unknown.digest = d(9).String()
	wrongArgv := ha
	wrongArgv.container.Args = []string{"--debug"}
	for name, cs := range map[string][]cdsFloorContainer{
		"no seed entry":   {unknown},
		"argv not pinned": {wrongArgv},
		"no HA CDS":       {ds},
	} {
		if _, err := buildCDSFloor(seed, cs); err == nil {
			t.Errorf("%s: floor built", name)
		}
	}
}
