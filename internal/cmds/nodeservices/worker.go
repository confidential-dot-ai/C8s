package nodeservices

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// prepareWorker stages the NRI floor of a node joined to an outside control
// plane. That control plane writes every pod spec in every namespace, so the
// floor trusts no namespace name and no RKE2 image: as in a pod CVM, nothing
// is exempt, only the measured mesh endpoint forms the base, nothing is node
// TCB, and host privilege is enforced, not audited. Every workload comes from
// CDS's policy, which the document cannot add to. A privileged add-on runs
// only once an entry pins its digest, arguments and mounts; until then it is
// refused, closed.
func prepareWorker(rootDir string, d *launchconfig.Document, outputs map[string][]byte) error {
	path := func(name string) string { return filepath.Join(rootDir, name) }
	floor, a, err := loadFloor(rootDir)
	if err != nil {
		return err
	}
	policy, ok := floor["policy"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing policy")
	}
	mesh, err := podMeshPolicy(floor["mesh"])
	if err != nil {
		return err
	}
	base, _, err := podMeshBase(a["base"])
	if err != nil {
		return err
	}
	a["base"] = base
	a["node_tcb"] = false
	if _, err := bindCDSPull(a, d); err != nil {
		return err
	}
	address, err := d.CDSAddrPort()
	if err != nil {
		return err
	}
	if err := appendCredentialRole(mesh, address); err != nil {
		return err
	}
	bindClusterNetwork(mesh, d.Kubernetes)
	floor["mesh"] = mesh
	policy["exempt_namespaces"] = []string{}
	delete(policy, "exempt_snapshot_path")
	policy["sandbox"] = "enforce"
	data, err := yaml.Marshal(floor)
	if err != nil {
		return err
	}
	if err := publishPublic(path(PublicDir), outputs, true); err != nil {
		return err
	}
	return writeFile(path(nriPolicyPath), data, 0600)
}
