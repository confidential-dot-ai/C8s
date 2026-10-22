package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod-role outputs. The kubelet, containerd and CNI configs are static and
// baked under /usr/lib/c8s/pod-runtime; only per-launch inputs land here.
const (
	PodDir             = "/run/c8s-pod"
	podManifestPath    = PodDir + "/manifests/pod.yaml"
	podKubeletEnvPath  = PodDir + "/kubelet.env"
	podUnmanagedLinks  = "/run/systemd/network/10-podcvm-unmanaged.network"
	podUnmanagedConfig = "[Match]\nName=veth* c8spod*\n\n[Link]\nUnmanaged=yes\n"
)

// preparePod admits the signed base and the authenticated CDS allowlist, and
// keeps of the baked base and mesh policy what makes the pod a mesh member:
// the mesh endpoint's measured entry and the mesh role's identity binding.
// The node's other components, roles and chart seed are dropped; nothing is
// node TCB.
func preparePod(rootDir string, d *launchconfig.Document, outputs map[string][]byte) error {
	path := func(name string) string { return filepath.Join(rootDir, name) }
	if d.Pod == nil || d.Workloads == "" {
		return fmt.Errorf("staged pod role requires a pod and its workloads")
	}
	workloads, err := allowlist.ParseJSON([]byte(d.Workloads))
	if err != nil {
		return fmt.Errorf("launch workloads: %w", err)
	}
	if len(workloads.Workloads) == 0 {
		return fmt.Errorf("staged pod role requires a nonempty workloads base")
	}
	if _, err := launchconfig.ParsePodManifest([]byte(d.Pod.Manifest)); err != nil {
		return err
	}
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
	base, err := bakedBase(a["base"])
	if err != nil {
		return err
	}
	endpoint, err := meshEndpointEntries(base)
	if err != nil {
		return err
	}
	if err := mergeWorkloads(workloads, endpoint, false); err != nil {
		return fmt.Errorf("merge the baked mesh endpoint into the pod base: %w", err)
	}
	a["base"] = workloads
	a["node_tcb"] = false
	pull, err := bindCDSPull(a, d)
	if err != nil {
		return err
	}
	if value, exists := pull["measure_policies"]; exists {
		enabled, ok := value.(bool)
		if !ok {
			return fmt.Errorf("baked allowlist.pull.measure_policies must be a boolean")
		}
		if enabled {
			return nriimagepolicy.ErrPodRoleMeasurePolicies
		}
	}
	floor["mesh"] = mesh
	policy["sandbox"] = "enforce"
	// Measure every started workload into RTMR[3], on top of the launch-key
	// seed the initrd extended from operator-pubkey's exact bytes, into the
	// journal under the baked inventory directory that pod-status reads.
	// A platform without the register cannot run measured pod workloads.
	if !d.Image.HasRuntimeRegister() {
		return fmt.Errorf("pod role requires a platform with a runtime register; %s has none", d.Image.Platform)
	}
	floor["measure"] = map[string]any{"rtmr3": true}
	policyData, err := yaml.Marshal(floor)
	if err != nil {
		return err
	}

	if err := publishPublic(path(PublicDir), outputs, true); err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{nriPolicyPath, policyData, 0600},
		{podManifestPath, []byte(d.Pod.Manifest), 0600},
		{podKubeletEnvPath, []byte("KUBELET_HOSTNAME=" + d.Node.Name + "\n"), 0644},
		{podUnmanagedLinks, []byte(podUnmanagedConfig), 0644},
	}
	for _, f := range files {
		if err := writeFile(path(f.path), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// podMeshPolicy is the baked mesh policy as a pod CVM enforces it: the
// capture ports, resolver and cluster ranges a node gates its pods with, the
// mesh role's binding alone, and no exempt namespace, because the one pod of
// a pod CVM is a member or nothing. The credential role is a node's: a pod
// CVM injects no credential clients.
func podMeshPolicy(declared any) (map[string]any, error) {
	if declared == nil {
		return nil, fmt.Errorf("baked NRI policy missing mesh")
	}
	policy, ok := declared.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("baked NRI mesh policy is %T, not a mapping", declared)
	}
	roles, ok := policy["roles"].([]any)
	if !ok {
		return nil, fmt.Errorf("baked NRI mesh roles are %T, not a list", policy["roles"])
	}
	var mesh []any
	for _, declared := range roles {
		role, ok := declared.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("baked NRI mesh role is %T, not a mapping", declared)
		}
		if role["name"] == workloadclaims.MeshRole {
			mesh = append(mesh, role)
		}
	}
	if len(mesh) == 0 {
		return nil, fmt.Errorf("baked NRI mesh policy binds no %s role", workloadclaims.MeshRole)
	}
	policy["roles"] = mesh
	policy["exempt_namespaces"] = []any{}
	return policy, nil
}

// meshEndpointEntries is the part of the baked base a pod CVM keeps: the
// workloads whose every container holds the mesh role. Such an entry admits
// the endpoint's image under its argv and mounts and binds it to the role,
// which the signed workloads cannot do, because their ingest drops roles. The
// node's other components, and the roles only a node grants, stay the node's.
func meshEndpointEntries(base *allowlist.Allowlist) (*allowlist.Allowlist, error) {
	kept := &allowlist.Allowlist{Schema: base.Schema, Workloads: map[string]allowlist.Workload{}}
	for name, workload := range base.Workloads {
		containers := slices.Concat(workload.InitContainers, workload.Containers)
		if len(containers) == 0 || slices.ContainsFunc(containers, func(c allowlist.Container) bool {
			return c.Role != workloadclaims.MeshRole
		}) {
			continue
		}
		kept.Workloads[name] = workload
	}
	if len(kept.Workloads) == 0 {
		return nil, fmt.Errorf("baked NRI base binds no container to the %s role, so no pod could start", workloadclaims.MeshRole)
	}
	return kept, nil
}
