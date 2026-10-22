package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

// preparePod admits the signed base and the authenticated CDS allowlist.
// The node's baked base and chart seed are dropped; nothing is node TCB.
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
	// The baked mesh policy is a node's: it gates every pod outside its
	// exempt namespaces on a verified mesh endpoint, which only the measured
	// base allowlist can declare. The signed workloads replace that base and
	// name no roles, so with the policy kept no pod could ever start. A pod
	// CVM hosts no mesh members until its mesh integration is defined.
	delete(floor, "mesh")
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
