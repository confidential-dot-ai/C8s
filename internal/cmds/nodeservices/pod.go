package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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

// preparePod admits exactly the signed workloads: the baked floor's plugin,
// inventory and fail-closed settings stay, but its base, the chart seed and
// the CDS pull are dropped, and nothing is exempt from the sandbox policy.
func preparePod(rootDir string, d *launchconfig.Document, outputs map[string][]byte) error {
	path := func(name string) string { return filepath.Join(rootDir, name) }
	if d.Pod == nil || d.Workloads == "" {
		return fmt.Errorf("staged pod role requires a pod and its workloads")
	}
	workloads, err := allowlist.ParseJSON([]byte(d.Workloads))
	if err != nil {
		return fmt.Errorf("launch workloads: %w", err)
	}
	if _, err := launchconfig.ParsePodManifest([]byte(d.Pod.Manifest)); err != nil {
		return err
	}
	data, err := os.ReadFile(path("/usr/lib/c8s/image-policy.yaml"))
	if err != nil {
		return err
	}
	var floor map[string]any
	if err := yaml.Unmarshal(data, &floor); err != nil {
		return fmt.Errorf("baked NRI policy: %w", err)
	}
	a, ok := floor["allowlist"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing allowlist")
	}
	policy, ok := floor["policy"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing policy")
	}
	a["base"] = workloads
	a["node_tcb"] = false
	delete(a, "pull")
	policy["sandbox"] = "enforce"
	// Measure every started workload into RTMR[3], on top of the launch-key
	// seed the initrd extended from operator-pubkey's exact bytes.
	if d.Image.HasRuntimeRegister() {
		floor["measure"] = map[string]any{
			"rtmr3":         true,
			"journal_path":  armtls.PodJournal,
			"launch_pubkey": launchDir + "operator-pubkey",
		}
	}
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
