package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	kubeyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod-role outputs. Kubelet and containerd configs stay baked; preparation
// stages the signed workload and the CNI template with the guest uplink MTU.
const (
	PodDir             = "/run/c8s-pod"
	podManifestPath    = PodDir + "/manifests/pod.yaml"
	podKubeletEnvPath  = PodDir + "/kubelet.env"
	podUnmanagedLinks  = "/run/systemd/network/10-podcvm-unmanaged.network"
	podUnmanagedConfig = "[Match]\nName=veth* c8spod*\n\n[Link]\nUnmanaged=yes\n"
)

// preparePod admits the signed base and the authenticated CDS allowlist.
// Only the baked mesh endpoint joins the signed base; nothing is node TCB.
func preparePod(rootDir string, d *launchconfig.Document, outputs map[string][]byte, resolveMTU func() (int, error)) error {
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
	pod, err := launchconfig.ParsePodManifest([]byte(d.Pod.Manifest))
	if err != nil {
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
	base, image, err := podMeshBase(a["base"])
	if err != nil {
		return err
	}
	if err := mergeWorkloads(base, workloads, false); err != nil {
		return err
	}
	if err := podmesh.InjectEndpoint(pod, image); err != nil {
		return fmt.Errorf("pod mesh endpoint: %w", err)
	}
	images, err := podImagePins(pod)
	if err != nil {
		return err
	}
	// Standalone Pods use the guest's upstream resolver configuration; they
	// have no cluster DNS. Workload overrides cannot replace this measured
	// networking contract or direct DNS to a guest-local service.
	pod.Spec.DNSPolicy = corev1.DNSDefault
	pod.Spec.DNSConfig = nil
	manifest, err := kubeyaml.Marshal(pod)
	if err != nil {
		return fmt.Errorf("render pod manifest: %w", err)
	}
	a["base"] = base
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
	// A Pod boot has no node namespaces or in-Pod credential clients. Its
	// guest broker reaches CDS outside the Pod network namespace.
	delete(mesh, "credential_attestation_port")
	peers, err := d.Pod.PeerAddresses()
	if err != nil {
		return err
	}
	ports, err := d.Pod.IngressPorts()
	if err != nil {
		return err
	}
	mesh["pod"] = map[string]any{"peers": peers, "ingress_ports": ports}
	floor["mesh"] = mesh
	policy["exempt_namespaces"] = []string{}
	delete(policy, "exempt_snapshot_path")
	// Kubelet suffixes a static Pod's name with its signed guest hostname.
	floor["pod"] = map[string]any{"uid": d.Pod.UID, "namespace": d.Pod.Namespace, "name": d.Pod.Name + "-" + d.Node.Name, "images": images}
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

	cni, err := preparePodNetwork(rootDir, resolveMTU)
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
		{podManifestPath, manifest, 0600},
		{podKubeletEnvPath, []byte("KUBELET_HOSTNAME=" + d.Node.Name + "\n"), 0644},
		{podUnmanagedLinks, []byte(podUnmanagedConfig), 0644},
		{podCNIPath, cni, 0644},
	}
	for _, f := range files {
		if err := writeFile(path(f.path), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// podImagePins binds every runtime container name to its signed or baked image.
func podImagePins(pod *corev1.Pod) (map[string]string, error) {
	images := make(map[string]string, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	for _, container := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if len(validation.IsDNS1123Label(container.Name)) != 0 {
			return nil, fmt.Errorf("pod container %q has no valid name", container.Name)
		}
		if _, exists := images[container.Name]; exists {
			return nil, fmt.Errorf("pod container name %q is duplicated", container.Name)
		}
		named, err := reference.ParseNormalizedNamed(container.Image)
		if err != nil {
			return nil, fmt.Errorf("pod container %q image: %w", container.Name, err)
		}
		canonical, ok := named.(reference.Canonical)
		if !ok {
			return nil, fmt.Errorf("pod container %q image must pin a canonical digest", container.Name)
		}
		digest, err := types.ParseDigest(canonical.Digest().String())
		if err != nil || digest.String() != canonical.Digest().String() {
			return nil, fmt.Errorf("pod container %q image must pin a canonical sha256 digest", container.Name)
		}
		images[container.Name] = digest.String()
	}
	return images, nil
}

// podMeshPolicy keeps the measured mesh binding and packet-capture inputs.
// Node roles and namespace exemptions cannot cross into a Pod guest.
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
	if len(mesh) != 1 {
		return nil, fmt.Errorf("baked NRI mesh policy must bind exactly one %s role", workloadclaims.MeshRole)
	}
	policy["roles"] = mesh
	policy["exempt_namespaces"] = []any{}
	return policy, nil
}

// podMeshBase extracts exactly the endpoint the image measured. No signed
// workload, chart seed or remote policy may choose platform role authority.
func podMeshBase(declared any) (*allowlist.Allowlist, string, error) {
	baked, err := bakedBase(declared)
	if err != nil {
		return nil, "", err
	}
	base := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
	image := ""
	for name, workload := range baked.Workloads {
		for _, container := range slices.Concat(workload.InitContainers, workload.Containers) {
			if container.Role != workloadclaims.MeshRole {
				continue
			}
			if image != "" {
				return nil, "", fmt.Errorf("baked NRI base declares more than one mesh endpoint")
			}
			endpoint := podmesh.Endpoint(container.Image, nil)
			if container.Image == "" || !strings.HasSuffix(container.Image, "@"+container.Digest.String()) ||
				container.Command.Policy != allowlist.PolicyExact || !slices.Equal(container.Command.Argv, []string{"/app/c8s", "armtls-mesh"}) ||
				container.Args.Policy != allowlist.PolicyExact || !slices.Equal(container.Args.Argv, endpoint.Args) ||
				container.Mounts.Policy != allowlist.PolicyExact || len(container.Mounts.Rules) != 1 {
				return nil, "", fmt.Errorf("baked mesh endpoint must pin its image, command, arguments and credential mount")
			}
			rule := container.Mounts.Rules[0]
			if rule.Kind != allowlist.MountEmptyDir || rule.Source != podmesh.CertVolumeName || rule.Destination != podmesh.CertDir {
				return nil, "", fmt.Errorf("baked mesh endpoint does not bind the private credential volume")
			}
			image = container.Image
			base.Workloads[name] = allowlist.Workload{Label: workload.Label, Containers: []allowlist.Container{container}}
		}
	}
	if image == "" {
		return nil, "", fmt.Errorf("baked NRI base declares no mesh endpoint")
	}
	return base, image, nil
}
