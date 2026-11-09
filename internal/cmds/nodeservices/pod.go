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

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod-role outputs. Kubelet and containerd configs stay baked; preparation
// stages the CNI template with the guest uplink MTU, and the assignment later
// renders the runtime policy and the manifest.
const (
	PodDir             = "/run/c8s-pod"
	podKubeletEnvPath  = PodDir + "/kubelet.env"
	podUnmanagedLinks  = "/run/systemd/network/10-podcvm-unmanaged.network"
	podUnmanagedConfig = "[Match]\nName=veth* c8spod*\n\n[Link]\nUnmanaged=yes\n"
)

// PodRuntime is fully validated runtime policy plus the assigned manifest.
// Rendering writes nothing, so assignment can validate before committing its record.
type PodRuntime struct {
	UID      string
	Policy   []byte
	Manifest []byte
}

// RenderPodRuntime applies the measured floor to an assigned pod: the generic
// document's trust, the pod's entries and the manifest the assignment carried.
func RenderPodRuntime(rootDir string, d *podlaunch.AssignedPod) (PodRuntime, error) {
	if d == nil || d.Role != podlaunch.Pod {
		return PodRuntime{}, fmt.Errorf("not a Pod role document")
	}
	floor, a, err := loadFloor(rootDir)
	if err != nil {
		return PodRuntime{}, err
	}
	policy, ok := floor["policy"].(map[string]any)
	if !ok {
		return PodRuntime{}, fmt.Errorf("baked NRI policy missing policy")
	}
	mesh, err := podMeshPolicy(floor["mesh"])
	if err != nil {
		return PodRuntime{}, err
	}
	base, image, err := podMeshBase(a["base"])
	if err != nil {
		return PodRuntime{}, err
	}
	// A plugin restart within the boot ends the pod identity; the plugin tells
	// a restart from its first registration by the boot marker, so the baked
	// floor must arm that check.
	if marker, _ := policy["boot_marker_path"].(string); policy["fatal_existing"] != true || marker == "" {
		return PodRuntime{}, fmt.Errorf("baked NRI policy must set policy.fatal_existing and policy.boot_marker_path")
	}
	workloads, err := allowlist.ParseJSON([]byte(d.Entries))
	if err != nil {
		return PodRuntime{}, fmt.Errorf("assignment entries: %w", err)
	}
	if err := mergeWorkloads(base, workloads, false); err != nil {
		return PodRuntime{}, err
	}
	manifest, images, err := renderPodManifest(&d.Pod, image)
	if err != nil {
		return PodRuntime{}, err
	}
	a["base"] = base
	a["node_tcb"] = false
	pull, err := bindCDSPull(a, d.CDS)
	if err != nil {
		return PodRuntime{}, err
	}
	if value, exists := pull["measure_policies"]; exists {
		enabled, ok := value.(bool)
		if !ok {
			return PodRuntime{}, fmt.Errorf("baked allowlist.pull.measure_policies must be a boolean")
		}
		if enabled {
			return PodRuntime{}, nriimagepolicy.ErrPodRoleMeasurePolicies
		}
	}
	// A Pod boot has no node namespaces, in-Pod credential clients or
	// platform services: its guest broker reaches CDS outside the Pod
	// network namespace, and its egress is the standalone ruleset's.
	delete(mesh, "credential_attestation_port")
	// No cluster DNS answers a pod CVM: the resolver the ruleset leaves
	// uncaptured is the first upstream its resolv.conf names.
	resolvers, err := podResolvers(rootDir)
	if err != nil {
		return PodRuntime{}, err
	}
	mesh["resolver"] = resolvers[0].String()
	peers, err := d.Pod.PeerAddresses()
	if err != nil {
		return PodRuntime{}, err
	}
	ports, err := d.Pod.IngressPorts()
	if err != nil {
		return PodRuntime{}, err
	}
	mesh["pod"] = map[string]any{"peers": peers, "ingress_ports": ports}
	// Standalone kubelet appends the guest's original launch name.
	floor["pod"] = map[string]any{"uid": d.Pod.UID, "namespace": d.Pod.Namespace, "name": d.Pod.Name + "-" + d.Node.Name, "images": images}
	floor["mesh"] = mesh
	// The pod profile is an overlay on the worker image, whose floor marks a
	// worker; the pod plugin's configuration is a pod's alone.
	delete(floor, "worker")
	policy["exempt_namespaces"] = []string{}
	delete(policy, "exempt_snapshot_path")
	policy["sandbox"] = "enforce"
	// Measure every started workload into RTMR[3], on top of the launch-key
	// seed the initrd extended from operator-pubkey's exact bytes, into the
	// journal under the baked inventory directory that pod-status reads.
	// A platform without the register cannot run measured pod workloads.
	if !d.Image.HasRuntimeRegister() {
		return PodRuntime{}, fmt.Errorf("pod role requires a platform with a runtime register; %s has none", d.Image.Platform)
	}
	floor["measure"] = map[string]any{"rtmr3": true}
	policyData, err := yaml.Marshal(floor)
	if err != nil {
		return PodRuntime{}, err
	}

	return PodRuntime{UID: d.Pod.UID, Policy: policyData, Manifest: manifest}, nil
}

func renderPodManifest(spec *podlaunch.PodSpec, image string) ([]byte, map[string]string, error) {
	pod, err := podlaunch.ParsePodManifest([]byte(spec.Manifest))
	if err != nil {
		return nil, nil, err
	}
	if err := podmesh.InjectEndpoint(pod, image); err != nil {
		return nil, nil, fmt.Errorf("pod mesh endpoint: %w", err)
	}
	images, err := podImagePins(pod)
	if err != nil {
		return nil, nil, err
	}
	// The guest owns DNS; no workload override changes the measured network contract.
	pod.Spec.DNSPolicy = corev1.DNSDefault
	pod.Spec.DNSConfig = nil
	manifest, err := kubeyaml.Marshal(pod)
	if err != nil {
		return nil, nil, fmt.Errorf("render pod manifest: %w", err)
	}
	return manifest, images, nil
}

// PreparePod publishes a pod CVM's CDS pin and stages its boot inputs from
// the verified launch document loaded by podlaunch.LoadStaged.
func PreparePod(rootDir string, d *podlaunch.Document) error {
	return preparePodDocument(rootDir, d, discoverPodMTU)
}

func preparePodDocument(rootDir string, d *podlaunch.Document, resolveMTU func() (int, error)) error {
	endpoint, err := d.CDS.Parse()
	if err != nil {
		return err
	}
	// The staged document is this Pod's only source for its CDS.
	cds, err := endpoint.Policy()
	if err != nil {
		return err
	}
	return preparePod(rootDir, d, map[string][]byte{CDSOutput: cds}, resolveMTU)
}

// preparePod stages boot inputs before the status service starts. It stages
// no runtime policy and no manifest: the assignment that supplies the Pod
// renders them, and the runtime, plugin and kubelet start only then (podstatus).
func preparePod(rootDir string, d *podlaunch.Document, outputs map[string][]byte, resolveMTU func() (int, error)) error {
	path := func(name string) string { return filepath.Join(rootDir, name) }
	cni, err := preparePodNetwork(rootDir, resolveMTU)
	if err != nil {
		return err
	}
	resolv, err := podResolvConf(rootDir)
	if err != nil {
		return err
	}

	if err := publishPublic(path(PublicDir), outputs); err != nil {
		return err
	}
	type output struct {
		path string
		data []byte
		mode os.FileMode
	}
	files := []output{
		{podKubeletEnvPath, []byte("KUBELET_HOSTNAME=" + d.Node.Name + "\n"), 0644},
		{podUnmanagedLinks, []byte(podUnmanagedConfig), 0644},
		{podCNIPath, cni, 0644},
		{podResolvConfPath, resolv, 0644},
	}
	if err := os.MkdirAll(path(PodDir+"/manifests"), 0700); err != nil {
		return err
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
		digest := canonical.Digest().String()
		if !types.IsCanonicalDigest(digest) {
			return nil, fmt.Errorf("pod container %q image must pin a canonical sha256 digest", container.Name)
		}
		images[container.Name] = digest
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
