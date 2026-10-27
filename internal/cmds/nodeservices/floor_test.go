package nodeservices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The measured floor's RKE2 launches are what RKE2 ran on booted nodes of the
// pinned image, captured in testdata/rke2-system-pods (`kubectl get pods -n
// kube-system -o json | jq -f capture.jq`). An RKE2 pin bump changes the
// digests, so this fails until the capture is redone.
const (
	nodeImagePolicyTemplate = "../../../node-guest-image/c8s/image-policy.yaml.in"
	capturedPodsDir         = "testdata/rke2-system-pods"
)

// capturedNode is a node whose system pods were captured, with the node
// values its staged launch document carried.
type capturedNode struct {
	capture string
	role    launchconfig.Role
	node    launchconfig.Node
}

// capturedNodes are the server and the agent of one cluster, whose launch
// documents give no node IP; a server whose launch staging recorded the
// address it autodetected as its node IP; and one that also names an
// external IP.
var capturedNodes = []capturedNode{
	{"server-and-agent.json", launchconfig.Server, launchconfig.Node{Name: "floorinv-server"}},
	{"server-and-agent.json", launchconfig.Agent, launchconfig.Node{Name: "a1"}},
	{"autodetected-server.json", launchconfig.Server, launchconfig.Node{Name: "floorpins-server", IP: "192.168.122.191"}},
	{"external-ip-server.json", launchconfig.Server, launchconfig.Node{Name: "floorpinsext-server", IP: "192.168.122.191", ExternalIP: "192.0.2.77"}},
}

// Every captured container is admitted on its node, and every floor container
// that pins the command of a captured image admits one of them, so the floor
// holds no pin RKE2 does not launch.
func TestPreparedFloorAdmitsTheCapturedSystemPods(t *testing.T) {
	entrypoints := capturedEntrypoints(t)
	pinsOfCapturedImages, launched := map[string]bool{}, map[string]bool{}
	for _, captured := range capturedNodes {
		floor := envOpen(preparedFloor(t, captured.role, captured.node))
		if got, want := advertiseAddressFlags(floor), advertiseAddressFlagsFor(captured.node); !slices.Equal(got, want) {
			t.Errorf("node %s: kube-apiserver's pinned address flags are %q, want %q", captured.node.Name, got, want)
		}
		launches := capturedLaunches(t, captured.capture, captured.node.Name, entrypoints)
		if len(launches) == 0 {
			t.Fatalf("%s holds no pod of node %s", captured.capture, captured.node.Name)
		}
		index := floor.BuildIndex()
		for _, launch := range launches {
			if !index.AdmitsContainer(launch.running) {
				t.Errorf("node %s: the floor refuses %s, which ran with argv %q and mounts %+v", captured.node.Name, launch.name, launch.running.Argv, launch.running.Mounts)
			}
		}
		for key, c := range commandPins(floor) {
			if !slices.ContainsFunc(launches, func(l capturedLaunch) bool { return l.running.Digest == c.Digest.String() }) {
				continue
			}
			pinsOfCapturedImages[key] = true
			if slices.ContainsFunc(launches, func(l capturedLaunch) bool { return admitsAlone(c, l.running) }) {
				launched[key] = true
			}
		}
	}
	for key := range pinsOfCapturedImages {
		if !launched[key] {
			t.Errorf("floor container %s admits no captured launch", key)
		}
	}
}

// envOpen is base with every environment policy set to any: the capture has
// no container environment (the nri-image-policy package checks the Cilium
// env pins against crictl records).
func envOpen(base *allowlist.Allowlist) *allowlist.Allowlist {
	for name, w := range base.Workloads {
		for _, containers := range [][]allowlist.Container{w.InitContainers, w.Containers} {
			for i := range containers {
				containers[i].Env = allowlist.EnvPolicy{Policy: allowlist.PolicyAny}
			}
		}
		base.Workloads[name] = w
	}
	return base
}

// advertiseAddressFlags are the address flags of kube-apiserver's pin.
func advertiseAddressFlags(floor *allowlist.Allowlist) []string {
	var flags []string
	for _, element := range floor.Workloads["kube-apiserver"].Containers[0].Args.Argv {
		if strings.HasPrefix(element, "--advertise-address=") {
			flags = append(flags, element)
		}
	}
	return flags
}

// advertiseAddressFlagsFor is the address flag RKE2 passes kube-apiserver on
// a node: none when the node has no address.
func advertiseAddressFlagsFor(node launchconfig.Node) []string {
	if node.AdvertiseAddress() == "" {
		return nil
	}
	return []string{"--advertise-address=" + node.AdvertiseAddress()}
}

// preparedFloor is the base allowlist boot preparation writes for a node,
// from the measured template with its build-time values filled in.
func preparedFloor(t *testing.T, role launchconfig.Role, node launchconfig.Node) *allowlist.Allowlist {
	t.Helper()
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", renderedNodeImagePolicy(t))
	doc := document(t, role)
	doc.Node = node
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	if err := policy.Allowlist.Base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return &policy.Allowlist.Base
}

// renderedNodeImagePolicy fills in the values mkosi.sync substitutes at image
// build.
func renderedNodeImagePolicy(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(nodeImagePolicyTemplate)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(data)
	for placeholder, value := range map[string]string{
		"@PLATFORM@":        "tdx",
		"@MESH_REPO@":       "ghcr.io/confidential-dot-ai/armtls-mesh",
		"@MESH_DIGEST@":     "sha256:" + strings.Repeat("1b", 32),
		"@OPERATOR_REPO@":   "ghcr.io/confidential-dot-ai/c8s-operator",
		"@OPERATOR_DIGEST@": "sha256:" + strings.Repeat("2c", 32),
		"@ROUTER_REPO@":     "docker.io/nginxinc/nginx-unprivileged",
		"@ROUTER_DIGEST@":   "sha256:" + strings.Repeat("3d", 32),
	} {
		rendered = strings.ReplaceAll(rendered, placeholder, value)
	}
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindString(rendered); left != "" {
		t.Fatalf("the template names a build-time value this test does not fill: %s", left)
	}
	return []byte(rendered)
}

// commandPins are the base's containers that pin a command, keyed by entry,
// container list and position.
func commandPins(base *allowlist.Allowlist) map[string]allowlist.Container {
	pins := map[string]allowlist.Container{}
	for name, w := range base.Workloads {
		for list, containers := range map[string][]allowlist.Container{"initContainers": w.InitContainers, "containers": w.Containers} {
			for i, c := range containers {
				if c.Command.Policy == allowlist.PolicyExact {
					pins[fmt.Sprintf("%s %s[%d]", name, list, i)] = c
				}
			}
		}
	}
	return pins
}

// admitsAlone reports whether c admits r with no other container's help.
func admitsAlone(c allowlist.Container, r allowlist.RunningContainer) bool {
	one := allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"c": {Containers: []allowlist.Container{c}}}}
	return one.BuildIndex().AdmitsContainer(r)
}

// capturedPods is the slice of `kubectl get pods -o json` the capture keeps.
type capturedPods struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec   corev1.PodSpec `json:"spec"`
		Status struct {
			ContainerStatuses []corev1.ContainerStatus `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// capturedLaunch is one captured container as the node's admission sees it.
type capturedLaunch struct {
	name    string
	running allowlist.RunningContainer
}

// capturedLaunches are the launches of the captured pods on one node. Each
// carries the digest containerd ran, the argv the kubelet handed it and the
// mounts the pod's volumes give it.
func capturedLaunches(t *testing.T, capture, node string, entrypoints map[string][]string) []capturedLaunch {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(capturedPodsDir, capture))
	if err != nil {
		t.Fatal(err)
	}
	var pods capturedPods
	if err := json.Unmarshal(data, &pods); err != nil {
		t.Fatal(err)
	}
	var launches []capturedLaunch
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != node {
			continue
		}
		ran := map[string]string{}
		for _, s := range pod.Status.ContainerStatuses {
			_, ran[s.Name], _ = strings.Cut(s.ImageID, "@")
		}
		volumes := map[string]corev1.Volume{}
		for _, v := range pod.Spec.Volumes {
			volumes[v.Name] = v
		}
		for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
			digest, captured := ran[c.Name]
			if !captured {
				t.Fatalf("%s: the capture has no status for %s, so no digest it ran", pod.Metadata.Name, c.Name)
			}
			if digest == "" {
				continue // not started when captured: nothing ran to admit
			}
			launches = append(launches, capturedLaunch{
				name: pod.Metadata.Name + "/" + c.Name,
				running: allowlist.RunningContainer{
					Digest: digest,
					Argv:   kubeletExpanded(launchArgv(c, entrypoints[digest]), c.Env, pod.Metadata.Namespace),
					Mounts: launchMounts(t, c, volumes),
				},
			})
		}
	}
	return launches
}

// launchArgv is the argv the kubelet hands the runtime: the container's
// command, else the image's entrypoint, then its args.
func launchArgv(c corev1.Container, entrypoint []string) []string {
	if len(c.Command) == 0 {
		return slices.Concat(entrypoint, c.Args)
	}
	return slices.Concat(c.Command, c.Args)
}

// kubeletExpanded is argv with each $(NAME) the container's env defines
// replaced by its value, as the kubelet does: a literal value, or the pod's
// namespace from the downward API.
func kubeletExpanded(argv []string, env []corev1.EnvVar, namespace string) []string {
	values := map[string]string{}
	for _, e := range env {
		switch {
		case e.ValueFrom == nil:
			values[e.Name] = e.Value
		case e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.namespace":
			values[e.Name] = namespace
		}
	}
	expanded := make([]string, len(argv))
	for i, element := range argv {
		for name, value := range values {
			element = strings.ReplaceAll(element, "$("+name+")", value)
		}
		expanded[i] = element
	}
	return expanded
}

// launchMounts are the container's volume mounts as the node classifies
// them.
func launchMounts(t *testing.T, c corev1.Container, volumes map[string]corev1.Volume) []allowlist.ObservedMount {
	t.Helper()
	mounts := make([]allowlist.ObservedMount, 0, len(c.VolumeMounts))
	for _, m := range c.VolumeMounts {
		mount, err := nodeClassifiedMount(m, volumes[m.Name])
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

// nodeClassifiedMount is a hostPath as a host mount of its path, the service account
// token as a platform mount, an emptyDir as the pod's scratch, and any other
// volume as data.
func nodeClassifiedMount(m corev1.VolumeMount, v corev1.Volume) (allowlist.ObservedMount, error) {
	if v.HostPath != nil {
		digest, err := allowlist.HostSourceDigest(v.HostPath.Path)
		return allowlist.ObservedMount{Destination: m.MountPath, Class: allowlist.MountHost, HostSourceDigest: digest, ReadOnly: m.ReadOnly, Storage: allowlist.MountUnknown}, err
	}
	volume := allowlist.ObservedMount{Destination: m.MountPath, Volume: m.Name, ReadOnly: m.ReadOnly, Storage: allowlist.MountEncrypted}
	switch {
	case m.MountPath == serviceAccountMountPath:
		volume.Class = allowlist.MountPlatform
	case v.EmptyDir != nil:
		volume.Class = allowlist.MountEmptyDir
	default:
		volume.Class = allowlist.MountData
	}
	return volume, nil
}

const serviceAccountMountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// capturedEntrypoints are the entrypoints of the captured images that run
// without a command, by digest (`crane config` of each image).
func capturedEntrypoints(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(capturedPodsDir, "image-entrypoints.json"))
	if err != nil {
		t.Fatal(err)
	}
	var images map[string]struct {
		Entrypoint []string `json:"entrypoint"`
	}
	if err := json.Unmarshal(data, &images); err != nil {
		t.Fatal(err)
	}
	entrypoints := make(map[string][]string, len(images))
	for digest, image := range images {
		entrypoints[digest] = image.Entrypoint
	}
	return entrypoints
}

func TestFillingRefusesAPlaceholderTheFloorDoesNotDefine(t *testing.T) {
	for _, element := range []string{"${NODE_NAME}", "--hostname-override=n-${NODE_NAME}", "--hostname-override=${NODE}"} {
		base := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"w": {Containers: []allowlist.Container{{
			Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{element}},
		}}}}}
		if err := fillNodeValues(base, launchconfig.Node{Name: "n1"}); err == nil {
			t.Errorf("filled %q", element)
		}
	}
}

// A pinned script's own shell variables are not floor placeholders.
func TestFillingKeepsAScriptsOwnVariables(t *testing.T) {
	script := `nsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT`
	base := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"w": {Containers: []allowlist.Container{{
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"bash", "-ec", script}},
	}}}}}
	if err := fillNodeValues(base, launchconfig.Node{Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if got := base.Workloads["w"].Containers[0].Command.Argv[2]; got != script {
		t.Errorf("script = %q, want it unchanged", got)
	}
}
