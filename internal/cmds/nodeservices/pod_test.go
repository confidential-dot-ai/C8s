package nodeservices

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const podWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

const podEndpoint = `      c8s-mesh-endpoint:
        containers:
          - digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
            image: registry.test/mesh@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
            role: mesh
            command: {policy: exact, argv: [/app/c8s, armtls-mesh]}
            args: {policy: exact, argv: [--cert-path=/etc/c8s/certs/tls.crt, --key-path=/etc/c8s/certs/tls.key, --ca-path=/etc/c8s/certs/ca.crt]}
            mounts:
              policy: exact
              rules: [{destination: /etc/c8s/certs, kind: emptyDir, source: c8s-certs}]
      c8s-get-cert:
        containers:
          - digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
            role: credentials
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
`

// podFloor bakes a node's exit beside the shared mesh policy: a pod CVM must drop it.
var podFloor = strings.Replace(strings.Replace(floor, "  pull:", podEndpoint+"  pull:", 1), "  enforce_existing: true\n", "  enforce_existing: true\n  fatal_existing: true\n  boot_marker_path: /run/nri-image-policy/registered\n", 1) +
	strings.Replace(meshPolicy, "  resolver:", "  exits: [\"10.53.0.11:8080\"]\n  resolver:", 1)

// podManifestPath is where the assignment publishes the manifest; a generic
// prepare never does.
const podManifestPath = PodDir + "/manifests/pod.yaml"

func preparePodRoot(t *testing.T) string {
	t.Helper()
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(podFloor))
	data, err := os.ReadFile("../../../images/node-guest/c8s/mkosi.extra" + bakedPodCNIPath)
	if err != nil {
		t.Fatal(err)
	}
	writeInput(t, root, bakedPodCNIPath, data)
	resolved, err := os.ReadFile("../../../images/node-guest/c8s/mkosi.extra" + bakedResolvedConfDir + "/10-upstream.conf")
	if err != nil {
		t.Fatal(err)
	}
	writeInput(t, root, bakedResolvedConfDir+"/10-upstream.conf", resolved)
	writeAirgapArchive(t, root, "c8s-0.tar", map[string]string{"registry.test/operator@" + operatorDigest: operatorDigest})
	writeAirgapArchive(t, root, "c8s-1.tar", map[string]string{podMeshImage: podMeshDigest, "registry.test/mesh:c8s-node": podMeshDigest})
	return root
}

const (
	podMeshDigest  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	podMeshImage   = "registry.test/mesh@" + podMeshDigest
	operatorDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// writeAirgapArchive writes an archive as airgap-images.sh lays it out: an
// index.json naming each image for containerd, then the layout's blobs.
func writeAirgapArchive(t *testing.T, root, name string, images map[string]string) {
	t.Helper()
	var index ocispec.Index
	for ref, digest := range images {
		index.Manifests = append(index.Manifests, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: godigest.Digest(digest), Size: 1,
			Annotations: map[string]string{imageNameAnnotation: ref, ocispec.AnnotationRefName: ref}})
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, f := range []struct {
		name string
		data []byte
	}{{"index.json", data}, {"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"blobs/sha256/" + strings.Repeat("0", 64), []byte("{}")}} {
		if err := w.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	writeInput(t, root, airgapImagesDir+"/"+name, b.Bytes())
}

// The pod role imports its mesh endpoint from the archive the image
// preserves, the one that names the measured endpoint at its digest.
func TestPreparePodStagesTheMeshEndpointArchive(t *testing.T) {
	root := preparePodRoot(t)
	if err := preparePodFixture(root, podDocument(t)); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(filepath.Join(root, podMeshArchivePath)); err != nil || got != airgapImagesDir+"/c8s-1.tar" {
		t.Fatalf("mesh archive link = %q, %v", got, err)
	}
}

// Without exactly one archive that holds the endpoint at its measured digest,
// the pod role publishes nothing rather than pull the endpoint at start.
func TestPreparePodRefusesAMissingOrMismatchedMeshArchive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		images map[string]string
		want   string
	}{
		{"missing", nil, "found 0"},
		{"other digest", map[string]string{podMeshImage: operatorDigest}, "at digest " + operatorDigest},
		{"duplicate", map[string]string{podMeshImage: podMeshDigest}, "found 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			if tc.images == nil {
				if err := os.Remove(filepath.Join(root, airgapImagesDir, "c8s-1.tar")); err != nil {
					t.Fatal(err)
				}
			} else {
				writeAirgapArchive(t, root, "c8s-2.tar", tc.images)
			}
			if err := preparePodFixture(root, podDocument(t)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			for _, name := range []string{floorConfigPath, podManifestPath, podMeshArchivePath} {
				if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatalf("published %s without the mesh archive: %v", name, err)
				}
			}
		})
	}
}

func preparePodFixture(root string, doc *launchconfig.Document) error {
	return prepare(root, doc, func() (int, error) { return podDefaultMTU, nil })
}

const podManifest = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}`

// podDocument is the generic document a pod CVM boots under.
func podDocument(t *testing.T) *launchconfig.Document {
	t.Helper()
	doc := document(t, launchconfig.Pod)
	doc.ClusterID = "demo"
	doc.PodOperatorPublicKey = string(testPins(t).Images[1].Anchor)
	doc.Node.Name = "p-pod"
	return doc
}

// assignedPod is the generic document with the assignment every render test
// starts from: the test manifest, the signed entries and no peers.
func assignedPod(t *testing.T, manifest string) *launchconfig.AssignedPod {
	t.Helper()
	assigned, err := launchconfig.Assign(podDocument(t), []byte(manifest), []byte(podWorkloads), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	return assigned
}

func renderedPolicy(t *testing.T, runtime PodRuntime) map[string]any {
	t.Helper()
	var got map[string]any
	if err := yaml.Unmarshal(runtime.Policy, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// The pod role is refused on a platform without a runtime register.
func TestRenderPodRuntimeRefusesAPlatformWithoutARuntimeRegister(t *testing.T) {
	root := preparePodRoot(t)
	assigned := assignedPod(t, podManifest)
	assigned.Image.Platform, assigned.Image.RTMRs = "snp", nil
	if _, err := RenderPodRuntime(root, assigned); err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
}

// The assigned pod is rendered under the measured mesh policy and the floor
// applies with no exempt namespace.
func TestRenderPodRuntimeBindsCDSPullAndKeepsOnlyMeasuredMeshAndSignedBase(t *testing.T) {
	root := preparePodRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    interval: 7s\n    cds_pin_floor: 1\n    measure_policies: false", 1)))
	assigned := assignedPod(t, podManifest)
	runtime, err := RenderPodRuntime(root, assigned)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.UID != "u1" {
		t.Fatalf("runtime UID = %q", runtime.UID)
	}
	got := renderedPolicy(t, runtime)
	var before map[string]any
	if err := yaml.Unmarshal([]byte(podFloor), &before); err != nil {
		t.Fatal(err)
	}
	// One key: the journal lives under the baked inventory directory and the
	// seed is the staged launch key, neither of which the document chooses.
	if m := got["measure"].(map[string]any); m["rtmr3"] != true || len(m) != 1 {
		t.Fatalf("measure = %v", m)
	}
	a := got["allowlist"].(map[string]any)
	pull, ok := a["pull"].(map[string]any)
	if !ok || pull["url"] != cmdsutil.CDSURL(assigned.CDS.Address) || pull["cds_measurements_config"] != PublicDir+"/cds.json" || pull["timeout"] != "30s" || pull["interval"] != "7s" || pull["measure_policies"] != false {
		t.Fatalf("pod CDS pull = %v", pull)
	}
	if floor := publishedPinFloor(t, pull); floor != assigned.CDS.PinFloor {
		t.Fatalf("pod CDS pin floor = %d, want signed floor %d", floor, assigned.CDS.PinFloor)
	}
	for _, legacy := range []string{"cds_measurements", "cds_rtmrs"} {
		if _, exists := pull[legacy]; exists {
			t.Fatalf("pod CDS pull kept competing %s", legacy)
		}
	}
	writeInput(t, root, floorConfigPath, runtime.Policy)
	mesh := stagedMeshPolicy(t, root)
	// A pod CVM reaches no platform service of a cluster: the baked exits
	// are a node's.
	if len(mesh.ExemptNamespaces) != 0 || len(mesh.Exits) != 0 || len(mesh.Roles) != 1 || mesh.Roles[0].Name != workloadclaims.MeshRole {
		t.Fatalf("Pod mesh floor = %+v", mesh)
	}
	if !reflect.DeepEqual(mesh.Roles, []stagedRole{{Name: workloadclaims.MeshRole, UID: workloadclaims.MeshUID}}) || mesh.Capture != (stagedCapture{Outbound: 15001, Inbound: 15006, Health: 15021}) {
		t.Fatalf("baked mesh role or capture settings changed: %+v", mesh)
	}
	if resolver := got["mesh"].(map[string]any)["resolver"]; resolver != "10.53.0.10" {
		t.Fatalf("baked mesh resolver changed: %v", resolver)
	}
	if a["node_tcb"] != false {
		t.Fatal("pod workloads must not be exempt from the sandbox policy")
	}
	base, err := bakedBase(a["base"])
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Workloads) != 2 || len(base.Workloads["app"].Containers) != 1 || base.Workloads["c8s-mesh-endpoint"].Containers[0].Role != workloadclaims.MeshRole {
		t.Fatalf("base = %v, want signed workloads plus the measured endpoint", base.Workloads)
	}
	policy := got["policy"].(map[string]any)
	if policy["sandbox"] != "enforce" || policy["mode"] != "fail-closed" {
		t.Fatalf("policy = %v", policy)
	}
	delete(policy, "sandbox")
	delete(policy, "exempt_namespaces")
	if !reflect.DeepEqual(policy, before["policy"]) {
		t.Fatal("changed baked enforcement policy beyond sandbox")
	}
	pod, err := launchconfig.ParsePodManifest(runtime.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != workloadclaims.MeshContainerName || !pod.Spec.InitContainers[0].VolumeMounts[0].ReadOnly || pod.Spec.Volumes[0].Name != podmesh.CertVolumeName {
		t.Fatalf("rendered endpoint = %+v", pod.Spec)
	}
}

// A generic boot stages its network and kubelet inputs, no runtime policy and
// no manifest, and nothing of a server boot.
func TestPreparePodStagesNoWorkload(t *testing.T) {
	root := preparePodRoot(t)
	// A server boot earlier must not leave its inputs to the pod.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	if err := preparePodFixture(root, podDocument(t)); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		podKubeletEnvPath: "KUBELET_HOSTNAME=p-pod\n",
		podUnmanagedLinks: podUnmanagedConfig,
	} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	for _, path := range []string{floorConfigPath, podManifestPath, PublicDir + "/allowlist-seed.json"} {
		if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Fatalf("generic boot staged %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "peers.json")); err != nil {
		t.Fatal(err)
	}
}

// The assigned pod's DNS policy is the guest's and the manifest's resolver
// configuration is dropped.
func TestRenderPodRuntimeUsesGuestUpstreamDNS(t *testing.T) {
	root := preparePodRoot(t)
	assigned := assignedPod(t, strings.Replace(podManifest, `"spec":{`, `"spec":{"dnsPolicy":"None","dnsConfig":{"nameservers":["10.255.254.1"],"searches":["tenant.invalid"],"options":[{"name":"ndots","value":"5"}]},`, 1))
	runtime, err := RenderPodRuntime(root, assigned)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := launchconfig.ParsePodManifest(runtime.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.DNSPolicy != corev1.DNSDefault || pod.Spec.DNSConfig != nil {
		t.Fatalf("rendered DNS policy = %q, config = %+v", pod.Spec.DNSPolicy, pod.Spec.DNSConfig)
	}
}

func TestRenderPodRuntimePinsImagesForInitSidecarsAndApplications(t *testing.T) {
	root := preparePodRoot(t)
	initPin := "sha256:" + strings.Repeat("c", 64)
	sidecarPin := "sha256:" + strings.Repeat("a", 64)
	assigned := assignedPod(t, strings.Replace(podManifest, `"containers":[`,
		`"initContainers":[{"name":"setup","image":"repo@`+initPin+`"},{"name":"native-sidecar","image":"repo@`+sidecarPin+`","restartPolicy":"Always"}],"containers":[`, 1))
	runtime, err := RenderPodRuntime(root, assigned)
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Pod struct {
			Images map[string]string `yaml:"images"`
		} `yaml:"pod"`
	}
	if err := yaml.Unmarshal(runtime.Policy, &staged); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"app":                            "sha256:" + strings.Repeat("b", 64),
		"setup":                          initPin,
		"native-sidecar":                 sidecarPin,
		workloadclaims.MeshContainerName: "sha256:" + strings.Repeat("d", 64),
	}
	if !reflect.DeepEqual(staged.Pod.Images, want) {
		t.Fatalf("rendered image pins = %v, want %v", staged.Pod.Images, want)
	}
}

// The renderer binds every container to a canonical digest itself, whatever
// the assignment's own checks accepted.
func TestRenderPodRuntimeRefusesIncompleteImageBindings(t *testing.T) {
	for _, tc := range []struct{ name, containers string }{
		{"invalid name", `{"name":"../app","image":"repo@sha256:` + strings.Repeat("b", 64) + `"}`},
		{"duplicate name", `{"name":"app","image":"repo@sha256:` + strings.Repeat("b", 64) + `"},{"name":"app","image":"repo@sha256:` + strings.Repeat("c", 64) + `"}`},
		{"mutable tag", `{"name":"app","image":"repo:latest"}`},
		{"missing image", `{"name":"app"}`},
		{"noncanonical digest", `{"name":"app","image":"repo@sha256:` + strings.Repeat("A", 64) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			assigned := assignedPod(t, podManifest)
			assigned.Pod.Manifest = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[` + tc.containers + `]}}`
			if _, err := RenderPodRuntime(root, assigned); err == nil {
				t.Fatal("incomplete image identity was rendered")
			}
		})
	}
}

// A rejected assignment or baked floor renders nothing. A missing platform
// endpoint or role cannot be repaired by tenant policy.
func TestRenderPodRuntimeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		floor  string
		change func(*launchconfig.AssignedPod)
		want   string
	}{
		{"no CDS address", podFloor, func(a *launchconfig.AssignedPod) { a.CDS.Address = "" }, "cds.address"},
		{"bad entries", podFloor, func(a *launchconfig.AssignedPod) { a.Entries = "{" }, "assignment entries"},
		{"bad manifest", podFloor, func(a *launchconfig.AssignedPod) { a.Pod.Manifest = "kind: Deployment" }, "pod.manifest"},
		{"no endpoint", meshFloor, func(*launchconfig.AssignedPod) {}, "no mesh endpoint"},
		{"no mesh policy", floor, func(*launchconfig.AssignedPod) {}, "missing mesh"},
		{"no mesh role", strings.Replace(podFloor, "name: mesh", "name: untrusted", 1), func(*launchconfig.AssignedPod) {}, "exactly one mesh role"},
		{"no restart detection", strings.Replace(podFloor, "  fatal_existing: true\n", "", 1), func(*launchconfig.AssignedPod) {}, "fatal_existing"},
		{"no boot marker", strings.Replace(podFloor, "  boot_marker_path: /run/nri-image-policy/registered\n", "", 1), func(*launchconfig.AssignedPod) {}, "boot_marker_path"},
		{"tenant endpoint collision", podFloor, func(a *launchconfig.AssignedPod) {
			a.Entries = strings.Replace(podWorkloads, `"app"`, `"c8s-mesh-endpoint"`, 1)
		}, "replaces a baked component"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(tc.floor))
			assigned := assignedPod(t, podManifest)
			tc.change(assigned)
			runtime, err := RenderPodRuntime(root, assigned)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if runtime.Policy != nil || runtime.Manifest != nil {
				t.Fatal("rendered policy from a rejected assignment")
			}
		})
	}
}

// A floor that also measures served policies into the register is refused.
func TestRenderPodRuntimeRejectsCompetingPolicyMeasurements(t *testing.T) {
	root := preparePodRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    measure_policies: true", 1)))
	if _, err := RenderPodRuntime(root, assignedPod(t, podManifest)); !errors.Is(err, nriimagepolicy.ErrPodRoleMeasurePolicies) {
		t.Fatalf("got %v, want the competing RTMR writer refusal", err)
	}
}
