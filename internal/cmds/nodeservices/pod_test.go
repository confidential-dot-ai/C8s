package nodeservices

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const podWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

func podDocument(t *testing.T) *launchconfig.Document {
	t.Helper()
	doc := document(t, launchconfig.Pod)
	doc.PodOperatorPublicKey = string(testPins(t).Images[1].Anchor)
	doc.Node.Name = "p-pod"
	doc.Workloads = podWorkloads
	doc.Pod = &launchconfig.PodSpec{UID: "u1", Namespace: "tenant", Name: "app",
		Manifest: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[{"name":"app","image":"busybox"}]}}`}
	return doc
}

// podMeshDigest is the baked mesh endpoint's image, bound to no signed entry.
const podMeshDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// podFloor is the baked config as a pod CVM reads it: the node's base carries
// its own components and every platform role beside the mesh endpoint, and
// the measured mesh policy binds the mesh role.
const podFloor = `platform: tdx
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      system:
        containers:
          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            command: {policy: any}
            args: {policy: any}
      c8s-mesh-endpoint:
        containers:
          - digest: ` + podMeshDigest + `
            role: "mesh"
            command: {policy: exact, argv: ["/app/c8s", "armtls-mesh"]}
            args: {policy: exact, argv: ["--cert-path=/etc/c8s/certs/tls.crt"]}
            mounts:
              policy: exact
              rules:
                - destination: "/etc/c8s/certs"
                  kind: "emptyDir"
                  source: "c8s-certs"
      c8s-get-cert:
        containers:
          - digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
            role: "credentials"
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
    cds_measurements: []
policy:
  mode: fail-closed
  enforce_existing: true
` + meshPolicy

// preparePodRoot stages a pod CVM's inputs: a node's, under the baked config
// a pod boots with.
func preparePodRoot(t *testing.T) string {
	t.Helper()
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(podFloor))
	return root
}

func TestPreparePodRefusesAPlatformWithoutARuntimeRegister(t *testing.T) {
	root := preparePodRoot(t)
	doc := podDocument(t)
	doc.Image.Platform = "snp"
	// Prepare checks the staged pins' family first; the pod step is what
	// must refuse, so call it as Prepare would.
	err := preparePod(root, doc, map[string][]byte{})
	if err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
		t.Fatalf("policy written without measurement: %v", err)
	}
}

// The pod role keeps two things of the baked base and mesh policy: the mesh
// endpoint's measured entry, which admits that image under that argv and
// binds it to the mesh role, and the role's identity binding. Every other
// baked component and role is a node's, and every signed workload holds no
// role; the pod has no namespace the mesh exempts.
func TestPreparePodBindsCDSPullAndKeepsOnlyTheMeshEndpointOfTheBakedBase(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    interval: 7s\n    measure_policies: false", 1)))
	// A server boot earlier must not leave its inputs to the pod.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	doc := podDocument(t)
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, nriPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	var got, before map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(floor), &before); err != nil {
		t.Fatal(err)
	}
	// One key: the journal lives under the baked inventory directory and the
	// seed is the staged launch key, neither of which the document chooses.
	if m := got["measure"].(map[string]any); m["rtmr3"] != true || len(m) != 1 {
		t.Fatalf("measure = %v", m)
	}
	a := got["allowlist"].(map[string]any)
	pull, ok := a["pull"].(map[string]any)
	if !ok || pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" || pull["timeout"] != "30s" || pull["interval"] != "7s" || pull["measure_policies"] != false {
		t.Fatalf("pod CDS pull = %v", pull)
	}
	for _, legacy := range []string{"cds_measurements", "cds_rtmrs"} {
		if _, exists := pull[legacy]; exists {
			t.Fatalf("pod CDS pull kept competing %s", legacy)
		}
	}
	var staged struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	base := staged.Allowlist.Base.Workloads
	if len(base) != 2 || base["app"].Containers[0].Role != "" || base["c8s-mesh-endpoint"].Containers[0].Role != "mesh" {
		t.Fatalf("staged base = %+v, want the signed app and the baked mesh endpoint alone", base)
	}
	if got := base["c8s-mesh-endpoint"].Containers[0].Digest.String(); got != podMeshDigest {
		t.Fatalf("staged mesh endpoint digest = %s", got)
	}
	mesh := stagedMeshPolicy(t, root)
	if len(mesh.ExemptNamespaces) != 0 {
		t.Fatalf("exempt namespaces = %v: every pod of a pod CVM is a member", mesh.ExemptNamespaces)
	}
	if !reflect.DeepEqual(mesh.Roles, []stagedRole{{Name: "mesh", UID: workloadclaims.MeshUID}}) {
		t.Fatalf("staged roles = %+v, want the mesh role alone", mesh.Roles)
	}
	if mesh.Capture != (stagedCapture{Outbound: 15001, Inbound: 15006, Health: 15021}) {
		t.Fatalf("staged capture = %+v changed from the baked one", mesh.Capture)
	}
	if resolver := got["mesh"].(map[string]any)["resolver"]; resolver != "10.53.0.10" {
		t.Fatalf("staged resolver = %v changed from the baked one", resolver)
	}
	if a["node_tcb"] != false {
		t.Fatal("pod workloads must not be exempt from the sandbox policy")
	}
	policy := got["policy"].(map[string]any)
	if policy["sandbox"] != "enforce" || policy["mode"] != "fail-closed" {
		t.Fatalf("policy = %v", policy)
	}
	delete(policy, "sandbox")
	if !reflect.DeepEqual(policy, before["policy"]) {
		t.Fatal("changed baked enforcement policy beyond sandbox")
	}

	for path, want := range map[string]string{
		podManifestPath:   doc.Pod.Manifest,
		podKubeletEnvPath: "KUBELET_HOSTNAME=p-pod\n",
		podUnmanagedLinks: podUnmanagedConfig,
	} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("pod kept a server output")
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "peers.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePodFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*launchconfig.Document)
		want   string
	}{
		{"no pod", func(d *launchconfig.Document) { d.Pod = nil }, "requires a pod"},
		{"no workloads", func(d *launchconfig.Document) { d.Workloads = "" }, "requires a pod"},
		{"empty workloads", func(d *launchconfig.Document) { d.Workloads = `{"schema":"c8s.allowlist/v1","workloads":{}}` }, "nonempty workloads base"},
		{"no CDS address", func(d *launchconfig.Document) { d.Server.Address = "" }, "server.address"},
		{"invalid CDS address", func(d *launchconfig.Document) { d.Server.Address = "127.0.0.1" }, "server.address"},
		{"bad workloads", func(d *launchconfig.Document) { d.Workloads = "{" }, "launch workloads"},
		{"bad manifest", func(d *launchconfig.Document) { d.Pod.Manifest = "kind: Deployment" }, "pod.manifest"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			doc := podDocument(t)
			tc.change(doc)
			err := Prepare(root, doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
				t.Fatal("published NRI policy from a rejected pod launch")
			}
		})
	}
}

func TestPreparePodRejectsCompetingPolicyMeasurementsBeforePublication(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    measure_policies: true", 1)))
	if err := Prepare(root, podDocument(t)); !errors.Is(err, nriimagepolicy.ErrPodRoleMeasurePolicies) {
		t.Fatalf("got %v, want the competing RTMR writer refusal", err)
	}
	for _, path := range []string{nriPolicyPath, podManifestPath, PublicDir + "/cds.json"} {
		if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Fatalf("published %s after refusing the RTMR writer: %v", path, err)
		}
	}
}

// A pod CVM is a mesh member or nothing: a baked config that binds no mesh
// endpoint, or carries no mesh policy, stages no pod, and the signed workloads
// cannot redefine the endpoint's measured entry.
func TestPreparePodRequiresTheBakedMeshEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		floor  string
		change func(*launchconfig.Document)
		want   string
	}{
		{"baked base binds no mesh endpoint", meshFloor, func(*launchconfig.Document) {}, "mesh role"},
		{"baked policy without mesh", floor, func(*launchconfig.Document) {}, "missing mesh"},
		{"signed workloads name the baked endpoint", podFloor, func(d *launchconfig.Document) {
			d.Workloads = strings.Replace(podWorkloads, `"app"`, `"c8s-mesh-endpoint"`, 1)
		}, "replaces a baked component"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(tc.floor))
			doc := podDocument(t)
			tc.change(doc)
			err := Prepare(root, doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
				t.Fatal("published NRI policy from a rejected pod launch")
			}
		})
	}
}
