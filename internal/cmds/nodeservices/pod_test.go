package nodeservices

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

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

var podFloor = strings.Replace(floor, "  pull:", podEndpoint+"  pull:", 1) + meshPolicy

func preparePodRoot(t *testing.T) string {
	t.Helper()
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(podFloor))
	data, err := os.ReadFile("../../../node-guest-image/c8s/mkosi.extra" + bakedPodCNIPath)
	if err != nil {
		t.Fatal(err)
	}
	writeInput(t, root, bakedPodCNIPath, data)
	return root
}

func preparePodFixture(root string, doc *launchconfig.Document) error {
	return prepare(root, doc, func() (int, error) { return podDefaultMTU, nil })
}

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

func TestPreparePodRefusesAPlatformWithoutARuntimeRegister(t *testing.T) {
	root := preparePodRoot(t)
	doc := podDocument(t)
	doc.Image.Platform = "snp"
	// Prepare checks the staged pins' family first; the pod step is what
	// must refuse, so call it as Prepare would.
	err := preparePod(root, doc, map[string][]byte{}, func() (int, error) { return podDefaultMTU, nil })
	if err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
		t.Fatalf("policy written without measurement: %v", err)
	}
}

func TestPreparePodBindsCDSPullAndKeepsOnlyMeasuredMeshAndSignedBase(t *testing.T) {
	root := preparePodRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    interval: 7s\n    measure_policies: false", 1)))
	// A server boot earlier must not leave its inputs to the pod.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	doc := podDocument(t)
	if err := preparePodFixture(root, doc); err != nil {
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
	if !ok || pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" || pull["timeout"] != "30s" || pull["interval"] != "7s" || pull["measure_policies"] != false {
		t.Fatalf("pod CDS pull = %v", pull)
	}
	for _, legacy := range []string{"cds_measurements", "cds_rtmrs"} {
		if _, exists := pull[legacy]; exists {
			t.Fatalf("pod CDS pull kept competing %s", legacy)
		}
	}
	mesh := stagedMeshPolicy(t, root)
	if len(mesh.ExemptNamespaces) != 0 || len(mesh.Roles) != 1 || mesh.Roles[0].Name != workloadclaims.MeshRole {
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

	for path, want := range map[string]string{
		podKubeletEnvPath: "KUBELET_HOSTNAME=p-pod\n",
		podUnmanagedLinks: podUnmanagedConfig,
	} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(root, podManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	pod, err := launchconfig.ParsePodManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != workloadclaims.MeshContainerName || !pod.Spec.InitContainers[0].VolumeMounts[0].ReadOnly || pod.Spec.Volumes[0].Name != podmesh.CertVolumeName {
		t.Fatalf("staged endpoint = %+v", pod.Spec)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("pod kept a server output")
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "peers.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePodUsesGuestUpstreamDNS(t *testing.T) {
	for _, tc := range []struct{ name, dns string }{
		{"omitted", ``},
		{"cluster", `"dnsPolicy":"ClusterFirst",`},
		{"default", `"dnsPolicy":"Default",`},
		{"custom", `"dnsPolicy":"None","dnsConfig":{"nameservers":["10.255.254.1"],"searches":["tenant.invalid"],"options":[{"name":"ndots","value":"5"}]},`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			doc := podDocument(t)
			doc.Pod.Manifest = strings.Replace(doc.Pod.Manifest, `"spec":{`, `"spec":{`+tc.dns, 1)
			if err := preparePodFixture(root, doc); err != nil {
				t.Fatal(err)
			}
			manifest, err := os.ReadFile(filepath.Join(root, podManifestPath))
			if err != nil {
				t.Fatal(err)
			}
			pod, err := launchconfig.ParsePodManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if pod.Spec.DNSPolicy != corev1.DNSDefault || pod.Spec.DNSConfig != nil {
				t.Fatalf("prepared DNS policy = %q, config = %+v", pod.Spec.DNSPolicy, pod.Spec.DNSConfig)
			}
		})
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
			err := preparePodFixture(root, doc)
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
	root := preparePodRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    measure_policies: true", 1)))
	if err := preparePodFixture(root, podDocument(t)); !errors.Is(err, nriimagepolicy.ErrPodRoleMeasurePolicies) {
		t.Fatalf("got %v, want the competing RTMR writer refusal", err)
	}
	for _, path := range []string{nriPolicyPath, podManifestPath, PublicDir + "/cds.json"} {
		if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Fatalf("published %s after refusing the RTMR writer: %v", path, err)
		}
	}
}

// A missing platform endpoint or role cannot be repaired by tenant policy.
func TestPreparePodRequiresTheBakedMeshEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		floor  string
		change func(*launchconfig.Document)
		want   string
	}{
		{"no endpoint", meshFloor, func(*launchconfig.Document) {}, "no mesh endpoint"},
		{"no mesh policy", floor, func(*launchconfig.Document) {}, "missing mesh"},
		{"no mesh role", strings.Replace(podFloor, "name: mesh", "name: untrusted", 1), func(*launchconfig.Document) {}, "exactly one mesh role"},
		{"tenant endpoint collision", podFloor, func(d *launchconfig.Document) {
			d.Workloads = strings.Replace(podWorkloads, `"app"`, `"c8s-mesh-endpoint"`, 1)
		}, "replaces a baked component"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(tc.floor))
			doc := podDocument(t)
			tc.change(doc)
			if err := preparePodFixture(root, doc); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
				t.Fatal("published policy from a rejected Pod launch")
			}
		})
	}
}
