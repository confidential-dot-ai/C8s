package podlaunch

import (
	"context"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

const (
	testPodUID       = "0b7c6f9e-3c1a-4d3e-9a51-2f0c1d2e3f40"
	testPodWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
)

func testPodManifest(spec string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + testPodUID +
		`"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]` + spec + `}}`
}

// A pod document stages its trust and no workload authority, and nothing of
// a cluster node.
func TestStagePodRole(t *testing.T) {
	doc, key, pub := testPodDocument(t, "tdx")
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	requirePresent(t, cfg.path(PodMarker))
	for _, path := range []string{Dir + "/workloads.json", Dir + "/cds.json", Dir + "/peers.json"} {
		requireAbsent(t, cfg.path(path))
	}
	for path, want := range map[string]string{Dir + "/operator-pubkey": pub} {
		got, err := os.ReadFile(cfg.path(path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Role != Pod || staged.PodOperatorPublicKey != pub || staged.CDS != doc.CDS {
		t.Fatalf("staged %+v", staged)
	}
	cds := stagedCDSPolicy(t, staged)
	if cds.Family != teetypes.FamilySNP || len(cds.Images) != 2 {
		t.Fatalf("pod CDS pins = %+v", cds)
	}
	for _, pin := range cds.Images {
		if string(pin.LaunchFile) != cdsLaunchFile || pin.Anchor != nil {
			t.Fatalf("Pod CDS pin is not independently launch-file-bound: %+v", pin)
		}
	}

	if err := clearOutputs(cfg); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, cfg.path(PodMarker))
	requireAbsent(t, cfg.path(Dir+"/workloads.json"))
}

// The pod launch key is the document's single signing key, matched by
// its exact bytes; the cluster server's key authorizes no pod launch.
func TestVerifyRequiresTheExactPodLaunchKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (doc Document, signer *ecdsa.PrivateKey, loaded string)
		want  string
	}{
		{"another launch key", func(t *testing.T) (Document, *ecdsa.PrivateKey, string) {
			doc, _, _ := testPodDocument(t, "tdx")
			other, pub := testKey(t)
			return doc, other, pub
		}, "pod launch key does not match"},
		{"differently encoded key", func(t *testing.T) (Document, *ecdsa.PrivateKey, string) {
			doc, key, pub := testPodDocument(t, "tdx")
			doc.PodOperatorPublicKey = strings.TrimSpace(pub)
			return doc, key, pub
		}, "podOperatorPublicKey bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, signer, loaded := tc.setup(t)
			testLoader(t, doc, loaded)
			cfg := testConfig(t, doc, signer)
			if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			requireAbsent(t, cfg.path(PodMarker))
		})
	}
}

// Every refusal of a pod document, one row per check. A pod section or
// allowlist entries are unknown keys: a pod document is always generic.
func TestValidatePodRole(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Document)
		append string
		want   string
	}{
		{"no CDS policy", func(d *Document) { d.CDS.Measurements = "" }, "", "cds.measurements"},
		{"no pod key", func(d *Document) { d.PodOperatorPublicKey = "" }, "", "podOperatorPublicKey"},
		{"no runtime register", func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "", "runtime register"},
		{"server block", func(*Document) {}, "server:\n  address: 10.0.0.1\n", "server"},
		{"rke2 block", func(*Document) {}, "rke2:\n  agentToken: x\n", "rke2"},
		{"other role", func(d *Document) { d.Role = "agent" }, "", "role must be pod"},
		{"pod section", func(*Document) {}, "pod:\n  uid: " + testPodUID + "\n  namespace: tenant\n  name: app\n", "pod"},
		{"workloads", func(*Document) {}, "workloads: '" + testPodWorkloads + "'\n", "workloads"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "tdx")
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, tc.append...)
			_, err = Parse(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The only happy path of NewPodBundle: a generic document.
func TestNewPodBundleStages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "tdx"), "--name", "p-1",
		"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t)); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, podDir)
	if doc.Role != Pod || doc.Node.Name != "p-1" {
		t.Fatalf("pod document %+v", doc)
	}
	if doc.CDS.Address != "cds.example.org:8443" || stagedCDSPolicy(t, doc).Family != teetypes.FamilySNP {
		t.Fatal("Pod bundle lost independent DNS-addressed SNP CDS trust")
	}
	requirePresent(t, filepath.Join(dir, podKeyFile))
	stageBundleNode(t, dir, podDir)
}

// An SNP image has no runtime register to measure the pod with, so new-pod
// refuses its manifest before writing anything.
func TestNewPodBundleRefusesSNPManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "snp"), "--name", "p-1",
		"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t))
	if err == nil || !strings.Contains(err.Error(), "TDX-only") {
		t.Fatalf("got %v, want a TDX-only refusal", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("a refused bundle left %s behind: %v", dir, statErr)
	}
}

func writePodCDSPin(t *testing.T) string {
	t.Helper()
	return writeFile(t, "cds.json", testCDSPin(t, teetypes.FamilySNP, 2))
}

func testProviderPod(t *testing.T, spec string) *corev1.Pod {
	t.Helper()
	pod, err := ParsePodManifest([]byte(testPodManifest(`,"automountServiceAccountToken":false` + spec)))
	if err != nil {
		t.Fatal(err)
	}
	return pod
}

func providerPodWith(t *testing.T, change func(c *corev1.Container)) *corev1.Pod {
	t.Helper()
	pod := testProviderPod(t, "")
	change(&pod.Spec.Containers[0])
	return pod
}

func fieldRefEnv(path string) corev1.EnvVar {
	return corev1.EnvVar{Name: "A", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}

// A provider pod also refuses everything a standalone kubelet cannot resolve
// from the external cluster, one row per check.
func TestValidateProviderPod(t *testing.T) {
	for _, pod := range []*corev1.Pod{
		testProviderPod(t, ""),
		testProviderPod(t, `,"serviceAccountName":"default"`),
		providerPodWith(t, func(c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "B", Value: "b"}, fieldRefEnv("spec.nodeName")}
		}),
		providerPodWith(t, func(c *corev1.Container) { c.Env = []corev1.EnvVar{fieldRefEnv("metadata.name")} }),
	} {
		if err := ValidateProviderPod(pod); err != nil {
			t.Fatalf("ValidateProviderPod: %v", err)
		}
	}
	for _, tc := range []struct {
		name string
		pod  func(t *testing.T) *corev1.Pod
		want string
	}{
		{"no containers", func(*testing.T) *corev1.Pod { return &corev1.Pod{} }, "must have containers"},
		{"nil pod", func(*testing.T) *corev1.Pod { return nil }, "must have containers"},
		{"token automount unset", func(t *testing.T) *corev1.Pod {
			pod := testProviderPod(t, "")
			pod.Spec.AutomountServiceAccountToken = nil
			return pod
		}, "automountServiceAccountToken: false"},
		{"token automount on", func(t *testing.T) *corev1.Pod {
			return testProviderPodAutomount(t, true)
		}, "automountServiceAccountToken: false"},
		{"service account", func(t *testing.T) *corev1.Pod { return testProviderPod(t, `,"serviceAccountName":"builder"`) }, "cluster service account"},
		{"image pull secret", func(t *testing.T) *corev1.Pod {
			return testProviderPod(t, `,"imagePullSecrets":[{"name":"registry"}]`)
		}, "imagePullSecrets"},
		{"runtime class", func(t *testing.T) *corev1.Pod { return testProviderPod(t, `,"runtimeClassName":"kata"`) }, "runtimeClassName"},
		{"workload shape", func(t *testing.T) *corev1.Pod { return testProviderPod(t, `,"hostPID":true`) }, "host namespaces"},
		{"readiness gates", func(t *testing.T) *corev1.Pod {
			return testProviderPod(t, `,"readinessGates":[{"conditionType":"x"}]`)
		}, "readinessGates"},
		{"kubelet annotation FieldRef", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) {
				c.Env = []corev1.EnvVar{fieldRefEnv("metadata.annotations['kubernetes.io/config.hash']")}
			})
		}, "through FieldRef"},
		{"pod resources", func(t *testing.T) *corev1.Pod {
			pod := testProviderPod(t, "")
			pod.Spec.Resources = &corev1.ResourceRequirements{}
			return pod
		}, "per container"},
		{"resource claim", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) { c.Resources.Claims = []corev1.ResourceClaim{{Name: "gpu"}} })
		}, "resource claims"},
		{"annotations FieldRef", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) { c.Env = []corev1.EnvVar{fieldRefEnv("metadata.annotations")} })
		}, "through FieldRef"},
		{"provider annotation FieldRef", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) {
				c.Env = []corev1.EnvVar{fieldRefEnv("metadata.annotations['confidential.ai/pod-cvm']")}
			})
		}, "through FieldRef"},
		{"envFrom", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) {
				c.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}}}
			})
		}, "does not resolve envFrom"},
		{"Secret env", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) {
				c.Env = []corev1.EnvVar{{Name: "A", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}}}
			})
		}, "Secret or ConfigMap"},
		{"unparsable image", func(t *testing.T) *corev1.Pod {
			return providerPodWith(t, func(c *corev1.Container) { c.Image = "Busybox@@" })
		}, `container "app" image "Busybox@@"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateProviderPod(tc.pod(t)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func testProviderPodAutomount(t *testing.T, automount bool) *corev1.Pod {
	t.Helper()
	pod := testProviderPod(t, "")
	pod.Spec.AutomountServiceAccountToken = &automount
	return pod
}

// The assigned pod's own identity fields are checked against its manifest.
func TestPodSpecValidate(t *testing.T) {
	valid := PodSpec{UID: testPodUID, Namespace: "tenant", Name: "app", Manifest: testPodManifest("")}
	if err := valid.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(p *PodSpec)
		want   string
	}{
		{"no uid", func(p *PodSpec) { p.UID = "" }, "pod.uid"},
		{"bad namespace", func(p *PodSpec) { p.Namespace = "Tenant_1" }, "pod.namespace"},
		{"bad name", func(p *PodSpec) { p.Name = "App" }, "pod.name must be an RFC1123 subdomain"},
		{"workload shape", func(p *PodSpec) { p.Manifest = testPodManifest(`,"hostNetwork":true`) }, "host namespaces"},
		{"bad mesh peer", func(p *PodSpec) { p.MeshPeers = []string{"not-an-address"} }, "pod.meshPeers"},
		{"not a manifest", func(p *PodSpec) { p.Manifest = "- a list" }, "pod.manifest"},
		{"no containers", func(p *PodSpec) {
			p.Manifest = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + testPodUID + `"},"spec":{}}`
		}, "pod.manifest has no containers"},
		{"metadata of another pod", func(p *PodSpec) { p.Name = "other" }, "metadata must match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.change(&p)
			if err := p.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPodSpecIngressPorts(t *testing.T) {
	p := PodSpec{Manifest: strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","ports":[{"containerPort":8080}],"image"`, 1)}
	ports, err := p.IngressPorts()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ports, []uint16{8080}) {
		t.Fatalf("IngressPorts = %v, want [8080]", ports)
	}
	if _, err := (&PodSpec{Manifest: "kind: Deployment"}).IngressPorts(); err == nil || !strings.Contains(err.Error(), "v1 Pod") {
		t.Fatalf("got %v, want a non-Pod manifest refused", err)
	}
}

// An assignment of a document that does not validate is refused.
func TestAssignRefusesInvalidDocument(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	doc.ClusterID = "Cluster_One"
	if _, err := Assign(&doc, []byte(testPodManifest("")), []byte(emptyPodEntries), []byte("[]"), nil); err == nil || !strings.Contains(err.Error(), "clusterID") {
		t.Fatalf("got %v, want the document refused", err)
	}
}
