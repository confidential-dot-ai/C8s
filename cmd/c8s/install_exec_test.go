//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testDigest = "sha256:abababababababababababababababababababababababababababababababab"

func readYAMLTree(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	return tree
}

func treeAt(t *testing.T, tree map[string]any, path ...string) any {
	t.Helper()
	var cur any = tree
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: not a map at %q (%#v)", path, seg, cur)
		}
		cur = m[seg]
	}
	return cur
}

// podListFile writes a typed PodList as the JSON `kubectl get pods -A -o json`
// would emit and returns its path.
func podListFile(t *testing.T, pods ...corev1.Pod) string {
	t.Helper()
	data, err := json.Marshal(corev1.PodList{Items: append(pods, providerPlatformPod())})
	if err != nil {
		t.Fatalf("marshal pod list: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pod list: %v", err)
	}
	return path
}

// The kube-system DaemonSet pod a hosted lane's confidential node runs.
func providerPlatformPod() corev1.Pod {
	return corev1.Pod{
		Namespace:       "kube-system",
		Name:            "kube-proxy-node-a",
		OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "kube-proxy"}},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "kube-proxy", Image: kubeProxyImage}},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:    "kube-proxy",
			Image:   kubeProxyImage,
			ImageID: "mcr.microsoft.com/oss/kubernetes/kube-proxy@" + kubeProxyDigest,
		}}},
	}
}

const (
	kubeProxyImage  = "mcr.microsoft.com/oss/kubernetes/kube-proxy:v1.31.0"
	kubeProxyDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
)

func hostPortPod(ns, name, node string, port int32) corev1.Pod {
	return corev1.Pod{
		Namespace: ns, Name: name,
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Ports: []corev1.ContainerPort{{HostPort: port}}}},
		},
	}
}

// testNodeSelector is the confidential-node selector install derives from the
// release's values.
const testNodeSelector = "c8s.example/confidential=true"

func TestConfidentialNodesExec(t *testing.T) {
	t.Run("the labelled nodes are listed", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `case "$*" in
"get nodes -l `+testNodeSelector+` -o jsonpath"*) /usr/bin/printf 'node-a\nnode-b\n' ;;
esac`)
		nodes, err := confidentialNodes(context.Background(), testNodeSelector)
		if err != nil || !slices.Equal(nodes, []string{"node-a", "node-b"}) {
			t.Fatalf("confidentialNodes = (%v, %v), want ([node-a node-b], nil)", nodes, err)
		}
	})

	t.Run("a cluster with no labelled node is refused", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 0")
		_, err := confidentialNodes(context.Background(), testNodeSelector)
		if err == nil || !strings.Contains(err.Error(), testNodeSelector) {
			t.Fatalf("want the refusal naming the labels, got %v", err)
		}
	})

	t.Run("node read failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		if _, err := confidentialNodes(context.Background(), testNodeSelector); err == nil {
			t.Fatal("want error when kubectl fails")
		}
	})
}

func TestPreflightRouterHostPortExec(t *testing.T) {
	kubectlBody := func(podsFile string) string {
		return `case "$*" in
"get pods --all-namespaces -o json") /bin/cat '` + podsFile + `' ;;
esac`
	}

	t.Run("port taken on every node aborts", func(t *testing.T) {
		pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "kubectl", kubectlBody(pods))
		err := preflightRouterHostPort(context.Background(), []string{"node-a"})
		if err == nil {
			t.Fatal("want error when the host port is bound on every node")
		}
		for _, want := range []string{"443", "kube-system/ingress-a", "free the port"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err, want)
			}
		}
	})

	t.Run("a free node passes", func(t *testing.T) {
		pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "kubectl", kubectlBody(pods))
		if err := preflightRouterHostPort(context.Background(), []string{"node-a", "node-b"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("the router's own holder is ignored", func(t *testing.T) {
		pods := podListFile(t, hostPortPod(workloadclaims.RouterNamespace, "c8s-router", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "kubectl", kubectlBody(pods))
		if err := preflightRouterHostPort(context.Background(), []string{"node-a"}); err != nil {
			t.Fatalf("re-install must not flag its own router: %v", err)
		}
	})

	t.Run("unparseable pod list surfaces", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "pods.json")
		if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeBin(t)
		f.tool(t, "kubectl", kubectlBody(bad))
		if err := preflightRouterHostPort(context.Background(), []string{"node-a"}); err == nil {
			t.Fatal("want error for unparseable pod list")
		}
	})
}

func TestCraneDigestShellsOut(t *testing.T) {
	t.Run("resolves the ref", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", fakeCrane(testDigest))
		got, err := crane.Digest(context.Background(), "ghcr.io/x/app:v1")
		if err != nil || got != testDigest {
			t.Fatalf("craneDigest = (%q, %v), want (%q, nil)", got, err, testDigest)
		}
		mustContainLine(t, f.calls(t), "crane digest ghcr.io/x/app:v1")
	})
	t.Run("failure carries crane stderr", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", `echo "UNAUTHORIZED: bad creds" >&2; exit 1`)
		_, err := crane.Digest(context.Background(), "ghcr.io/x/app:v1")
		if err == nil || !strings.Contains(err.Error(), "UNAUTHORIZED: bad creds") {
			t.Fatalf("want the registry stderr in the error, got %v", err)
		}
	})
	t.Run("non-digest output is rejected", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "echo latest")
		if _, err := crane.Digest(context.Background(), "ghcr.io/x/app:v1"); err == nil {
			t.Fatal("want error for a non-sha256 crane answer")
		}
	})
}

func TestEffectiveValuesExec(t *testing.T) {
	values := "attestationApi:\n  enabled: true\n"

	t.Run("set override beats the chart default", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		tree, err := effectiveValues(context.Background(), writeChart(t, values), nil,
			[]string{"--set", "attestationApi.enabled=false"})
		if err != nil {
			t.Fatalf("effectiveValues: %v", err)
		}
		if boolAtPath(tree, "attestationApi.enabled") {
			t.Error("override to false must win over the chart default true")
		}
	})

	t.Run("chart default stands without overrides", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		tree, err := effectiveValues(context.Background(), writeChart(t, values), nil, nil)
		if err != nil {
			t.Fatalf("effectiveValues: %v", err)
		}
		if !boolAtPath(tree, "attestationApi.enabled") {
			t.Error("chart default true must stand")
		}
	})

	t.Run("helm failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "exit 1")
		if _, err := effectiveValues(context.Background(), writeChart(t, values), nil, nil); err == nil {
			t.Fatal("want error when helm fails")
		}
	})

	t.Run("overlay conflict surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		_, err := effectiveValues(context.Background(), writeChart(t, values), nil,
			[]string{"--set", "attestationApi=x", "--set", "attestationApi.enabled=false"})
		if err == nil {
			t.Fatal("want error for a scalar/map overlay conflict")
		}
	})
}

// effectiveValues sees what helm renders: the computed values replace a
// values file's list, as a later -f does, rather than merging into it.
func TestEffectiveValuesReplacesLists(t *testing.T) {
	newFakeBin(t).tool(t, "helm", helmShowValuesBody)
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte("w:\n  containers:\n    - digest: a\n    - digest: stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCLIState(t)
	tree, err := effectiveValues(context.Background(), writeChart(t, "{}\n"), []string{values}, []string{"--set-string", "w.containers[0].digest=b"})
	if err != nil {
		t.Fatalf("effectiveValues: %v", err)
	}
	if want := []any{map[string]any{"digest": "b"}}; !reflect.DeepEqual(tree["w"].(map[string]any)["containers"], want) {
		t.Fatalf("w.containers = %#v, want %#v", tree["w"], want)
	}
}

func TestPreflightImagePullSecretExec(t *testing.T) {
	secretJSON := func(t *testing.T, typ corev1.SecretType) string {
		t.Helper()
		data, err := json.Marshal(corev1.Secret{Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "secret.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("registry secret passes", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "/bin/cat '"+secretJSON(t, corev1.SecretTypeDockerConfigJson)+"'")
		if err := preflightImagePullSecret(context.Background(), "c8s-system", "regcred"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContainLine(t, f.calls(t), "kubectl get secret regcred -n c8s-system -o json")
	})

	t.Run("wrong secret type fails", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "/bin/cat '"+secretJSON(t, corev1.SecretTypeOpaque)+"'")
		if err := preflightImagePullSecret(context.Background(), "c8s-system", "regcred"); err == nil {
			t.Fatal("want error for a non-registry secret type")
		}
	})

	t.Run("missing secret fails with creation hint", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `echo 'Error from server (NotFound): secrets "regcred" not found' >&2; exit 1`)
		err := preflightImagePullSecret(context.Background(), "c8s-system", "regcred")
		if err == nil || !strings.Contains(err.Error(), "kubectl create secret docker-registry") {
			t.Fatalf("want the creation hint, got %v", err)
		}
	})

	t.Run("other kubectl failure surfaces the stderr", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo forbidden >&2; exit 1")
		err := preflightImagePullSecret(context.Background(), "c8s-system", "regcred")
		if err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("want the kubectl stderr in the error, got %v", err)
		}
	})

	t.Run("unparseable secret surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo not-json")
		if err := preflightImagePullSecret(context.Background(), "c8s-system", "regcred"); err == nil {
			t.Fatal("want error for an unparseable secret")
		}
	})
}

func TestPatchAdoptedWorkloadExec(t *testing.T) {
	ref := workloadRef{kind: "deployment", name: "vllm", namespace: "ws"}

	t.Run("patches the pod template annotation", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		if err := patchAdoptedWorkload(context.Background(), ref, "infer"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		calls := f.calls(t)
		i := lineIndex(calls, "kubectl patch deployment vllm -n ws --type merge -p ")
		if i < 0 {
			t.Fatalf("no kubectl patch call logged: %v", calls)
		}
		if !strings.Contains(calls[i], `"`+webhook.AnnotationWorkload+`":"infer"`) {
			t.Errorf("patch %q missing the %s=infer annotation", calls[i], webhook.AnnotationWorkload)
		}
	})

	t.Run("kubectl failure names the workload", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		err := patchAdoptedWorkload(context.Background(), ref, "infer")
		if err == nil || !strings.Contains(err.Error(), "deployment/vllm in namespace ws") {
			t.Fatalf("want the workload named in the error, got %v", err)
		}
	})
}

// deploymentFile writes a typed Deployment as `kubectl get -o json` output.
func deploymentFile(t *testing.T, images ...string) string {
	t.Helper()
	var containers []corev1.Container
	for _, img := range images {
		containers = append(containers, corev1.Container{Name: "c", Image: img})
	}
	data, err := json.Marshal(appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: containers}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deploy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdoptedWorkloadImagesExec(t *testing.T) {
	ref := workloadRef{kind: "deployment", name: "vllm", namespace: "ws"}

	t.Run("reads the pod template images", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "/bin/cat '"+deploymentFile(t, "ghcr.io/acme/vllm:v1")+"'")
		got, err := adoptedWorkloadTemplate(context.Background(), ref)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if images := podTemplateImages(got); !reflect.DeepEqual(images, podImages{Main: []string{"ghcr.io/acme/vllm:v1"}}) {
			t.Fatalf("images = %v, want [ghcr.io/acme/vllm:v1]", got)
		}
		mustContainLine(t, f.calls(t), "kubectl get deployment vllm -n ws -o json")
	})

	t.Run("kubectl failure carries its output", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo no-such-workload; exit 1")
		_, err := adoptedWorkloadTemplate(context.Background(), ref)
		if err == nil || !strings.Contains(err.Error(), "no-such-workload") {
			t.Fatalf("want kubectl output in the error, got %v", err)
		}
	})
}

func TestAppendResolvedWorkloadImageArgsExec(t *testing.T) {
	t.Run("resolves and pins the allowlist entry", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", fakeCrane(testDigest))
		got, _, err := appendResolvedWorkloadImageArgs(context.Background(), nil, []adoptedWorkload{{
			workloadAdoption: workloadAdoption{cwID: "infer", ref: workloadRef{kind: "deployment", name: "vllm", namespace: "ws"}},
			template:         templateRunning("ghcr.io/acme/vllm:v1"),
		}}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		p := "nriImagePolicy.bootstrapAllowlist.workloads.infer."
		assertArgsEqual(t, got, []string{
			"--set-string", p + "label=ws/deployment/vllm",
			"--set-string", p + "containers[0].digest=" + testDigest,
			"--set-string", p + "containers[0].image=ghcr.io/acme/vllm@" + testDigest,
			"--set-string", p + "containers[0].command.policy=any",
			"--set-string", p + "containers[0].args.policy=any",
			"--set-string", p + "containers[0].env.policy=any",
			"--set-string", p + "containers[0].mounts.policy=deny",
		})
		mustContainLine(t, f.calls(t), "crane digest ghcr.io/acme/vllm:v1")
	})

	t.Run("resolver failure aborts", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "exit 1")
		if _, _, err := appendResolvedWorkloadImageArgs(context.Background(), nil, []adoptedWorkload{{template: templateRunning("ghcr.io/acme/vllm:v1")}}, ""); err == nil {
			t.Fatal("want error when crane fails")
		}
	})
}

// installStubs wires stub helm/kubectl/crane for full `c8s install` runs of
// a release CLI against the real embedded chart. The helm stub answers `show
// values` with the chart's values.yaml, `pull` with the release chart, and
// snapshots the computed values file an upgrade receives; kubectl apply
// payloads are captured for typed inspection.
type installStubs struct {
	f        *fakeBin
	computed string
	applied  string
	release  string
}

// testReleaseVersion is the CLI version installStubs releases, testDigest
// every image digest of its chart.
const testReleaseVersion = "v9.9.9"

func newInstallStubs(t *testing.T, kubectlBody string, helmUpgradeFails bool) *installStubs {
	t.Helper()
	f := newFakeBin(t)
	s := &installStubs{
		f:        f,
		computed: filepath.Join(f.dir, "computed.yaml"),
		applied:  filepath.Join(f.dir, "applied.json"),
		release:  writeReleaseChart(t, testDigest),
	}
	fail := ""
	if helmUpgradeFails {
		fail = "exit 1"
	}
	setCLIVersion(t, testReleaseVersion)
	f.tool(t, "helm", `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
pull) `+helmPullBody(s.release)+` ;;
template) /bin/echo '`+installSeedConfigMap+`' ;;
upgrade)
  prev=; last=
  for a in "$@"; do
    if [ "$prev" = "-f" ]; then last="$a"; fi
    prev="$a"
  done
  if [ -n "$last" ]; then /bin/cp "$last" '`+s.computed+`'; fi
  `+fail+`
  ;;
esac`)
	f.tool(t, "kubectl", kubectlBody)
	f.tool(t, "crane", fakeCrane(testDigest))
	return s
}

// setCLIVersion sets the build version for the test.
func setCLIVersion(t *testing.T, v string) {
	t.Helper()
	prev := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = prev })
}

// helmPullBody is a helm stub arm that copies chart to --untardir as c8s-cloud.
func helmPullBody(chart string) string {
	return `dir=; prev=
  for a in "$@"; do
    if [ "$prev" = "--untardir" ]; then dir="$a"; fi
    prev="$a"
  done
  /bin/mkdir -p "$dir"
  /bin/cp -r '` + chart + `' "$dir/c8s-cloud"`
}

// writeReleaseChart writes the c8s-cloud chart a release stamps: digest on
// every bundled component repository, beside values install never reads.
func writeReleaseChart(t *testing.T, digest string) string {
	t.Helper()
	dir := t.TempDir()
	values := strings.Join([]string{
		"armtlsMesh: {image: " + releaseImage("armtls-mesh", digest) + "}",
		"attestationApi: {image: " + releaseImage("attestation-api", digest) + "}",
		"image: " + releaseImage("c8s-operator", digest),
		"nriImagePolicy: {image: " + releaseImage("nri-image-policy", digest) + ", policy: {mode: audit}}",
		"volumed: {enabled: true, image: " + releaseImage("volumed", digest) + "}",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("name: c8s-cloud\nversion: 9.9.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(values+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// releaseImage is a stamped image object of the C8s repository name.
func releaseImage(name, digest string) string {
	return "{repository: ghcr.io/confidential-dot-ai/" + name + ", digest: " + digest + "}"
}

// clusterKubectl is a healthy single-node cluster: one vanilla linux node that
// carries the confidential-node labels, one pod answering inside the range
// that node publishes, and namespace applies captured.
// extra case arms are matched first, so scenarios override single answers.
func clusterKubectl(t *testing.T, applied, extra string) string {
	t.Helper()
	return `case "$*" in
` + extra + `"get nodes -l "*kubeletVersion*) /usr/bin/printf 'node-a\tv1.31.0\n' ;;
"get nodes -l "*containerRuntimeVersion*) /usr/bin/printf 'node-a\tcontainerd://2.3.4\n' ;;
"get nodes -l "*'{.metadata.name}{"\n"}'*) /usr/bin/printf 'node-a\n' ;;
"get nodes -o json") echo '{"items":[{"metadata":{"name":"node-a"},"spec":{"podCIDR":"10.42.0.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.10"}]}}]}' ;;
"get pods --all-namespaces -o json") /bin/cat '` + podListFile(t, podInNodeRange()) + `' ;;
"version -o json") echo '{"serverVersion":{"gitVersion":"v1.31.0"}}' ;;
"apply -f -") /bin/cat >> '` + applied + `' ;;
esac`
}

// pipedCDS names the stubs' CDS in a values file, as an operator's -f does:
// the install reads the pin from the values it renders with, so a piped one is
// held to the same shape as --cds-pin.
func pipedCDS(t *testing.T) string {
	t.Helper()
	return "cds:\n  address: " + installCDSAddressUnreachable + "\n  measurementsConfig: |\n    " +
		string(cdsPinDocument(t, []string{installSeedEntryName}, "192.0.2.0/24")) + "\n"
}

// runInstall runs c8s install against the CDS the stubs render and serve,
// which cdsPreflight otherwise demands.
func runInstall(t *testing.T, args ...string) error {
	t.Helper()
	pin := cdsPinFile(t, []string{installSeedEntryName}, "192.0.2.0/24")
	return runC8s(t, append([]string{"install", flagArg(flagCDSAddress), installCDSAddressUnreachable, flagArg(flagCDSPin), pin}, args...)...)
}

func TestInstallHappyPath(t *testing.T) {
	var s *installStubs
	var err error
	stderr := captureStderr(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	})
	if err != nil {
		t.Fatalf("install: %v\nstderr:\n%s", err, stderr)
	}
	calls := s.f.calls(t)

	// The helm invocation: release/namespace fixed, the stock file the
	// platform selects first, computed values as the last -f, no --wait.
	hi := lineIndex(calls, "helm upgrade ")
	if hi < 0 {
		t.Fatalf("no helm upgrade logged:\n%s", strings.Join(calls, "\n"))
	}
	args := strings.Fields(calls[hi])[1:]
	if len(args) != 10 || args[0] != "upgrade" || args[1] != "--install" || args[2] != "c8s" ||
		args[4] != "--namespace" || args[5] != "c8s-system" || args[6] != "-f" ||
		args[7] != filepath.Join(args[3], "values-aks-snp.yaml") || args[8] != "-f" {
		t.Fatalf("helm argv = %v", args)
	}

	// Preflights and the namespace apply all happen before helm mutates the
	// cluster via the chart.
	for _, prefix := range []string{
		"kubectl get pods --all-namespaces -o json",
		"kubectl apply -f -",
	} {
		if i := lineIndex(calls, prefix); i < 0 || i > hi {
			t.Errorf("%q must run before helm upgrade (index %d vs %d)", prefix, i, hi)
		}
	}

	// A release CLI pins its images from the release chart of its own version.
	mustContainLine(t, calls, "helm pull "+releaseChartRepository+" --version 9.9.9 --untar --untardir "+filepath.Join(filepath.Dir(args[3]), releaseChartDir))
	mustNotContainPrefix(t, calls, "crane ")

	// The computed values helm received carry the release digest of every
	// component under its repository, and nothing else of the release chart.
	tree := readYAMLTree(t, s.computed)
	for _, image := range [][]string{
		{"armtlsMesh", "image"},
		{"attestationApi", "image"},
		{"image"},
		{"nriImagePolicy", "image"},
		{"volumed", "image"},
	} {
		if got := treeAt(t, tree, append(image, "digest")...); got != testDigest {
			t.Errorf("%v.digest = %#v, want %s", image, got, testDigest)
		}
		if got, _ := treeAt(t, tree, append(image, "repository")...).(string); !strings.HasPrefix(got, "ghcr.io/confidential-dot-ai/") {
			t.Errorf("%v.repository = %#v, want the bundled chart's", image, got)
		}
	}
	// Nothing an install reads from the cluster reaches the policy the nodes
	// boot on, so the entry a release's seed names is the one it needs served.
	if policy, ok := nestedMap(tree, "nriImagePolicy", "policy"); ok {
		t.Errorf("computed nriImagePolicy.policy = %v, want no computed policy", policy)
	}
	if boolAtPath(tree, "volumed.enabled") {
		t.Error("computed values carry the release chart's volumed.enabled")
	}

	// The namespace applied before helm must admit privileged pods.
	var ns corev1.Namespace
	data, err := os.ReadFile(s.applied)
	if err != nil {
		t.Fatalf("read applied manifests: %v", err)
	}
	if err := json.Unmarshal(data, &ns); err != nil {
		t.Fatalf("applied manifest is not a Namespace: %v\n%s", err, data)
	}
	if ns.Name != "c8s-system" || ns.Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Errorf("applied namespace = %s labels %v, want c8s-system privileged", ns.Name, ns.Labels)
	}
}

// --volumes must reach helm as volumed.enabled, beside the daemon's own
// pinned image, which derives it into the NRI floor that would otherwise deny
// it.
func TestInstallVolumesEnablesTheNodeAgent(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	if err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", "--volumes"); err != nil {
		t.Fatalf("install: %v", err)
	}

	tree := readYAMLTree(t, s.computed)
	if got := treeAt(t, tree, "volumed", "enabled"); got != true {
		t.Errorf("volumed.enabled = %#v, want true", got)
	}
	if got := treeAt(t, tree, "volumed", "image", "digest"); got != testDigest {
		t.Errorf("volumed.image.digest = %#v, want %s", got, testDigest)
	}
}

func TestInstallAbortsOnRouterHostPortConflict(t *testing.T) {
	pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `*metadata.name*) echo node-a ;;
"get pods --all-namespaces -o json") /bin/cat '`+pods+`' ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "443") || !strings.Contains(err.Error(), "kube-system/ingress-a") {
		t.Fatalf("want the router host-port conflict, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// A node whose containerd predates the NRI container user is refused before
// helm runs: the admission plugin would read every container as uid 0 and
// refuse the router and every confidential pod.
func TestInstallRefusesContainerdWithoutTheContainerUser(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `*containerRuntimeVersion*) /usr/bin/printf 'node-a\tcontainerd://2.2.7\n' ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false")
	want := "containerd " + containerdNRIUserVersion.String() + " or later"
	if err == nil || !strings.Contains(err.Error(), "node-a (containerd://2.2.7)") || !strings.Contains(err.Error(), want) {
		t.Fatalf("want the container-user refusal naming the node and the version, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// A node running a Kubernetes distribution's own containerd is refused: the
// installer would write a config file that containerd never reads, leaving the
// node's pods admitted by nothing.
func TestInstallRefusesABundledContainerdNode(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `*kubeletVersion*) /usr/bin/printf 'node-a\tv1.29.5+rke2r1\n' ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false")
	if err == nil || !strings.Contains(err.Error(), "node-a") || !strings.Contains(err.Error(), "upstream containerd") {
		t.Fatalf("want the bundled-containerd refusal naming the node, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

func TestInstallAdoptsWorkloadAfterHelm(t *testing.T) {
	deploy := deploymentFile(t, "ghcr.io/acme/vllm@"+testDigest)
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get deployment vllm -n ws -o json") /bin/cat '`+deploy+`' ;;
`))
	routesOut := filepath.Join(t.TempDir(), "routes.json")
	err := runInstall(t, "--platform=aks-snp", "--force",
		"--workload-ref", "infer=ws/deployment/vllm:8000", "--upstream", "infer", "--routes-out", routesOut)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := s.f.calls(t)

	hi := lineIndex(calls, "helm upgrade ")
	if hi < 0 {
		t.Fatal("helm upgrade did not run")
	}
	// Adoption needs --wait (default true) so the webhook is ready first.
	if !strings.HasSuffix(calls[hi], "--wait --timeout=5m") {
		t.Errorf("helm upgrade must wait before workloads roll: %q", calls[hi])
	}
	// The existence read runs before helm; the patch only after the release.
	if gi := lineIndex(calls, "kubectl get deployment vllm -n ws -o json"); gi < 0 || gi > hi {
		t.Errorf("workload existence check at %d, want before helm at %d", gi, hi)
	}
	if pi := lineIndex(calls, "kubectl patch deployment vllm -n ws --type merge -p "); pi < hi {
		t.Errorf("workload patch at %d, want after helm at %d", pi, hi)
	}

	if _, ok := valueAtPath(readYAMLTree(t, s.computed), "router.upstream"); ok {
		t.Error("install set router.upstream, which the chart refuses")
	}
	// Without --operator-key the route goes to --routes-out, as a new
	// manifest at the Unix time.
	b, err := os.ReadFile(routesOut)
	if err != nil {
		t.Fatalf("read --routes-out: %v", err)
	}
	m, err := pkgroutes.Parse(b)
	if err != nil {
		t.Fatalf("Parse(--routes-out) = %v", err)
	}
	want := []pkgroutes.Route{{Path: "/", Match: pkgroutes.MatchPrefix, Backend: pkgroutes.Backend{Address: "c8s-infer.ws.svc.cluster.local:8000", Workload: "infer"}}}
	// The host is the router's own SAN, which names the namespace it serves.
	host := "c8s-router." + workloadclaims.RouterNamespace + ".svc"
	if routes := m.Hosts[host].Routes; m.Revision < 1e9 || len(m.Hosts) != 1 || !reflect.DeepEqual(routes, want) {
		t.Errorf("--routes-out = revision %d, hosts %v, want a Unix-time revision routing %s / to %+v", m.Revision, m.Hosts, host, want[0])
	}
}

// install refuses, before touching the cluster, a route flag with no route
// to write.
func TestInstallRefusesRouteFlagsWithoutUpstream(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"--operator-key", "op.pem"}, "pass --upstream"},
		{[]string{"--routes-out", "routes.json"}, "--routes-out applies"},
		{[]string{"--routes-max-age", "1h"}, "--routes-max-age applies"},
	} {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
		err := runC8s(t, append([]string{"install", "--platform=aks-snp", "--force"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("install %v = %v, want an error containing %q", tc.args, err, tc.wantErr)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
	}
}

func TestInstallHelmUpgradeFailureSurfaces(t *testing.T) {
	s := newInstallStubs(t, "", true)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "helm install failed") {
		t.Fatalf("want the helm failure surfaced, got %v", err)
	}
}

func TestInstallNamespaceApplyFailureSurfaces(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, "", `"apply -f -") exit 1 ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "kubectl apply namespace") {
		t.Fatalf("want the namespace apply failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

func TestInstallRequiresCLIsOnPath(t *testing.T) {
	// newFakeBin keeps /bin:/usr/bin on PATH, where CI runners ship real helm
	// and kubectl; pin PATH to the stub dir so "missing" actually means missing.
	t.Run("helm missing", func(t *testing.T) {
		f := newFakeBin(t)
		t.Setenv("PATH", f.dir)
		err := runInstall(t, "--platform=aks-snp", "--force")
		if err == nil || !strings.Contains(err.Error(), "helm CLI not found") {
			t.Fatalf("want a helm-not-found error, got %v", err)
		}
	})
	t.Run("kubectl missing", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "")
		t.Setenv("PATH", f.dir)
		err := runInstall(t, "--platform=aks-snp", "--force")
		if err == nil || !strings.Contains(err.Error(), "kubectl CLI not found") {
			t.Fatalf("want a kubectl-not-found error, got %v", err)
		}
	})
}

// helmValuesCapture re-stubs helm so an `upgrade` appends every -f file's
// content (path header + payload) to captureFile, in argv order. It keeps the
// installStubs `show values` and `pull` answers.
func helmValuesCapture(t *testing.T, s *installStubs, captureFile string) {
	t.Helper()
	s.f.tool(t, "helm", `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
pull) `+helmPullBody(s.release)+` ;;
template) /bin/echo '`+installSeedConfigMap+`' ;;
upgrade)
  prev=; last=
  for a in "$@"; do
    if [ "$prev" = "-f" ]; then
      echo "== $a" >> '`+captureFile+`'
      /bin/cat "$a" >> '`+captureFile+`'
      last="$a"
    fi
    prev="$a"
  done
  if [ -n "$last" ]; then /bin/cp "$last" '`+s.computed+`'; fi
  ;;
esac`)
}

// `c8s install -f -` pipes stdin into a real values file: effectiveValues
// must read it, and helm must receive the piped bytes as a
// -f file ahead of the computed values.
func TestInstallValuesFromStdin(t *testing.T) {
	payload := "volumed:\n  enabled: true\n" + pipedCDS(t)

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	capture := filepath.Join(s.f.dir, "values-stream.log")
	helmValuesCapture(t, s, capture)

	resetCLIState(t)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	rootCmd.SetIn(strings.NewReader(payload))
	rootCmd.SetArgs([]string{"install", "--platform=aks-snp", "--wait=false", "-f", "-"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	// Helm received the piped values as a real -f file, followed by the
	// computed values file (which wins on shared keys).
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read values capture: %v", err)
	}
	sections := strings.Split(string(data), "== ")
	if len(sections) != 4 { // leading empty + stock file + stdin file + computed file
		t.Fatalf("helm received %d -f files, want 3:\n%s", len(sections)-1, data)
	}
	stdinSection := sections[2]
	header, content, _ := strings.Cut(stdinSection, "\n")
	if !strings.Contains(header, "c8s-install-stdin-") {
		t.Errorf("first -f is %q, want the materialized stdin file", header)
	}
	if content != payload {
		t.Errorf("helm's stdin-derived -f content = %q, want the piped %q", content, payload)
	}
	if got := treeAt(t, readYAMLTree(t, s.computed), "volumed", "image", "digest"); got != testDigest {
		t.Errorf("computed values volumed digest = %#v, want %s (last -f still the computed file)", got, testDigest)
	}
}

// When stdin cannot be materialized, install fails before anything else runs.
func TestInstallStdinValuesMaterializeFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)

	f := newFakeBin(t)
	resetCLIState(t)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	rootCmd.SetIn(strings.NewReader("router:\n  enabled: false\n"))
	rootCmd.SetArgs([]string{"install", "--platform=aks-snp", "-f", "-"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "stdin values file") {
		t.Fatalf("want the temp-file error, got %v", err)
	}
	if got := f.calls(t); len(got) != 0 {
		t.Errorf("materializing stdin precedes every exec, logged: %v", got)
	}
}

// Flag-validation failures must precede every exec — a doc command that
// stops parsing is exactly what the doc-parity gate keys on.
func TestInstallFlagValidationPrecedesExec(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown platform", []string{"install", "--platform=eks"}, `--platform must be one of aks-snp, aks-tdx, gke-snp, got "eks"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			err := runC8s(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if got := f.calls(t); len(got) != 0 {
				t.Errorf("validation must precede every exec, logged: %v", got)
			}
		})
	}
}

// effectiveValues surfaces a broken chart, a missing -f file, and an
// unparseable -f file rather than rendering on defaults the operator did not
// ask for.
func TestEffectiveValuesErrorPaths(t *testing.T) {
	t.Run("unparseable chart values", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		if _, err := effectiveValues(context.Background(), writeChart(t, "	"), nil, nil); err == nil {
			t.Fatal("want the chart-values parse error")
		}
	})

	t.Run("missing values file", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		missing := []string{filepath.Join(t.TempDir(), "missing.yaml")}
		_, err := effectiveValues(context.Background(), writeChart(t, "a: 1\n"), missing, nil)
		if err == nil || !strings.Contains(err.Error(), "read values file") {
			t.Fatalf("want the read error, got %v", err)
		}
	})

	t.Run("unparseable values file", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(bad, []byte("\t"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := effectiveValues(context.Background(), writeChart(t, "a: 1\n"), []string{bad}, nil)
		if err == nil || !strings.Contains(err.Error(), "parse values file") {
			t.Fatalf("want the parse error, got %v", err)
		}
	})
}

// platformPodListKubectl answers the pod list with these pods plus the one the
// healthy cluster answers at, on top of the healthy-cluster answers.
func platformPodListKubectl(t *testing.T, applied string, pods ...corev1.Pod) string {
	t.Helper()
	podsFile := podListFile(t, append(pods, podInNodeRange())...)
	return clusterKubectl(t, applied, `"get pods --all-namespaces -o json") /bin/cat '`+podsFile+`' ;;
`)
}

// podInNodeRange answers inside the range the healthy cluster's node publishes,
// which is what confirms the ranges install checks the CDS against.
func podInNodeRange() corev1.Pod {
	return corev1.Pod{
		Namespace: "ws",
		Name:      "app",
		Status:    corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.42.0.5"}}},
	}
}

const etcdDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func staticEtcdPod() corev1.Pod {
	return corev1.Pod{
		Namespace:   "kube-system",
		Name:        "etcd-node-a",
		Annotations: map[string]string{corev1.MirrorPodAnnotationKey: "mirror"},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "etcd", Image: "index.docker.io/rancher/hardened-etcd:v3.6.12-k3s1"}},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:    "etcd",
			Image:   "index.docker.io/rancher/hardened-etcd:v3.6.12-k3s1",
			ImageID: "index.docker.io/rancher/hardened-etcd@" + etcdDigest,
		}}},
	}
}

// A fail-closed policy that admits nothing the control plane runs must be
// refused BEFORE the namespace apply and the helm install, since registering
// the plugin restarts containerd and the denied static pods never come back.
func TestInstallRefusesPolicyDenyingPlatformPods(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
	// exemptNamespaces cleared: the shape a pre-#396 values file installs.
	values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")

	err := runInstall(t, "--platform=aks-snp", "--wait=false", "-f", values)
	if err == nil {
		t.Fatal("want a refusal when the rendered policy denies the control plane")
	}
	for _, want := range []string{
		"kube-system/etcd-node-a",
		"docker.io/rancher/hardened-etcd@" + etcdDigest,
		"nriImagePolicy.policy.exemptNamespaces",
		"nriImagePolicy.bootstrapAllowlist.workloads",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q is missing %q", err, want)
		}
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm upgrade")
	mustNotContainPrefix(t, calls, "kubectl apply")
}

// The chart exempts kube-system, so the same cluster passes with no values
// file at all.
func TestInstallHostedLaneDefaultAdmitsPlatformPods(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
	if err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force"); err != nil {
		t.Fatalf("install: %v", err)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// The refusal is a guard, not a wall: --force installs and says what it gave up.
func TestInstallForcePastPlatformPodDenial(t *testing.T) {
	var s *installStubs
	var err error
	stderr := captureStderr(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
		values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force", "-f", values)
	})
	if err != nil {
		t.Fatalf("--force must install anyway: %v", err)
	}
	if !strings.Contains(stderr, "2 platform images") {
		t.Errorf("stderr missing the forced-past warning for the denied etcd and kube-proxy images:\n%s", stderr)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// audit mode creates the container anyway, so there is nothing to refuse — and
// no pod list to read.
func TestInstallAuditPolicySkipsPlatformPodCheck(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
	values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    mode: audit\n    exemptNamespaces: []\n")
	if err := runInstall(t, "--platform=aks-snp", "--wait=false", "-f", values); err != nil {
		t.Fatalf("install: %v", err)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// The operator reviews the exemption before any node admits on it.
func TestInstallReportsWhatTheExemptionAdmits(t *testing.T) {
	var s *installStubs
	var err error
	stdout := captureStdout(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied))
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, want := range []string{
		"mcr.microsoft.com/oss/kubernetes/",
		"kube-system/kube-proxy-node-a",
		"mcr.microsoft.com/oss/kubernetes/kube-proxy@" + kubeProxyDigest,
		"nriImagePolicy.bootstrapAllowlist.workloads",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("install output does not report %q:\n%s", want, stdout)
		}
	}
	// It has to land before the plugin is installed, or reviewing it is moot.
	if i, h := strings.Index(stdout, "kube-system/kube-proxy-node-a"), lineIndex(s.f.calls(t), "helm upgrade "); i < 0 || h < 0 {
		t.Fatalf("missing report (%d) or helm upgrade (%d)", i, h)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// A provider image pre-loaded in the node image reports a bare image ID, which
// no digest set can hold, and installs without --force.
func TestInstallAdmitsAPreloadedProviderImage(t *testing.T) {
	const nodeLocal = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	preloaded := daemonSetPod("kube-system", "coredns-abc", "mcr.microsoft.com/oss/kubernetes/coredns:v1.11.3", nodeLocal)
	preloaded.Spec.NodeName = "node-a"

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, preloaded))
	if err := runInstall(t, "--platform=aks-snp", "--wait=false"); err != nil {
		t.Fatalf("install: %v", err)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

func TestInstallGKEAdmitsRequestedRepositoryDespiteRuntimeAlias(t *testing.T) {
	pod := daemonSetPod("kube-system", "gke-proxy", "us-artifactregistry.gcr.io/gke-release/gke-release/kube-proxy:v1", kubeProxyDigest)
	pod.Spec.NodeName = "node-a"
	pod.Status.ContainerStatuses[0].Image = "gke.gcr.io/kube-proxy:v1"
	data, err := json.Marshal(corev1.PodList{Items: []corev1.Pod{pod, podInNodeRange()}})
	if err != nil {
		t.Fatal(err)
	}
	podsFile := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(podsFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get pods --all-namespaces -o json") /bin/cat '`+podsFile+`' ;;
`))
	if err := runInstall(t, "--platform=gke-snp", "--wait=false"); err != nil {
		t.Fatalf("install without --force: %v", err)
	}
	if lineIndex(s.f.calls(t), "helm upgrade ") < 0 {
		t.Fatalf("install did not reach helm upgrade: %v", s.f.calls(t))
	}
}

// An add-on no prefix covers is refused by name, with the value that admits it.
func TestInstallRefusesAProviderImageUnderNoPrefix(t *testing.T) {
	const digest = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	uncovered := daemonSetPod("kube-system", "fluentbit-a", "example.test/fluentbit:v1", "example.test/fluentbit@"+digest)
	uncovered.Spec.NodeName = "node-a"

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, uncovered))
	err := runInstall(t, "--platform=aks-snp", "--wait=false")
	if err == nil || !strings.Contains(err.Error(), "kube-system/fluentbit-a") || !strings.Contains(err.Error(), exemptRepositoriesPath) {
		t.Fatalf("want the refusal naming the container and %s, got %v", exemptRepositoriesPath, err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm upgrade")
	mustNotContainPrefix(t, calls, "kubectl apply")
}

// A pod of a node this install does not touch is not this policy's to admit.
func TestInstallJudgesTheConfidentialNodesPodsAlone(t *testing.T) {
	const elsewhereDigest = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	elsewhere := daemonSetPod("kube-system", "fluentbit-node-z",
		"example.test/fluentbit:v1", "example.test/fluentbit@"+elsewhereDigest)
	elsewhere.Spec.NodeName = "node-z"

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, elsewhere))
	if err := runInstall(t, "--platform=aks-snp", "--wait=false"); err != nil {
		t.Fatalf("a denied pod on another node is not a refusal: %v", err)
	}
}

// A denied container the cluster survives without — GKE's managed
// kube-state-metrics, a StatefulSet no exemption names — is not a refusal, so
// the install must say that registering the plugin stops it and goes on.
func TestInstallReportsDeniedWorkloads(t *testing.T) {
	const ksm = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	managed := statefulSetPod("gke-managed-cim", "kube-state-metrics-0", "gke.io/ksm:v2", "gke.io/ksm@"+ksm)
	managed.Spec.NodeName = "node-a"

	var s *installStubs
	var err error
	stdout := captureStdout(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, managed))
		err = runInstall(t, "--platform=aks-snp", "--wait=false")
	})
	if err != nil {
		t.Fatalf("a denied provider add-on is not a refusal: %v", err)
	}
	for _, want := range []string{"gke-managed-cim/kube-state-metrics-0", "gke.io/ksm@" + ksm} {
		if !strings.Contains(stdout, want) {
			t.Errorf("install output does not report %q:\n%s", want, stdout)
		}
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// An install that stores no route manifest prints a front-door check whose
// route digest the operator reads from CDS under the operator keys.
func TestInstallHintReadsTheRouteDigestFromCDS(t *testing.T) {
	var err error
	stdout := captureStdout(t, func() {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	verifyArgs := hintCommandArgs(t, stdout, "c8s verify")
	if i := slices.Index(verifyArgs, "--route-digest"); i < 0 || verifyArgs[i+1] != "<ROUTE_DIGEST>" {
		t.Errorf("the front-door check names no route digest to fill in:\n%s", stdout)
	}
	digestArgs := hintCommandArgs(t, stdout, "c8s routes show")
	if i := slices.Index(digestArgs, "--operator-keys"); i < 0 || digestArgs[i+1] != "<operator-pub.pem>" {
		t.Errorf("the digest command names no operator keys to verify it under:\n%s", stdout)
	}
	if i := slices.Index(digestArgs, "--url"); i < 0 || digestArgs[i+1] != "https://"+installCDSAddressUnreachable {
		t.Errorf("the digest command names another CDS than this install:\n%s", stdout)
	}
}

// A release that exempts no namespace has nothing to report.
func TestInstallWithoutExemptionReportsNone(t *testing.T) {
	var err error
	stdout := captureStdout(t, func() {
		s := newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
		values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")
		err = runInstall(t, "--platform=aks-snp", "--wait=false", "--force", "-f", values)
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if strings.Contains(stdout, "admitted by digest") {
		t.Errorf("an install exempting nothing reported an exemption:\n%s", stdout)
	}
}

// aksConfidentialNodeSelector is the selector --platform=aks-snp derives from
// the stock values file.
const aksConfidentialNodeSelector = "kubernetes.azure.com/security-type=ConfidentialVM"

// A cluster whose nodes carry none of the confidential-node labels is refused.
func TestInstallRefusesAClusterWithoutConfidentialNodes(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get nodes -l "*'{.metadata.name}{"\n"}'*) ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), aksConfidentialNodeSelector) {
		t.Fatalf("want the refusal naming the platform's confidential-node labels, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// The host-port, image-policy and containerd preflights judge the
// confidential nodes alone, so a plain node in the cluster neither blocks the
// router's port nor fails the runtime check. The node-subnet check still reads
// every node: CDS dials the inventory address of any node a sandbox lands on.
func TestInstallReadsNodesThroughTheConfidentialSelector(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	if err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force"); err != nil {
		t.Fatalf("install: %v", err)
	}
	var reads []string
	for _, call := range s.f.calls(t) {
		if strings.HasPrefix(call, "kubectl get nodes") {
			reads = append(reads, call)
		}
	}
	want := []string{
		`kubectl get nodes -l ` + aksConfidentialNodeSelector + ` -o jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`,
		`kubectl get nodes -o json`,
		`kubectl get nodes -l ` + aksConfidentialNodeSelector + ` -o jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}`,
		`kubectl get nodes -l ` + aksConfidentialNodeSelector + ` -o jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}`,
	}
	if !slices.Equal(reads, want) {
		t.Errorf("install read nodes as:\n%s\nwant:\n%s", strings.Join(reads, "\n"), strings.Join(want, "\n"))
	}
}
