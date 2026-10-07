//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
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

func TestPreflightCDSNodeExec(t *testing.T) {
	values := "cds:\n  node:\n    selector:\n      role: cds\n"

	t.Run("labelled node passes", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", `echo node/node-a`)
		if err := preflightCDSNode(context.Background(), writeChart(t, values)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The label requirement is read from the chart selector verbatim.
		mustContainLine(t, f.calls(t), "kubectl get nodes -l role=cds -o name")
	})

	t.Run("no labelled node fails with the label command", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", "")
		err := preflightCDSNode(context.Background(), writeChart(t, values))
		if err == nil {
			t.Fatal("want error when no node carries the CDS label")
		}
		if !strings.Contains(err.Error(), "kubectl label node <node> role=cds") {
			t.Errorf("error %q should carry the exact label command", err)
		}
	})

	t.Run("customized selector shape skips", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", "")
		chart := writeChart(t, "cds:\n  node:\n    selector:\n      a: \"1\"\n      b: \"2\"\n")
		if err := preflightCDSNode(context.Background(), chart); err != nil {
			t.Fatalf("multi-pair selector must skip, got %v", err)
		}
		mustNotContainPrefix(t, f.calls(t), "kubectl")
	})

	t.Run("kubectl failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", "exit 1")
		if err := preflightCDSNode(context.Background(), writeChart(t, values)); err == nil {
			t.Fatal("want error when kubectl fails")
		}
	})

	t.Run("helm failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "exit 1")
		if err := preflightCDSNode(context.Background(), writeChart(t, values)); err == nil {
			t.Fatal("want error when helm fails")
		}
	})

	t.Run("bad chart values surface", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		if err := preflightCDSNode(context.Background(), writeChart(t, "\t")); err == nil {
			t.Fatal("want error for unparseable chart values")
		}
	})
}

// notBakedKubectl returns a namespace response only for the expected read.
func notBakedKubectl(out string) string {
	return `case "$*" in
"get namespace c8s-system -o json --ignore-not-found") printf '%s' '` + out + `' ;;
*) exit 1 ;;
esac`
}

func TestPreflightNotBakedNodeExec(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		wantErr      bool
	}{
		{"baked namespace", `{"metadata":{"labels":{"confidential.ai/baked":"true"}}}`, true},
		{"ordinary namespace", `{"metadata":{"labels":{"confidential.ai/baked":"false"}}}`, false},
		{"unlabelled namespace", `{"metadata":{}}`, false},
		{"no namespace", "", false},
		{"malformed response", "broken", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "kubectl", notBakedKubectl(tc.output))
			err := preflightNotBakedNode(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %v, want error %v", err, tc.wantErr)
			}
			mustContainLine(t, f.calls(t), "kubectl get namespace c8s-system -o json --ignore-not-found")
		})
	}
	t.Run("read failure remains visible", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `echo 'namespaces is forbidden' >&2; exit 1`)
		if err := preflightNotBakedNode(context.Background()); err == nil || !strings.Contains(err.Error(), "namespaces is forbidden") {
			t.Fatalf("want server error, got %v", err)
		}
	})
}

// podListFile writes a typed PodList as the JSON `kubectl get pods -A -o json`
// would emit and returns its path.
func podListFile(t *testing.T, pods ...corev1.Pod) string {
	t.Helper()
	data, err := json.Marshal(corev1.PodList{Items: pods})
	if err != nil {
		t.Fatalf("marshal pod list: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pod list: %v", err)
	}
	return path
}

func hostPortPod(ns, name, node string, port int32) corev1.Pod {
	return corev1.Pod{
		Namespace: ns, Name: name,
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Ports: []corev1.ContainerPort{{HostPort: port}}}},
		},
	}
}

func TestPreflightRouterHostPortExec(t *testing.T) {
	values := "router:\n  enabled: true\n  hostPort:\n    enabled: true\n    https: \"\"\n"
	kubectlBody := func(nodes, podsFile string) string {
		return `case "$*" in
"get pods --all-namespaces -o json") /bin/cat '` + podsFile + `' ;;
"get nodes -o jsonpath"*) /usr/bin/printf '` + nodes + `' ;;
esac`
	}

	t.Run("port taken on every node aborts", func(t *testing.T) {
		pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", kubectlBody(`node-a\n`, pods))
		err := preflightRouterHostPort(context.Background(), writeChart(t, values), "c8s-system")
		if err == nil {
			t.Fatal("want error when the host port is bound on every node")
		}
		for _, want := range []string{"443", "kube-system/ingress-a", "router.hostPort.enabled=false"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err, want)
			}
		}
	})

	t.Run("a free node passes", func(t *testing.T) {
		pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", kubectlBody(`node-a\nnode-b\n`, pods))
		if err := preflightRouterHostPort(context.Background(), writeChart(t, values), "c8s-system"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("own namespace holder is ignored", func(t *testing.T) {
		pods := podListFile(t, hostPortPod("c8s-system", "c8s-router", "node-a", 443))
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", kubectlBody(`node-a\n`, pods))
		if err := preflightRouterHostPort(context.Background(), writeChart(t, values), "c8s-system"); err != nil {
			t.Fatalf("re-install must not flag its own router: %v", err)
		}
	})

	t.Run("hostPort disabled skips the cluster reads", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", "")
		chart := writeChart(t, "router:\n  enabled: true\n  hostPort:\n    enabled: false\n")
		if err := preflightRouterHostPort(context.Background(), chart, "c8s-system"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustNotContainPrefix(t, f.calls(t), "kubectl")
	})

	t.Run("node read failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", "exit 1")
		if err := preflightRouterHostPort(context.Background(), writeChart(t, values), "c8s-system"); err == nil {
			t.Fatal("want error when kubectl fails")
		}
	})

	t.Run("unparseable pod list surfaces", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "pods.json")
		if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "kubectl", kubectlBody(`node-a\n`, bad))
		if err := preflightRouterHostPort(context.Background(), writeChart(t, values), "c8s-system"); err == nil {
			t.Fatal("want error for unparseable pod list")
		}
	})
}

func TestDetectDistroExec(t *testing.T) {
	t.Run("rke2 kubelet suffix selects rke2", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/usr/bin/printf 'node-a\tv1.29.5+rke2r1\n'`)
		got, err := detectDistro(context.Background())
		if err != nil || got != "rke2" {
			t.Fatalf("detectDistro = (%q, %v), want (rke2, nil)", got, err)
		}
	})
	t.Run("vanilla kubelet selects k8s", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/usr/bin/printf 'node-a\tv1.31.0\n'`)
		got, err := detectDistro(context.Background())
		if err != nil || got != "k8s" {
			t.Fatalf("detectDistro = (%q, %v), want (k8s, nil)", got, err)
		}
	})
	t.Run("kubectl failure surfaces its stderr", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo The connection to the server dead was refused >&2; exit 1")
		_, err := detectDistro(context.Background())
		if err == nil || !strings.Contains(err.Error(), "The connection to the server dead was refused") {
			t.Fatalf("want kubectl's own reason in the error, got %v", err)
		}
	})
}

func TestCraneDigestShellsOut(t *testing.T) {
	t.Run("resolves the ref", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "echo "+testDigest)
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

func TestComponentEnabledPredicateExec(t *testing.T) {
	values := "attestationApi:\n  enabled: true\n"

	t.Run("set override beats the chart default", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		enabled, err := componentEnabledPredicate(context.Background(), writeChart(t, values),
			[]string{"--set", "attestationApi.enabled=false"})
		if err != nil {
			t.Fatalf("componentEnabledPredicate: %v", err)
		}
		if on, _ := enabled("attestationApi.enabled"); on {
			t.Error("override to false must win over the chart default true")
		}
	})

	t.Run("chart default stands without overrides", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		enabled, err := componentEnabledPredicate(context.Background(), writeChart(t, values), nil)
		if err != nil {
			t.Fatalf("componentEnabledPredicate: %v", err)
		}
		if on, _ := enabled("attestationApi.enabled"); !on {
			t.Error("chart default true must stand")
		}
	})

	t.Run("helm failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "exit 1")
		if _, err := componentEnabledPredicate(context.Background(), writeChart(t, values), nil); err == nil {
			t.Fatal("want error when helm fails")
		}
	})

	t.Run("overlay conflict surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		_, err := componentEnabledPredicate(context.Background(), writeChart(t, values),
			[]string{"--set", "attestationApi=x", "--set", "attestationApi.enabled=false"})
		if err == nil {
			t.Fatal("want error for a scalar/map overlay conflict")
		}
	})
}

func TestOverlaySetArgs(t *testing.T) {
	t.Run("applies typed and string pairs", func(t *testing.T) {
		tree := map[string]any{}
		err := overlaySetArgs(tree, []string{
			"--set", "a.b=true",
			"--set-string", "c=42",
			"--set-file", "skip=/nonexistent", // --set-file never carries an enable toggle
			"--set", "junk", // no '=', skipped
		})
		if err != nil {
			t.Fatalf("overlaySetArgs: %v", err)
		}
		want := map[string]any{"a": map[string]any{"b": true}, "c": "42"}
		if !reflect.DeepEqual(tree, want) {
			t.Fatalf("tree = %#v, want %#v", tree, want)
		}
	})

	t.Run("value keeps everything after the first equals", func(t *testing.T) {
		tree := map[string]any{}
		if err := overlaySetArgs(tree, []string{"--set-string", "k=a=b"}); err != nil {
			t.Fatalf("overlaySetArgs: %v", err)
		}
		if tree["k"] != "a=b" {
			t.Fatalf("k = %#v, want %q", tree["k"], "a=b")
		}
	})

	t.Run("empty path before equals is applied", func(t *testing.T) {
		tree := map[string]any{}
		if err := overlaySetArgs(tree, []string{"--set", "=x"}); err != nil {
			t.Fatalf("overlaySetArgs: %v", err)
		}
		if tree[""] != "x" {
			t.Fatalf("tree = %#v, want the empty key set to x", tree)
		}
	})

	t.Run("dangling flag is ignored without panicking", func(t *testing.T) {
		tree := map[string]any{}
		if err := overlaySetArgs(tree, []string{"--set", "a=1", "--set"}); err != nil {
			t.Fatalf("overlaySetArgs: %v", err)
		}
		if tree["a"] != int64(1) || len(tree) != 1 {
			t.Fatalf("tree = %#v, want only a=1", tree)
		}
	})

	t.Run("scalar conflict surfaces", func(t *testing.T) {
		tree := map[string]any{}
		if err := overlaySetArgs(tree, []string{"--set", "a=1", "--set", "a.b=2"}); err == nil {
			t.Fatal("want error for a scalar/map conflict")
		}
	})
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

func TestPreflightOperatorImageExec(t *testing.T) {
	comps := []c8sComponent{
		{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"},
		{valuePrefix: "image", repository: "ghcr.io/x/op"},
	}

	t.Run("published operator image passes", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "echo "+testDigest)
		if err := preflightOperatorImage(context.Background(), comps, "v1"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Only the operator component resolves here, at repo:tag.
		mustContainLine(t, f.calls(t), "crane digest ghcr.io/x/op:v1")
		mustNotContainPrefix(t, f.calls(t), "crane digest ghcr.io/x/cds")
	})

	t.Run("missing tag aborts with the coupling hint", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", `echo "MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1`)
		err := preflightOperatorImage(context.Background(), comps, "v1")
		if err == nil || !strings.Contains(err.Error(), "not published") {
			t.Fatalf("want a not-published error, got %v", err)
		}
	})

	t.Run("auth or network trouble warns and continues", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", `echo "UNAUTHORIZED" >&2; exit 1`)
		if err := preflightOperatorImage(context.Background(), comps, "v1"); err != nil {
			t.Fatalf("best-effort path must not abort: %v", err)
		}
	})

	t.Run("crane off PATH warns and continues", func(t *testing.T) {
		newFakeBin(t)
		if err := preflightOperatorImage(context.Background(), comps, "v1"); err != nil {
			t.Fatalf("missing crane must not abort: %v", err)
		}
	})

	t.Run("no operator component is a no-op", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "echo "+testDigest)
		if err := preflightOperatorImage(context.Background(), comps[:1], "v1"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustNotContainPrefix(t, f.calls(t), "crane")
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
		got, err := adoptedWorkloadImages(context.Background(), ref)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"ghcr.io/acme/vllm:v1"}) {
			t.Fatalf("images = %v, want [ghcr.io/acme/vllm:v1]", got)
		}
		mustContainLine(t, f.calls(t), "kubectl get deployment vllm -n ws -o json")
	})

	t.Run("kubectl failure carries its output", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo no-such-workload; exit 1")
		_, err := adoptedWorkloadImages(context.Background(), ref)
		if err == nil || !strings.Contains(err.Error(), "no-such-workload") {
			t.Fatalf("want kubectl output in the error, got %v", err)
		}
	})
}

func TestAppendResolvedWorkloadImageArgsExec(t *testing.T) {
	t.Run("resolves and pins the allowlist entry", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "echo "+testDigest)
		got, err := appendResolvedWorkloadImageArgs(context.Background(), nil, []string{"ghcr.io/acme/vllm:v1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		p := "nriImagePolicy.bootstrapAllowlist.workloads.vllm-" + testDigest[7:19] + "."
		assertArgsEqual(t, got, []string{
			"--set-string", p + "label=ghcr.io/acme/vllm@" + testDigest,
			"--set-string", p + "containers[0].digest=" + testDigest,
			"--set-string", p + "containers[0].image=ghcr.io/acme/vllm@" + testDigest,
			"--set-string", p + "containers[0].command.policy=any",
			"--set-string", p + "containers[0].args.policy=any",
		})
		mustContainLine(t, f.calls(t), "crane digest ghcr.io/acme/vllm:v1")
	})

	t.Run("resolver failure aborts", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "crane", "exit 1")
		if _, err := appendResolvedWorkloadImageArgs(context.Background(), nil, []string{"ghcr.io/acme/vllm:v1"}); err == nil {
			t.Fatal("want error when crane fails")
		}
	})
}

func TestAppendResolvedDigestArgsExec(t *testing.T) {
	comps := []c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}}

	t.Run("crane off PATH is an actionable error", func(t *testing.T) {
		newFakeBin(t)
		_, err := appendResolvedDigestArgs(context.Background(), t.TempDir(), nil, "main", comps)
		if err == nil || !strings.Contains(err.Error(), "crane") {
			t.Fatalf("want a crane-not-found error, got %v", err)
		}
	})

	t.Run("pins repository and digest per component", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "crane", "echo "+testDigest)
		got, err := appendResolvedDigestArgs(context.Background(), writeChart(t, "a: 1\n"), nil, "main", comps)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertArgsEqual(t, got, []string{
			"--set-string", "cds.image.repository=ghcr.io/x/cds",
			"--set-string", "cds.image.digest=" + testDigest,
			"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		})
		mustContainLine(t, f.calls(t), "crane digest ghcr.io/x/cds:main")
	})

	t.Run("helm failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "exit 1")
		f.tool(t, "crane", "echo "+testDigest)
		if _, err := appendResolvedDigestArgs(context.Background(), writeChart(t, "a: 1\n"), nil, "main", comps); err == nil {
			t.Fatal("want error when helm fails")
		}
	})

	t.Run("resolve failure aborts", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		f.tool(t, "crane", "exit 1")
		if _, err := appendResolvedDigestArgs(context.Background(), writeChart(t, "a: 1\n"), nil, "main", comps); err == nil {
			t.Fatal("want error when crane fails")
		}
	})
}

func TestPrintAttestVerifyHint(t *testing.T) {
	prev := installMeasurements
	defer func() { installMeasurements = prev }()

	var buf bytes.Buffer
	installMeasurements = nil
	printAttestVerifyHint(&buf, false)
	if buf.Len() != 0 {
		t.Errorf("--attest=false must print nothing, got %q", buf.String())
	}

	buf.Reset()
	printAttestVerifyHint(&buf, true)
	if !strings.Contains(buf.String(), "UNPINNED") {
		t.Errorf("no measurements: want the UNPINNED warning, got %q", buf.String())
	}

	buf.Reset()
	installMeasurements = []string{strings.Repeat("aa", 48)}
	printAttestVerifyHint(&buf, true)
	out := buf.String()
	if !strings.Contains(out, "pinned to --measurements") || strings.Contains(out, "UNPINNED") {
		t.Errorf("with measurements: want the pinned hint only, got %q", out)
	}
}

// installStubs wires stub helm/kubectl/crane for full `c8s install` runs
// against the real embedded chart. The helm stub answers `show values` with
// the chart's values.yaml and snapshots the computed values file an upgrade
// receives; kubectl apply payloads are captured for typed inspection.
type installStubs struct {
	f        *fakeBin
	computed string
	applied  string
}

func newInstallStubs(t *testing.T, kubectlBody string, helmUpgradeFails bool) *installStubs {
	t.Helper()
	f := newFakeBin(t)
	s := &installStubs{
		f:        f,
		computed: filepath.Join(f.dir, "computed.yaml"),
		applied:  filepath.Join(f.dir, "applied.json"),
	}
	fail := ""
	if helmUpgradeFails {
		fail = "exit 1"
	}
	f.tool(t, "helm", `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
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
	f.tool(t, "crane", "echo "+testDigest)
	return s
}

// clusterKubectl is a healthy single-node cluster: one vanilla linux node that
// carries the CDS and SNP labels, no pods, and namespace applies captured.
// extra case arms are matched first, so scenarios override single answers.
func clusterKubectl(applied, extra string) string {
	return `case "$*" in
` + extra + `*kubeletVersion*) /usr/bin/printf 'node-a\tv1.31.0\n' ;;
"get nodes -l role=cds -o name") echo node/node-a ;;
"get nodes -l confidential.ai/sev-snp=true -o name") echo node/node-a ;;
"get nodes -o json") echo '{"items":[{"metadata":{"name":"node-a"},"spec":{"podCIDR":"10.42.0.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.10"}]}}]}' ;;
"get pods --all-namespaces -o json") echo '{"items":[]}' ;;
"apply -f -") /bin/cat >> '` + applied + `' ;;
esac`
}

func TestInstallBareMetalModeHappyPath(t *testing.T) {
	var s *installStubs
	var err error
	stderr := captureStderr(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
		err = runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force")
	})
	if err != nil {
		t.Fatalf("install: %v\nstderr:\n%s", err, stderr)
	}
	calls := s.f.calls(t)

	// The helm invocation: release/namespace fixed, computed values as the
	// last -f, no --wait.
	hi := lineIndex(calls, "helm upgrade ")
	if hi < 0 {
		t.Fatalf("no helm upgrade logged:\n%s", strings.Join(calls, "\n"))
	}
	args := strings.Fields(calls[hi])[1:]
	if len(args) != 8 || args[0] != "upgrade" || args[1] != "--install" || args[2] != "c8s" ||
		args[4] != "--namespace" || args[5] != "c8s-system" || args[6] != "-f" {
		t.Fatalf("helm argv = %v", args)
	}

	// Preflights and the namespace apply all happen before helm mutates the
	// cluster via the chart.
	for _, prefix := range []string{
		"kubectl get nodes -l role=cds -o name",
		"kubectl get pods --all-namespaces -o json",
		"kubectl apply -f -",
	} {
		if i := lineIndex(calls, prefix); i < 0 || i > hi {
			t.Errorf("%q must run before helm upgrade (index %d vs %d)", prefix, i, hi)
		}
	}

	// An unstamped build resolves digests at the fallback tag, and only for
	// components the bare-metal mode actually renders. nri-image-policy is among
	// them: the baked installer runs from that image, and its digest is what
	// derives it into the seed the node's plugin admits it from.
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/c8s-operator:main")
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/cds:main")
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/armtls-mesh:main")
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/nri-image-policy:main")
	mustNotContainPrefix(t, calls, "crane digest ghcr.io/confidential-dot-ai/attestation-api")
	// volumed stays off without --volumes.
	mustNotContainPrefix(t, calls, "crane digest ghcr.io/confidential-dot-ai/volumed")

	// --force without operator keys must say what it is giving up.
	if !strings.Contains(stderr, "allowlist writes DISABLED") {
		t.Errorf("stderr missing the operator-keys warning:\n%s", stderr)
	}

	// The computed values helm received, decoded and pinned.
	tree := readYAMLTree(t, s.computed)
	if got := treeAt(t, tree, "attestationApi", "cvmMode"); got != "bare-metal" {
		t.Errorf("attestationApi.cvmMode = %#v, want bare-metal", got)
	}
	if got := treeAt(t, tree, "attestationApi", "enabled"); got != false {
		t.Errorf("attestationApi.enabled = %#v, want false (baked into the node image)", got)
	}
	// The plugin is baked, but its installer stays on (chart default enabled) —
	// it is the only path that writes this release's CDS pins into the baked
	// config, so bare-metal mode flips the installer's shape, not its presence.
	if got := treeAt(t, tree, "nriImagePolicy", "baked"); got != true {
		t.Errorf("nriImagePolicy.baked = %#v, want true", got)
	}
	if got := treeAt(t, tree, "attestationApi", "teeDevices", "sevGuest"); got != true {
		t.Errorf("teeDevices.sevGuest = %#v, want true", got)
	}
	if got := treeAt(t, tree, "image", "digest"); got != testDigest {
		t.Errorf("image.digest = %#v, want %s", got, testDigest)
	}
	if got := treeAt(t, tree, "nriImagePolicy", "distro"); got != "k8s" {
		t.Errorf("nriImagePolicy.distro = %#v, want the detected k8s", got)
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

func TestInstallImageTagOverridesResolveRef(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	if err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--image-tag=v9.9.9"); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := s.f.calls(t)
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/c8s-operator:v9.9.9")
	mustNotContainPrefix(t, calls, "crane digest ghcr.io/confidential-dot-ai/c8s-operator:main")
}

// --volumes must reach helm as volumed.enabled, and must do so before digest
// resolution: the daemon's own image is pinned only for a component the
// effective values enable, and that pin is what derives it into the NRI floor
// that would otherwise deny it.
func TestInstallVolumesEnablesTheNodeAgent(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	if err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--volumes"); err != nil {
		t.Fatalf("install: %v", err)
	}
	mustContainLine(t, s.f.calls(t), "crane digest ghcr.io/confidential-dot-ai/volumed:main")

	tree := readYAMLTree(t, s.computed)
	if got := treeAt(t, tree, "volumed", "enabled"); got != true {
		t.Errorf("volumed.enabled = %#v, want true", got)
	}
	if got := treeAt(t, tree, "volumed", "image", "digest"); got != testDigest {
		t.Errorf("volumed.image.digest = %#v, want %s", got, testDigest)
	}
}

func TestInstallFailsFastWhenCDSNodeUnlabelled(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, `"get nodes -l role=cds -o name") : ;;
`))
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false")
	if err == nil || !strings.Contains(err.Error(), "role=cds") {
		t.Fatalf("want the CDS label preflight failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

func TestInstallSingleNodeSkipsCDSNodePreflight(t *testing.T) {
	s := newInstallStubs(t, "", false)
	// No node carries role=cds; --single-node clears the selector so the
	// preflight must not even ask.
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, `"get nodes -l role=cds -o name") : ;;
`))
	if err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false", "--single-node"); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "kubectl get nodes -l role=cds")
	if lineIndex(calls, "helm upgrade ") < 0 {
		t.Fatal("helm upgrade did not run")
	}
	tree := readYAMLTree(t, s.computed)
	sel, ok := treeAt(t, tree, "cds", "node").(map[string]any)
	if !ok || sel["selector"] != nil {
		t.Errorf("cds.node = %#v, want a cleared (null) selector", sel)
	}
}

func TestInstallAbortsOnRouterHostPortConflict(t *testing.T) {
	pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
	s := newInstallStubs(t, "", false)
	// kubeletVersion first: the distro query also mentions .metadata.name.
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, `*kubeletVersion*) /usr/bin/printf 'node-a\tv1.31.0\n' ;;
*metadata.name*) echo node-a ;;
"get pods --all-namespaces -o json") /bin/cat '`+pods+`' ;;
`))
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false")
	if err == nil || !strings.Contains(err.Error(), "443") || !strings.Contains(err.Error(), "kube-system/ingress-a") {
		t.Fatalf("want the router host-port conflict, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

func TestInstallAdoptsWorkloadAfterHelm(t *testing.T) {
	deploy := deploymentFile(t, "ghcr.io/acme/vllm@"+testDigest)
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, `"get deployment vllm -n ws -o json") /bin/cat '`+deploy+`' ;;
`))
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--force", "--resolve-digests=false",
		"--workload-ref", "infer=ws/deployment/vllm:8000", "--upstream", "infer")
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

	tree := readYAMLTree(t, s.computed)
	if got := treeAt(t, tree, "router", "upstream", "address"); got != "c8s-infer.ws.svc.cluster.local:8000" {
		t.Errorf("router.upstream.address = %#v, want the adopted headless-Service address", got)
	}
}

func TestInstallHelmUpgradeFailureSurfaces(t *testing.T) {
	s := newInstallStubs(t, "", true)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false")
	if err == nil || !strings.Contains(err.Error(), "helm install failed") {
		t.Fatalf("want the helm failure surfaced, got %v", err)
	}
}

func TestInstallNamespaceApplyFailureSurfaces(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl("", `"apply -f -") exit 1 ;;
`))
	err := runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false")
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
		err := runC8s(t, "install", "--cvm-mode=bare-metal", "--force")
		if err == nil || !strings.Contains(err.Error(), "helm CLI not found") {
			t.Fatalf("want a helm-not-found error, got %v", err)
		}
	})
	t.Run("kubectl missing", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "")
		t.Setenv("PATH", f.dir)
		err := runC8s(t, "install", "--cvm-mode=bare-metal", "--force")
		if err == nil || !strings.Contains(err.Error(), "kubectl CLI not found") {
			t.Fatalf("want a kubectl-not-found error, got %v", err)
		}
	})
}

// helmValuesCapture re-stubs helm so an `upgrade` appends every -f file's
// content (path header + payload) to captureFile, in argv order. It keeps the
// installStubs `show values` answer.
func helmValuesCapture(t *testing.T, s *installStubs, captureFile string) {
	t.Helper()
	s.f.tool(t, "helm", `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
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

// `c8s install -f -` pipes stdin into a real values file: the distro scan and
// effectiveValues must read it, and helm must receive the piped bytes as a
// -f file ahead of the computed values.
func TestInstallValuesFromStdin(t *testing.T) {
	payload := "volumed:\n  enabled: true\nnriImagePolicy:\n  distro: rke2\n"

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	capture := filepath.Join(s.f.dir, "values-stream.log")
	helmValuesCapture(t, s, capture)

	resetCLIState(t)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	rootCmd.SetIn(strings.NewReader(payload))
	rootCmd.SetArgs([]string{"install", "--cvm-mode=bare-metal", "--wait=false", "-f", "-"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := s.f.calls(t)

	// The piped nriImagePolicy.distro owns the distro, so detection never runs.
	mustNotContainPrefix(t, calls, "kubectl get nodes -o jsonpath")

	// The piped volumed.enabled=true is visible to the digest resolver, which
	// reads effectiveValues — volumed is pinned only when enabled there.
	mustContainLine(t, calls, "crane digest ghcr.io/confidential-dot-ai/volumed:main")

	// Helm received the piped values as a real -f file, followed by the
	// computed values file (which wins on shared keys).
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read values capture: %v", err)
	}
	sections := strings.Split(string(data), "== ")
	if len(sections) != 3 { // leading empty + stdin file + computed file
		t.Fatalf("helm received %d -f files, want 2:\n%s", len(sections)-1, data)
	}
	stdinSection := sections[1]
	header, content, _ := strings.Cut(stdinSection, "\n")
	if !strings.Contains(header, "c8s-install-stdin-") {
		t.Errorf("first -f is %q, want the materialized stdin file", header)
	}
	if content != payload {
		t.Errorf("helm's stdin-derived -f content = %q, want the piped %q", content, payload)
	}
	if got := treeAt(t, readYAMLTree(t, s.computed), "attestationApi", "cvmMode"); got != "bare-metal" {
		t.Errorf("computed values cvmMode = %#v, want bare-metal (last -f still the computed file)", got)
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
	rootCmd.SetArgs([]string{"install", "--cvm-mode=bare-metal", "-f", "-"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "create stdin values file") {
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
		{"missing cvm mode", []string{"install"}, "--cvm-mode is required"},
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
		if _, err := effectiveValues(context.Background(), writeChart(t, "	"), nil); err == nil {
			t.Fatal("want the chart-values parse error")
		}
	})

	t.Run("missing values file", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		prev := installValues
		t.Cleanup(func() { installValues = prev })
		installValues = []string{filepath.Join(t.TempDir(), "missing.yaml")}
		_, err := effectiveValues(context.Background(), writeChart(t, "a: 1\n"), nil)
		if err == nil || !strings.Contains(err.Error(), "read values file") {
			t.Fatalf("want the read error, got %v", err)
		}
	})

	t.Run("unparseable values file", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", helmShowValuesBody)
		prev := installValues
		t.Cleanup(func() { installValues = prev })
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(bad, []byte("\t"), 0o600); err != nil {
			t.Fatal(err)
		}
		installValues = []string{bad}
		_, err := effectiveValues(context.Background(), writeChart(t, "a: 1\n"), nil)
		if err == nil || !strings.Contains(err.Error(), "parse values file") {
			t.Fatalf("want the parse error, got %v", err)
		}
	})
}

// --hardware-platform fails like --cvm-mode does: at flag validation, before
// any helm/kubectl invocation.
func TestInstallValidatesHardwarePlatformBeforeTheCluster(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := newFakeBin(t)
		err := runC8s(t, "install", "--cvm-mode=bare-metal", "--hardware-platform=")
		if err == nil || !strings.Contains(err.Error(), "--hardware-platform is required; one of sev-snp, tdx") {
			t.Fatalf("want the required-platform error, got %v", err)
		}
		if got := f.calls(t); len(got) != 0 {
			t.Errorf("validation must precede every exec, logged: %v", got)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		f := newFakeBin(t)
		err := runC8s(t, "install", "--cvm-mode=bare-metal", "--hardware-platform=power9")
		if err == nil || !strings.Contains(err.Error(), `--hardware-platform must be one of sev-snp, tdx, got "power9"`) {
			t.Fatalf("want the unknown-platform error, got %v", err)
		}
		if got := f.calls(t); len(got) != 0 {
			t.Errorf("validation must precede every exec, logged: %v", got)
		}
	})
}

// The hosted lanes must render the exempt-namespace default themselves: a
// plain `--cvm-mode=aks` install that renders digest-only admission denies the
// platform's own kube-system pods at the containerd restart it performs.
func TestInstallHostedLaneDefaultsExemptNamespaces(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	if err := runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--force", "--resolve-digests=false"); err != nil {
		t.Fatalf("install: %v", err)
	}
	got := treeAt(t, readYAMLTree(t, s.computed), "nriImagePolicy", "policy", "exemptNamespaces")
	if want := []any{"kube-system"}; !reflect.DeepEqual(got, want) {
		t.Errorf("exemptNamespaces = %#v, want %#v", got, want)
	}
}

// The computed values are helm's LAST -f, so they win on every key they set.
// An operator who wrote exemptNamespaces must therefore see it reach helm
// unchanged — the default must not be emitted at all.
func TestInstallHostedLaneKeepsOperatorExemptNamespaces(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))
	values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: [gatekeeper-system]\n")
	if err := runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--resolve-digests=false", "-f", values); err != nil {
		t.Fatalf("install: %v", err)
	}
	policy, _ := treeAt(t, readYAMLTree(t, s.computed), "nriImagePolicy").(map[string]any)["policy"].(map[string]any)
	if got, ok := policy["exemptNamespaces"]; ok {
		t.Errorf("computed values override the operator's exemptNamespaces with %#v", got)
	}
}

// platformPodListKubectl answers the pod list with one static control-plane
// pod, on top of the healthy-cluster answers.
func platformPodListKubectl(applied, podsFile string) string {
	return clusterKubectl(applied, `"get pods --all-namespaces -o json") /bin/cat '`+podsFile+`' ;;
`)
}

const etcdDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func staticEtcdPod() corev1.Pod {
	return corev1.Pod{
		Namespace:   "kube-system",
		Name:        "etcd-node-a",
		Annotations: map[string]string{corev1.MirrorPodAnnotationKey: "mirror"},
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
	pods := podListFile(t, staticEtcdPod())
	s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, pods))
	// exemptNamespaces cleared: the shape a pre-#396 values file installs.
	values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")

	err := runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--resolve-digests=false", "-f", values)
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

// The default hosted-lane install exempts kube-system, so the same cluster
// passes with no values file at all.
func TestInstallHostedLaneDefaultAdmitsPlatformPods(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, podListFile(t, staticEtcdPod())))
	if err := runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--force", "--resolve-digests=false"); err != nil {
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
		s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, podListFile(t, staticEtcdPod())))
		values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")
		err = runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--force", "--resolve-digests=false", "-f", values)
	})
	if err != nil {
		t.Fatalf("--force must install anyway: %v", err)
	}
	if !strings.Contains(stderr, "1 platform image") {
		t.Errorf("stderr missing the forced-past warning:\n%s", stderr)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// audit mode creates the container anyway, so there is nothing to refuse — and
// no pod list to read.
func TestInstallAuditPolicySkipsPlatformPodCheck(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, podListFile(t, staticEtcdPod())))
	values := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    mode: audit\n    exemptNamespaces: []\n")
	if err := runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--resolve-digests=false", "-f", values); err != nil {
		t.Fatalf("install: %v", err)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// The exempted digest set is what an operator has to review before the plugin
// freezes it on every node, so a default hosted-lane install must print it.
func TestInstallReportsWhatTheExemptionAdmits(t *testing.T) {
	var s *installStubs
	var err error
	stdout := captureStdout(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, podListFile(t, staticEtcdPod())))
		err = runC8s(t, "install", "--cvm-mode=aks", "--wait=false", "--force", "--resolve-digests=false")
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, want := range []string{
		"kube-system/etcd-node-a",
		"docker.io/rancher/hardened-etcd@" + etcdDigest,
		"nriImagePolicy.bootstrapAllowlist.workloads",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("install output does not report %q:\n%s", want, stdout)
		}
	}
	// It has to land before the plugin is installed, or reviewing it is moot.
	if i, h := strings.Index(stdout, "kube-system/etcd-node-a"), lineIndex(s.f.calls(t), "helm upgrade "); i < 0 || h < 0 {
		t.Fatalf("missing report (%d) or helm upgrade (%d)", i, h)
	}
	mustContainLine(t, s.f.calls(t), "kubectl apply -f -")
}

// Nothing is exempt on the bare-metal lane, so there is nothing to report.
func TestInstallNodeLaneReportsNoExemption(t *testing.T) {
	var s *installStubs
	var err error
	stdout := captureStdout(t, func() {
		s = newInstallStubs(t, "", false)
		s.f.tool(t, "kubectl", platformPodListKubectl(s.applied, podListFile(t, staticEtcdPod())))
		err = runC8s(t, "install", "--cvm-mode=bare-metal", "--wait=false", "--force", "--resolve-digests=false")
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if strings.Contains(stdout, "admitted by captured digest") {
		t.Errorf("bare-metal lane reported an exemption it does not render:\n%s", stdout)
	}
}

// The hosted-lane default stands aside for a -f file that writes the key, and
// `-f -` is such a file: the exempt scan runs after stdin is materialized, so
// it reads the piped bytes rather than a literal "-".
func TestInstallHostedLaneKeepsExemptNamespacesFromStdin(t *testing.T) {
	payload := "nriImagePolicy:\n  policy:\n    exemptNamespaces: [gatekeeper-system]\n"

	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(s.applied, ""))

	resetCLIState(t)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	rootCmd.SetIn(strings.NewReader(payload))
	rootCmd.SetArgs([]string{"install", "--cvm-mode=aks", "--wait=false", "--resolve-digests=false", "-f", "-"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	policy, _ := treeAt(t, readYAMLTree(t, s.computed), "nriImagePolicy").(map[string]any)["policy"].(map[string]any)
	if got, ok := policy["exemptNamespaces"]; ok {
		t.Errorf("computed values override the piped exemptNamespaces with %#v", got)
	}
}
