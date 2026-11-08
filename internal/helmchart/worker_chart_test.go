package helmchart

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// workerChart is the c8s-worker chart in the repository layout.
const workerChart = "worker"

// workerStockFiles are the worker chart's stock files, one per CPU TEE.
var workerStockFiles = []string{
	"values-sev-snp.yaml",
	"values-tdx.yaml",
}

// helmTemplateWorker renders the worker chart with a stock file and the image
// digests the worker render commands pass.
func helmTemplateWorker(t *testing.T, stockFile string, args ...string) string {
	t.Helper()
	base := []string{
		"template", "c8s", workerChart,
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--include-crds",
		"-f", workerChart + "/" + stockFile,
		"--set-string", "image.digest=" + c8sDigest,
		"--set-string", "armtlsMesh.image.digest=sha256:" + strings.Repeat("2", 64),
	}
	out, err := helmOutput(exec.Command("helm", append(base, args...)...))
	if err != nil {
		t.Fatalf("helm template %s: %v\n%s", stockFile, err, out)
	}
	return string(out)
}

// renderedObjectKeys lists each rendered object as kind/namespace/name.
func renderedObjectKeys(t *testing.T, manifest string) []string {
	t.Helper()
	var keys []string
	for _, doc := range splitManifestDocs(manifest) {
		var meta struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("decode: %v\n%s", err, doc)
		}
		if meta.Kind != "" {
			keys = append(keys, meta.Kind+"/"+meta.Metadata.Namespace+"/"+meta.Metadata.Name)
		}
	}
	slices.Sort(keys)
	return keys
}

// A cluster of workers holds these objects and no other, and the operator's
// grants go to its user alone.
func TestWorkerChartRendersItsObjects(t *testing.T) {
	t.Parallel()
	want := []string{
		"ClusterRole//c8s-operator",
		"ClusterRoleBinding//c8s-operator",
		"ConfigMap/c8s-system/c8s-allowlist-seed",
		"CustomResourceDefinition//confidentialworkloads.confidential.ai",
		"Deployment/c8s-router/c8s-router",
		"MutatingWebhookConfiguration//c8s-pod-injector",
		"Namespace//c8s-router",
		"Namespace//c8s-system",
		"NetworkPolicy/c8s-router/c8s-router-ingress",
		"Service/c8s-router/c8s-router",
		"ValidatingWebhookConfiguration//c8s-pod-validator",
	}
	for _, stockFile := range workerStockFiles {
		out := helmTemplateWorker(t, stockFile)
		if got := renderedObjectKeys(t, out); !slices.Equal(got, want) {
			t.Errorf("%s renders %v, want %v", stockFile, got, want)
		}
		var binding rbacv1.ClusterRoleBinding
		findDoc(t, out, "ClusterRoleBinding", "c8s-operator", &binding)
		operator := rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "c8s-operator"}
		if !slices.Equal(binding.Subjects, []rbacv1.Subject{operator}) {
			t.Errorf("%s binds the operator's grants to %v, want the user c8s-operator alone", stockFile, binding.Subjects)
		}
	}
}

func TestWorkerChartRouterMatchesSeededEntry(t *testing.T) {
	t.Parallel()
	for _, stockFile := range workerStockFiles {
		assertRouterMatches(t, helmTemplateWorker(t, stockFile))
	}
}

func TestWorkerValuesSchemaCoversValuesYAML(t *testing.T) {
	t.Parallel()
	assertChartSchemaCovers(t, workerChart, []string{
		"armtlsMesh",
		"certProvisioning",
		"controlPlane",
		"image",
		"router",
	})
}
