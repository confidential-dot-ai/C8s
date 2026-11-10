package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestCloudWebhookProviderExclusions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		platform string
		args     []string
		excluded []string
	}{
		{
			name:     "gke",
			platform: "gke-snp",
			excluded: []string{"local-path-storage", "kube-system", "gmp-system", "gke-managed-cim"},
		},
		{
			name:     "aks-snp",
			platform: "aks-snp",
			excluded: []string{"local-path-storage", "kube-system"},
		},
		{
			name:     "aks-tdx",
			platform: "aks-tdx",
			excluded: []string{"local-path-storage", "kube-system"},
		},
		{
			name:     "custom provider and explicit exclusions",
			platform: "aks-snp",
			args: []string{
				"--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,gatekeeper-system}",
				"--set-string", "nriImagePolicy.policy.exemptRepositories.gatekeeper-system[0]=mcr.microsoft.com/oss/",
				"--set", "controlPlane.webhook.extraExcluded={operator-tools}",
			},
			excluded: []string{"gatekeeper-system", "operator-tools", "kube-system"},
		},
		{
			name:     "overlapping exclusions",
			platform: "gke-snp",
			args:     []string{"--set", "controlPlane.webhook.extraExcluded={gmp-system,operator-tools}"},
			excluded: []string{"gmp-system", "operator-tools", "kube-system", "gke-managed-cim"},
		},
		{
			name:     "provider exclusions survive empty extras",
			platform: "gke-snp",
			args:     []string{"--set-json", "controlPlane.webhook.extraExcluded=[]"},
			excluded: []string{"kube-system", "gmp-system", "gke-managed-cim"},
		},
		{
			name:     "empty policy ignores repository keys",
			platform: "gke-snp",
			args:     []string{"--set-json", "nriImagePolicy.policy.exemptNamespaces=[]"},
			excluded: []string{"local-path-storage"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := helmTemplatePlatform(t, tc.platform, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			assertCloudWebhookExclusions(t, out, tc.excluded)
		})
	}
}

func TestControlPlaneWebhookExclusionsAsDependency(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	chart := "apiVersion: v2\nname: test-parent\nversion: 0.1.0\ndependencies:\n  - name: c8s-control-plane\n    version: 0.1.0\n"
	if err := os.WriteFile(filepath.Join(parent, "Chart.yaml"), []byte(chart), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "charts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(controlPlaneChartDir, filepath.Join(parent, "charts", "c8s-control-plane")); err != nil {
		t.Fatal(err)
	}
	out, err := helmOutput(exec.Command("helm", "template", "c8s", parent,
		"--namespace", "c8s-system", "--kube-version", "1.30.0",
		"--set", "c8s-control-plane.webhook.extraExcluded={operator-tools}",
	))
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertWebhookExclusions(t, string(out), []string{"operator-tools"})
	assertWebhookExclusions(t, helmTemplateControlPlane(t, "--set", "webhook.extraExcluded={operator-tools}"), []string{"operator-tools"})
}

func TestCloudRefusesDuplicateWebhookRendering(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "controlPlane.webhook.render=true")
	if err == nil || !strings.Contains(out, "render") {
		t.Fatalf("duplicate webhook rendering error = %v\n%s", err, out)
	}
}

func assertCloudWebhookExclusions(t *testing.T, manifest string, expectedSweepExclusions []string) {
	t.Helper()
	want := slices.Clone(expectedSweepExclusions)
	slices.Sort(want)
	var got []string
	for _, arg := range renderedOperatorArgs(t, manifest) {
		if namespace, ok := strings.CutPrefix(arg, "--exclude-namespaces="); ok {
			got = append(got, namespace)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("sweep exclusions = %v, want %v", got, want)
	}
	assertWebhookExclusions(t, manifest, expectedSweepExclusions)
}

func assertWebhookExclusions(t *testing.T, manifest string, additionalExclusions []string) {
	t.Helper()
	kinds := renderedKinds(t, manifest)
	if kinds["MutatingWebhookConfiguration"] != 1 || kinds["ValidatingWebhookConfiguration"] != 1 {
		t.Fatalf("webhook configuration counts = %v", kinds)
	}
	mutating, validating := renderedWebhookConfigurations(t, manifest)
	if len(mutating.Webhooks) != 1 || len(validating.Webhooks) != 1 {
		t.Fatalf("webhook counts = %d mutating and %d validating, want one each", len(mutating.Webhooks), len(validating.Webhooks))
	}
	want := slices.Concat([]string{"c8s-system", "c8s-router", "kube-system", "kube-public", "kube-node-lease"}, additionalExclusions)
	slices.Sort(want)
	want = slices.Compact(want)
	for _, selector := range []*metav1.LabelSelector{mutating.Webhooks[0].NamespaceSelector, validating.Webhooks[0].NamespaceSelector} {
		got := selectorExpressionValues(selector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("webhook exclusions = %v, want %v", got, want)
		}
		matcher, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			t.Fatal(err)
		}
		for _, ns := range []string{"tenant", "gmp-system", "gke-managed-cim", "gatekeeper-system", "local-path-storage", "operator-tools"} {
			if selected := matcher.Matches(labels.Set{"kubernetes.io/metadata.name": ns}); selected == slices.Contains(want, ns) {
				t.Errorf("namespace %s selected = %t, exclusions %v", ns, selected, want)
			}
		}
	}
}

func TestExtractedCloudWebhookProviderExclusions(t *testing.T) {
	t.Parallel()
	chart := extractedChart(t)
	out, err := helmTemplateIn(t, chart, "-f", filepath.Join(chart, "values-gke-snp.yaml"))
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertCloudWebhookExclusions(t, out, []string{"local-path-storage", "kube-system", "gmp-system", "gke-managed-cim"})
}

func TestProviderExclusionsPreserveHostSecurityPolicy(t *testing.T) {
	t.Parallel()
	before, err := helmTemplatePlatform(t, "gke-snp")
	if err != nil {
		t.Fatal(err)
	}
	after, err := helmTemplatePlatform(t, "gke-snp",
		"--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,provider-tools}",
		"--set-string", "nriImagePolicy.policy.exemptRepositories.provider-tools[0]=registry.example/provider/",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"c8s-deny-host-namespaces", "c8s-deny-host-namespaces-ephemeral"} {
		var oldPolicy, newPolicy admissionregv1.ValidatingAdmissionPolicy
		if !findDoc(t, before, "ValidatingAdmissionPolicy", name, &oldPolicy) || !findDoc(t, after, "ValidatingAdmissionPolicy", name, &newPolicy) {
			t.Fatalf("missing policy %s", name)
		}
		if !reflect.DeepEqual(oldPolicy, newPolicy) {
			t.Errorf("provider exemptions changed host-security policy %s", name)
		}
	}
}
