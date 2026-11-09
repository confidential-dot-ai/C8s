package helmchart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	sigsyaml "sigs.k8s.io/yaml"

	acmecmd "github.com/confidential-dot-ai/c8s/internal/cmds/acme"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// containerArgs returns the args of the named container, main or init, after
// kubelet expansion. Fails the test if no such container exists.
func containerArgs(t *testing.T, ds *appsv1.DaemonSet, name string) []string {
	t.Helper()
	for _, c := range slices.Concat(ds.Spec.Template.Spec.Containers, ds.Spec.Template.Spec.InitContainers) {
		if c.Name == name {
			return runtimeArgv(corev1.Container{Args: c.Args, Env: c.Env}, nil)
		}
	}
	t.Fatalf("container %q not found in DaemonSet", name)
	return nil
}

func TestChartDefaultRendersReplacementStack(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("default chart missing MutatingWebhookConfiguration\n%s", out)
	}
	for _, label := range [][2]string{
		{"app.kubernetes.io/component", "cds"},
		{"app.kubernetes.io/name", "nri-image-policy"},
		{"app.kubernetes.io/name", "router"},
	} {
		if !renderedManifestHasLabel(t, out, label[0], label[1]) {
			t.Fatalf("default chart missing a manifest labelled %s: %s", label[0], label[1])
		}
	}
	renderedRouterNginxConfig(t, out).server(t).assertDirective(t, "server_name", "_")
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"get-cert",
		"--attestation-api-url=unix:///run/c8s/workload-claims/attestation-api.sock",
		"--san=c8s-router.c8s-router.svc",
		"--cert-path=/etc/c8s/certs/tls.crt",
		"--key-path=/etc/c8s/certs/tls.key",
		"--renew-interval=1h",
		"--continue-on-initial-error",
		// The CA watch keeps the served mesh CA tracking the live CDS CA: a
		// CDS restart regenerates the mesh CA in-memory, and without the watch
		// the /.well-known/mesh-ca.pem discovery endpoint serves the dead CA
		// until the next scheduled renewal.
		"--ca-watch-interval=1m",
	)
	if cert.RestartPolicy == nil || *cert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %v, want Always", cert.RestartPolicy)
	}
	// nginx is gated by the c8s-cert-wait init container, not an exec
	// startupProbe on the sidecar.
	if cert.StartupProbe != nil {
		t.Fatalf("c8s-cert must NOT carry a startupProbe; got %+v", cert.StartupProbe)
	}
	wait := routerGetCertContainer(t, out, "c8s-cert-wait")
	if got := strings.Join(wait.Command, " "); !strings.Contains(got, "probe-file") || !strings.Contains(got, "--wait") || !strings.Contains(got, "/etc/c8s/certs/tls.crt") {
		t.Fatalf("c8s-cert-wait command = %q, want `/c8s probe-file --wait --timeout=... /etc/c8s/certs/tls.crt`", got)
	}
	if got := cert.SecurityContext.RunAsUser; got == nil || *got != int64(workloadclaims.CredentialsUID) {
		t.Fatalf("c8s-cert runAsUser = %v, want the credentials role's uid %d", got, workloadclaims.CredentialsUID)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--get-cert-image=ghcr.io/confidential-dot-ai/c8s-operator:dev",
		"--get-cert-renew-interval=2h",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
		}
	}
}

func namedContainerPort(c corev1.Container, portName string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == portName {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

func allContainers(ds *appsv1.DaemonSet) []corev1.Container {
	out := make([]corev1.Container, 0, len(ds.Spec.Template.Spec.InitContainers)+len(ds.Spec.Template.Spec.Containers))
	out = append(out, ds.Spec.Template.Spec.InitContainers...)
	out = append(out, ds.Spec.Template.Spec.Containers...)
	return out
}

// iterateManifests calls fn for each non-nil YAML document in helmOut,
// using yaml.NewDecoder so a "---" inside a block scalar can't fool the
// split. The document is re-marshalled to YAML bytes so fn can pass it
// to sigsyaml.Unmarshal for typed decoding. fn returning true stops
// iteration.
func iterateManifests(t *testing.T, helmOut string, fn func(doc []byte) bool) {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(helmOut))
	for {
		var raw any
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("decode helm output: %v", err)
		}
		if raw == nil {
			continue
		}
		b, err := yaml.Marshal(raw)
		if err != nil {
			t.Fatalf("re-marshal manifest: %v", err)
		}
		if fn(b) {
			return
		}
	}
}

// renderedKinds counts each manifest kind across a helm template output.
func renderedKinds(t *testing.T, helmOut string) map[string]int {
	t.Helper()
	out := map[string]int{}
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err == nil && head.Kind != "" {
			out[head.Kind]++
		}
		return false
	})
	return out
}

// TestChartARMTLSKubeVersionPinned guards the chart's Kubernetes base
// against accidental relaxation. Two contracts pin it:
//   - native sidecars (SidecarContainers default-on from 1.29): with the
//     gate off, iptables-cleanup is invalid as a native sidecar, its preStop
//     cannot run, and the host leaks managed chains/ipsets across restarts;
//   - ValidatingAdmissionPolicy v1 (GA from 1.30): the chart ships default-on
//     UID, workload-integrity, and Restricted pod-security policies, so a
//     pre-1.30 apply fails mid-install on unknown kinds anyway — the
//     kubeVersion constraint makes helm fail early and clearly instead.
func TestChartARMTLSKubeVersionPinned(t *testing.T) {
	t.Parallel()
	path := filepath.Join(cloudChartDir, "Chart.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var chart struct {
		KubeVersion string `json:"kubeVersion"`
	}
	if err := sigsyaml.Unmarshal(raw, &chart); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	const want = ">=1.30.0-0"
	if chart.KubeVersion != want {
		t.Fatalf("c8s Chart.yaml kubeVersion = %q; want %q (native sidecars need k8s 1.29+, and the default-on ValidatingAdmissionPolicies need v1/GA from 1.30)", chart.KubeVersion, want)
	}
}

// nodeAffinityHasKey reports whether any required nodeAffinity matchExpression
// keys on the given label.
func nodeAffinityHasKey(ds appsv1.DaemonSet, key string) bool {
	aff := ds.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil ||
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == key {
				return true
			}
		}
	}
	return false
}

// The chart renders exactly one pull-mode installer DaemonSet, `-worker`, that
// targets every node — there is no CDS/worker partition. The old push archetype
// (a role=cds-pinned `-cds` installer) is gone; this guards against it coming
// back.
func TestChartNriInstallerRendersSinglePullDaemonSet(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-nri-image-policy-cds") {
		t.Error("no cds/push installer must render; only the pull-mode -worker DaemonSet exists")
	}
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if nodeAffinityHasKey(worker, "role") {
		t.Error("worker installer must not key on role; it targets every node")
	}
	if got, want := worker.Spec.Template.Labels["app.kubernetes.io/component"], "nri-installer-worker"; got != want {
		t.Errorf("worker installer pod component label = %q, want %q", got, want)
	}
}

// Both admission paths enforce host isolation and Pod security defaults.
// The ephemeral policy otherwise checks only debugger containers, leaving
// unrelated preserved container fields alone.
func TestChartHostSecurityPoliciesSplitPodAndEphemeral(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var podPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &podPolicy) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	var ephemeralPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces-ephemeral", &ephemeralPolicy) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces-ephemeral not rendered")
	}

	resources := func(p admissionregv1.ValidatingAdmissionPolicy) []string {
		var got []string
		for _, rule := range p.Spec.MatchConstraints.ResourceRules {
			got = append(got, rule.Resources...)
		}
		return got
	}
	if got := resources(podPolicy); !slices.Contains(got, "pods") {
		t.Errorf("pod security policy resources = %v, want pods", got)
	} else if slices.Contains(got, "pods/ephemeralcontainers") {
		t.Errorf("pod security policy must not match the separately validated ephemeral subresource: %v", got)
	}
	if got := resources(ephemeralPolicy); !slices.Contains(got, "pods/ephemeralcontainers") {
		t.Errorf("ephemeral security policy resources = %v, want pods/ephemeralcontainers", got)
	} else if slices.Contains(got, "pods") {
		t.Errorf("ephemeral security policy must not match pods: %v", got)
	}

	var hostPortExpr string
	for _, v := range podPolicy.Spec.Validations {
		if strings.Contains(v.Expression, "hostPort") {
			hostPortExpr = v.Expression
		}
	}
	if hostPortExpr == "" {
		t.Fatal("no hostPort validation in c8s-deny-host-namespaces: a tenant pod with hostPort 1019 impersonates the admission inventory")
	}
	for _, want := range []string{"spec.containers", "spec.initContainers", "spec.ephemeralContainers"} {
		if !strings.Contains(hostPortExpr, want) {
			t.Errorf("hostPort validation does not cover %s; expression=%q", want, hostPortExpr)
		}
	}
	for _, v := range ephemeralPolicy.Spec.Validations {
		// Host isolation stays a full-Pod invariant on subresource updates.
		if slices.ContainsFunc([]string{"hostNetwork", "hostPID", "hostIPC", "hostPort", "hostPath", "sysctls"}, func(field string) bool {
			return strings.Contains(v.Expression, field)
		}) {
			continue
		}
		if !strings.Contains(v.Expression, "object.spec.ephemeralContainers") {
			t.Errorf("ephemeral security expression does not inspect debuggers: %s", v.Expression)
		}
		for _, preservedField := range []string{"object.spec.containers", "object.spec.initContainers", "object.spec.volumes"} {
			if strings.Contains(v.Expression, preservedField) {
				t.Errorf("ephemeral security expression revalidates unrelated preserved field %s: %s", preservedField, v.Expression)
			}
		}
	}

	for _, policy := range []admissionregv1.ValidatingAdmissionPolicy{podPolicy, ephemeralPolicy} {
		selector := policy.Spec.MatchConstraints.NamespaceSelector
		if selector == nil {
			t.Errorf("%s has no namespaceSelector", policy.Name)
			continue
		}
		var excluded []string
		for _, requirement := range selector.MatchExpressions {
			if requirement.Key == "kubernetes.io/metadata.name" &&
				requirement.Operator == metav1.LabelSelectorOpNotIn {
				excluded = append(excluded, requirement.Values...)
			}
		}
		// The router role's namespace is exempt too: a front-door pod binds
		// the node's port and reads its inventory socket.
		for _, want := range []string{"c8s-system", workloadclaims.RouterNamespace, "kube-system", "local-path-storage"} {
			if !slices.Contains(excluded, want) {
				t.Errorf("%s namespace exclusions = %v, missing %q", policy.Name, excluded, want)
			}
		}
	}

	for _, name := range []string{"c8s-deny-host-namespaces", "c8s-deny-host-namespaces-ephemeral"} {
		var binding admissionregv1.ValidatingAdmissionPolicyBinding
		if !findDoc(t, out, "ValidatingAdmissionPolicyBinding", name, &binding) {
			t.Errorf("ValidatingAdmissionPolicyBinding %s not rendered", name)
			continue
		}
		if binding.Spec.PolicyName != name {
			t.Errorf("%s binding policyName = %q, want %q", name, binding.Spec.PolicyName, name)
		}
		if len(binding.Spec.ValidationActions) != 1 ||
			binding.Spec.ValidationActions[0] != admissionregv1.Deny {
			t.Errorf("%s binding actions = %v, want [Deny]", name, binding.Spec.ValidationActions)
		}
	}
}

// The claims socket directory reaches CW pods as an NRI mount, not a pod-spec
// volume, so the deny-host-namespaces VAP denies hostPath outright: any
// carve-out would let a tenant reach the node filesystem.
func TestChartHostNamespacePolicyDeniesAllHostPath(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &vap) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	var hostPathExprs []string
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, "hostPath") {
			hostPathExprs = append(hostPathExprs, v.Expression)
		}
	}
	if len(hostPathExprs) == 0 {
		t.Fatal("no hostPath validation in c8s-deny-host-namespaces")
	}
	// Absence, not presence: a leftover carve-out would pass a "some hostPath
	// deny renders" check.
	for _, v := range vap.Spec.Validations {
		for _, stale := range []string{"/run/nri-image-policy", "readOnly", "hostPath.type"} {
			if strings.Contains(v.Expression, stale) {
				t.Errorf("validation still carves out the claims dir (%q); expression=%q", stale, v.Expression)
			}
		}
	}
}

// findContainer mirrors findEnv in internal/webhook/pod_mutator_test.go:
// return (value, ok) so callers decide how to report the miss.
func findContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range containers {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

// routerGetCertContainer returns the named router get-cert init container
// (c8s-cert), failing if absent.
func routerGetCertContainer(t *testing.T, manifest, name string) corev1.Container {
	t.Helper()
	init := renderedDeploymentInitContainers(t, manifest, "c8s-router")
	c, ok := findContainer(init, name)
	if !ok {
		t.Fatalf("router init container %q missing; have %v", name, containerNames(init))
	}
	return c
}

// assertAcmeArgsParse fails unless the sidecar's own command accepts the
// rendered argv: an unknown flag crash-loops the container, and the front
// door never starts. The sidecar fixes the credential's two directories
// itself (internal/cmds/acme), so the chart names neither.
func assertAcmeArgsParse(t *testing.T, args []string) {
	t.Helper()
	cmd := acmecmd.NewCmd()
	cmd.RunE = func(*cobra.Command, []string) error {
		return nil
	}
	cmd.SetArgs(args[1:])
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Errorf("the acme sidecar refuses its rendered args %v: %v", args, err)
	}
}

// assertContainerArgs fails unless every wanted arg is present on the container.
func assertContainerArgs(t *testing.T, c corev1.Container, want ...string) {
	t.Helper()
	for _, w := range want {
		assertContainerHasArg(t, c.Name, c.Args, w)
	}
}

// TestChartRejectsOperatorKeysPath pins the path-vs-content guard: a
// cds.operatorKeys value that is a filesystem path (or any non-PEM string)
// must fail the render with an instructive message, not ship a ConfigMap CDS
// will refuse at startup.
func TestChartRejectsOperatorKeysPath(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "cds.operatorKeys=/home/user/public.pem")
	if err == nil {
		t.Fatalf("helm template succeeded, want operatorKeys content-guard failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_operator_keys_content" {
		t.Fatalf("validation kind = %q, want cds_operator_keys_content\n%s", kind, out)
	}
}

func TestChartRendersOperatorKeysPEM(t *testing.T) {
	t.Parallel()
	pemText := "-----BEGIN PUBLIC KEY-----\nMFkwfakefakefake\n-----END PUBLIC KEY-----\n"
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	out, err := helmTemplate(t, "--set-file", "cds.operatorKeys="+path)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-operator-keys")
	if got := cm.Data["keys.pem"]; got != pemText {
		t.Fatalf("operator-keys ConfigMap keys.pem = %q, want the PEM content %q", got, pemText)
	}
}

func TestChartRunsTheStatusMirror(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerHasArg(t, "operator", renderedOperatorArgs(t, out), "--status-mirror-enabled=true")
}

func TestChartWebhookInjectsWorkloadsAndExcludesSystemNamespaces(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// router now self-renders get-cert, so the platform-pods rule that only
	// existed to inject it is gone: one workload webhook remains.
	names := renderedMutatingWebhookNames(t, out)
	if !slices.Equal(names, []string{"pods.c8s.confidential.ai"}) {
		t.Fatalf("webhook names = %v, want only the workload rule", names)
	}

	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excludedNamespaces := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	// The mesh policy designates the router role's namespace, whose pods hold
	// platform-role containers the chart renders itself.
	for _, want := range []string{"c8s-system", workloadclaims.RouterNamespace, "kube-system", "kube-public", "kube-node-lease", "local-path-storage"} {
		if !slices.Contains(excludedNamespaces, want) {
			t.Fatalf("general webhook namespaceSelector missing excluded namespace %q: %v", want, excludedNamespaces)
		}
	}
}

// The enforcer gives the pods of one fixed namespace the router's listener and
// egress rules, so the chart owns that namespace under the name the enforcer
// and the CLI both compile in.
func TestChartOwnsTheRouterNamespaceTheEnforcerCompilesIn(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var namespace corev1.Namespace
	if !findDoc(t, out, "Namespace", workloadclaims.RouterNamespace, &namespace) {
		t.Fatalf("rendered manifest missing Namespace %q\n%s", workloadclaims.RouterNamespace, out)
	}
	for _, mode := range []string{"enforce", "warn", "audit"} {
		if got := namespace.Labels["pod-security.kubernetes.io/"+mode]; got != "privileged" {
			t.Errorf("Namespace %s %s label = %q, want privileged: a front-door pod mounts the node's sockets", workloadclaims.RouterNamespace, mode, got)
		}
	}
}

func TestChartWebhookExtraExcludedFlowsToWebhookAndSweep(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "controlPlane.webhook.extraExcluded={tenant-a,tenant-b}")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// extraExcluded must reach both the webhook namespaceSelector (CREATE-time
	// exclusion) and the operator's reinject sweep (--exclude-namespaces), or
	// the two disagree on which namespaces are out of scope.
	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excluded := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	args := renderedOperatorArgs(t, out)
	for _, ns := range []string{"tenant-a", "tenant-b"} {
		if !slices.Contains(excluded, ns) {
			t.Fatalf("webhook namespaceSelector missing extraExcluded %q: %v", ns, excluded)
		}
		if !slices.Contains(args, "--exclude-namespaces="+ns) {
			t.Fatalf("operator args missing --exclude-namespaces=%s\n%v", ns, args)
		}
	}
}

// The AKS stock files opt both webhook configurations out of AKS's admissions
// enforcer, which rewrites their namespaceSelector; the GKE file leaves them
// unannotated.
func TestChartWebhookAnnotationsReachBothConfigurations(t *testing.T) {
	t.Parallel()
	for platform, want := range map[string]string{
		"aks-snp": "true",
		"aks-tdx": "true",
		"gke-snp": "",
	} {
		t.Run(platform, func(t *testing.T) {
			out, err := helmTemplatePlatform(t, platform)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var mutating admissionregv1.MutatingWebhookConfiguration
			var validating admissionregv1.ValidatingWebhookConfiguration
			if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &mutating) ||
				!findDoc(t, out, "ValidatingWebhookConfiguration", "c8s-pod-validator", &validating) {
				t.Fatalf("missing admission webhooks\n%s", out)
			}
			for _, annotations := range []map[string]string{mutating.Annotations, validating.Annotations} {
				if annotations["admissions.enforcer/disabled"] != want {
					t.Errorf("annotations = %v, want admissions.enforcer/disabled=%q", annotations, want)
				}
			}
		})
	}
}

// The CRD the control-plane subchart carries installs with the cloud release.
func TestChartReleaseCarriesTheWorkloadCRD(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--include-crds")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var crd docMeta
	if !findDoc(t, out, "CustomResourceDefinition", "confidentialworkloads.confidential.ai", &crd) {
		t.Fatalf("release carries no ConfidentialWorkload CRD\n%s", out)
	}
}

// TestChartLeavesTheInjectedCDSEndpointToTheNode proves the chart hands the
// injected credential clients no CDS URL: the node's plugin does, from the CDS
// node port rendered here and its own address, which is the one endpoint the
// pod ruleset admits.
func TestChartLeavesTheInjectedCDSEndpointToTheNode(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerNoArgPrefix(t, "operator", renderedOperatorArgs(t, out), "--cds-url=")
	// The node reads the endpoint from the file the installer puts beside its
	// config and hands it to every injected client; no component names it.
	if got := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Pull.CDSAddressFile; got != "/etc/nri/conf.d/cds-address" {
		t.Fatalf("allowlist.pull.cds_address_file = %q, want the file beside the boot config", got)
	}
	iterateManifests(t, out, func(doc []byte) bool {
		var meta docMeta
		if err := sigsyaml.Unmarshal(doc, &meta); err != nil {
			t.Fatalf("decode rendered document: %v", err)
		}
		if strings.Contains(string(doc), baseCDSAddress) && meta.Metadata.Name != "c8s-measurements" {
			t.Fatalf("%s %q names the CDS address; only the ConfigMap the installer mounts may\n%s", meta.Kind, meta.Metadata.Name, doc)
		}
		return false
	})
}

func TestChartNRIImagePolicyUsesPullMode(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	workerCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	// The CDS reaches the plugin as two paths beside its config: no argument
	// of the installer names the address or the pin it is served by.
	if got, want := workerCfg.Allowlist.Pull.CDSAddressFile, "/etc/nri/conf.d/cds-address"; got != want {
		t.Fatalf("worker CDS address file = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.CDSMeasurementsConfig, "/etc/nri/conf.d/cds.json"; got != want {
		t.Fatalf("worker CDS pin = %q, want %q", got, want)
	}
	if workerCfg.Allowlist.Pull.URL != "" {
		t.Fatalf("worker pull URL = %q, want none: the address file names the CDS", workerCfg.Allowlist.Pull.URL)
	}
	if got, want := workerCfg.Allowlist.Pull.Interval, "5s"; got != want {
		t.Fatalf("worker pull interval = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.AttestationApiURL, "unix:///run/nri-image-policy/attestation-api.sock"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
	// Pull-only: the boot config never carries a push block.
	if workerCfg.Allowlist.Push.PersistPath != "" {
		t.Fatalf("worker boot config has push persist path %q, want empty", workerCfg.Allowlist.Push.PersistPath)
	}
}

// The default attestation-api shape publishes nothing routable: no Service at
// all, the API bound to pod loopback, a default-deny NetworkPolicy on the
// DaemonSet pods, and the attest-proxy sidecar serving the on-node Unix
// socket every consumer dials.
func TestChartAttestationApiDefaultsToNodeLocalSocket(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") {
		t.Fatalf("default render must not create an attestation-api Service (evidence generation is node-local only)\n%s", out)
	}
	assertNoLegacyAttestationStrings(t, out)

	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "c8s-attestation-api", &np) {
		t.Fatalf("default render missing the attestation-api default-deny NetworkPolicy\n%s", out)
	}
	if len(np.Spec.Ingress) != 0 {
		t.Fatalf("default NetworkPolicy must deny all ingress; got rules %+v", np.Spec.Ingress)
	}
	if !slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
		t.Fatalf("NetworkPolicy policyTypes = %v, want Ingress", np.Spec.PolicyTypes)
	}

	if renderedManifestHasNamedKind(t, out, "Secret", "c8s-attestation-api") {
		t.Fatalf("attestation-api config must render as a ConfigMap, not a Secret\n%s", out)
	}
	cfg := renderedConfigMap(t, out, "c8s-attestation-api").Data["config.toml"]
	if !strings.Contains(cfg, `bind = "127.0.0.1:8400"`) {
		t.Fatalf("default config must bind pod loopback; got:\n%s", cfg)
	}
	if strings.Contains(cfg, "[auth]") {
		t.Fatalf("config must not render [auth] (nothing routable to protect); got:\n%s", cfg)
	}

	ds := renderedDaemonSet(t, out, "c8s-attestation-api")
	proxy := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attest-proxy")
	assertContainerArgs(t, proxy,
		"attest-proxy",
		"--socket=/run/nri-image-policy/attestation-api.sock",
		"--upstream=http://127.0.0.1:8400",
	)
	assertContainerNoArgPrefix(t, "attest-proxy", proxy.Args, "--api-key-file")
	// The proxy publishes into the socket-dir hostPath, and both it and the
	// API read their config from the ConfigMap — dropping either renders
	// fine and only fails at runtime.
	assertPodVolume(t, &ds.Spec.Template.Spec, "socket-dir", func(v corev1.Volume) bool {
		return v.HostPath != nil && v.HostPath.Path == "/run/nri-image-policy"
	})
	assertPodVolume(t, &ds.Spec.Template.Spec, "config", func(v corev1.Volume) bool {
		return projectedConfigMap(v) == "c8s-attestation-api"
	})
	assertContainerMount(t, proxy, "socket-dir", "/run/nri-image-policy")
	// HTTP (a locked node image denies every runc exec it was not granted), against
	// the proxy's own health listener: the API's loopback bind is not
	// kubelet-dialable, and this is the evidence path's only liveness signal.
	for name, probe := range map[string]*corev1.Probe{"readiness": proxy.ReadinessProbe, "liveness": proxy.LivenessProbe} {
		if probe == nil || probe.HTTPGet == nil {
			t.Fatalf("attest-proxy must carry an HTTP %s probe; got %+v", name, probe)
		}
		if probe.HTTPGet.Path != "/healthz" || probe.HTTPGet.Port.StrVal != "health" {
			t.Fatalf("attest-proxy %s probe = %+v, want GET /healthz on the health port", name, probe.HTTPGet)
		}
		// Kubelet's 1s default probe timeout would flap the healthcheck's 3s
		// internal budget.
		if probe.TimeoutSeconds != 5 {
			t.Fatalf("attest-proxy %s probe timeoutSeconds = %d, want 5", name, probe.TimeoutSeconds)
		}
	}
	if _, ok := findContainerPort(proxy, "health"); !ok {
		t.Fatalf("attest-proxy must name its health port; got %+v", proxy.Ports)
	}
	// uid 0 owns the socket (clients reject a foreign owner) and gid 65532 is
	// the socket's group — the chgrp works by membership, all caps dropped.
	sc := proxy.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 0 || sc.RunAsGroup == nil || *sc.RunAsGroup != 65532 {
		t.Fatalf("attest-proxy must run as uid 0 / gid 65532 (socket owner and group); got %+v", sc)
	}
	if sc.Capabilities == nil || !slices.Contains(sc.Capabilities.Drop, corev1.Capability("ALL")) {
		t.Fatalf("attest-proxy must drop all capabilities; got %+v", sc.Capabilities)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("attest-proxy must mount its root filesystem read-only; got %+v", sc.ReadOnlyRootFilesystem)
	}
	// An httpGet probe would never pass against the loopback bind, so the
	// proxy's exec probe is the only health signal.
	api := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
	if api.ReadinessProbe != nil || api.LivenessProbe != nil {
		t.Fatalf("attestation-api container must not carry kubelet probes against its loopback bind; got %+v / %+v", api.ReadinessProbe, api.LivenessProbe)
	}
}

// assertNoLegacyAttestationStrings keeps the routable shapes the hardening
// removed out of every render: the old NodePort, a wildcard bind, and the
// deleted Service's DNS name.
func assertNoLegacyAttestationStrings(t *testing.T, manifest string) {
	t.Helper()
	for _, legacy := range []string{"30840", "0.0.0.0", "c8s-attestation-api.c8s-system.svc"} {
		if strings.Contains(manifest, legacy) {
			t.Fatalf("render must not contain legacy routable-attestation string %q", legacy)
		}
	}
}

func assertPodVolume(t *testing.T, spec *corev1.PodSpec, name string, ok func(corev1.Volume) bool) {
	t.Helper()
	for _, v := range spec.Volumes {
		if v.Name == name {
			if !ok(v) {
				t.Fatalf("volume %q has the wrong source: %+v", name, v.VolumeSource)
			}
			return
		}
	}
	t.Fatalf("pod spec missing volume %q; volumes %+v", name, spec.Volumes)
}

func assertContainerMount(t *testing.T, c corev1.Container, name, mountPath string) {
	t.Helper()
	for _, m := range c.VolumeMounts {
		if m.Name == name && m.MountPath == mountPath {
			return
		}
	}
	t.Fatalf("container %s missing mount of volume %q at %q; mounts %+v", c.Name, name, mountPath, c.VolumeMounts)
}

// The host NRI plugin is a host process: it reaches the attestation-api over
// the node-local Unix socket, never the pod network.
func TestChartAttestationApiSocketWiresNRI(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := cfg.Allowlist.Pull.AttestationApiURL, "unix:///run/nri-image-policy/attestation-api.sock"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
}

// parseValidationErrorKind extracts kind=<id> from helm's stderr when the
// chart's `fail` message starts with `VALIDATION_ERROR kind=<id>:`. Returns
// empty string if the marker is absent.
func parseValidationErrorKind(helmOutput string) string {
	re := regexp.MustCompile(`VALIDATION_ERROR kind=([a-z0-9_]+)`)
	m := re.FindStringSubmatch(helmOutput)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func assertContainerHasArg(t *testing.T, container string, args []string, want string) {
	t.Helper()
	if !slices.Contains(args, want) {
		t.Fatalf("%s container missing arg %q\nargs: %v", container, want, args)
	}
}

func assertContainerNoArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			t.Fatalf("%s container has unexpected arg with prefix %q: %q\nargs: %v", container, prefix, arg, args)
		}
	}
}

func assertContainerHasArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return
		}
	}
	t.Fatalf("%s container missing arg with prefix %q\nargs: %v", container, prefix, args)
}

// renderedManifestHasLabel reports whether any rendered doc carries the label,
// on its own metadata or its pod template.
func renderedManifestHasLabel(t *testing.T, manifest, key, value string) bool {
	t.Helper()
	found := false
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Metadata struct {
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		if obj.Metadata.Labels[key] == value || obj.Spec.Template.Metadata.Labels[key] == value {
			found = true
			return true
		}
		return false
	})
	return found
}

// renderedWorkload is a pod-bearing manifest (Deployment, DaemonSet,
// StatefulSet, Job) with its decoded pod spec.
type renderedWorkload struct {
	kind, name string
	spec       corev1.PodSpec
}

func renderedPodSpecs(t *testing.T, manifest string) []renderedWorkload {
	t.Helper()
	var out []renderedWorkload
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "StatefulSet", "Job":
			out = append(out, renderedWorkload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	return out
}

// findKey returns a dotted path to the first occurrence of key anywhere in a
// decoded YAML tree, or "" if absent.
func findKey(node any, key string) string {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if k == key {
				return k
			}
			if p := findKey(child, key); p != "" {
				return k + "." + p
			}
		}
	case []any:
		for i, child := range v {
			if p := findKey(child, key); p != "" {
				return fmt.Sprintf("[%d].%s", i, p)
			}
		}
	}
	return ""
}

// TestChartAttestationApiPrivileged proves every platform renders privileged:
// true. A hostPath device mount does not add a device-cgroup rule, so open() on
// the TEE device (/dev/sev-guest, /dev/tpm0) is EPERM from an unprivileged
// container regardless of SYS_RAWIO (cgroup v2 eBPF device controller). TODO:
// revert to least-privilege once SNP attest goes through the TSM configfs
// report interface.
func TestChartAttestationApiPrivileged(t *testing.T) {
	t.Parallel()
	for _, platform := range cloudPlatforms {
		t.Run(platform, func(t *testing.T) {
			out, err := helmTemplatePlatform(t, platform)
			if err != nil {
				t.Fatalf("helm template (%s): %v\n%s", platform, err, out)
			}
			sc := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api").SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				t.Errorf("%s must be privileged for device access; got %+v", platform, sc)
			}
		})
	}
}

// TestChartOperatorStartupProbeHoldsOffLiveness pins the operator's
// startupProbe (#208). setupManager runs CRD discovery and the webhook PKI
// bootstrap before /healthz is served, so without it liveness (~90s at the
// defaults) can kill the operator mid-startup and, via failurePolicy=Fail,
// block every pod admission while it restarts.
func TestChartOperatorStartupProbeHoldsOffLiveness(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	op := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	sp := op.StartupProbe
	if sp == nil || sp.HTTPGet == nil {
		t.Fatalf("operator must carry an HTTP startupProbe; got %+v", sp)
	}
	if sp.HTTPGet.Path != "/healthz" || sp.HTTPGet.Port.String() != "health" {
		t.Errorf("operator startupProbe = GET %s on %s, want /healthz on the health port", sp.HTTPGet.Path, sp.HTTPGet.Port.String())
	}
	if window := sp.FailureThreshold * sp.PeriodSeconds; window < 300 {
		t.Errorf("operator startupProbe window = %ds, want >= 300s", window)
	}
	if op.LivenessProbe == nil {
		t.Fatal("operator lost its livenessProbe")
	}
}

// TestChartOperatorHasPodNameEnv pins the downward-API POD_NAME the operator
// puts in its webhook CA's CommonName: the CA's identity in the caBundle,
// which must be unique among live pods (the hostname is truncated at 63).
func TestChartOperatorHasPodNameEnv(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	op := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	for _, e := range op.Env {
		if e.Name == "POD_NAME" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "metadata.name" {
			return
		}
	}
	t.Fatalf("operator missing POD_NAME from metadata.name; env %+v", op.Env)
}

// TestChartUsesTheAttestationSocket proves every platform dials the on-node
// Unix socket and renders no HOST_IP env anywhere. The consumers that must
// carry both the socket URL and the socket-directory mount are asserted per
// platform.
func TestChartUsesTheAttestationSocket(t *testing.T) {
	t.Parallel()
	const socketURL = "--attestation-api-url=unix:///run/nri-image-policy/attestation-api.sock"
	for _, mode := range cloudPlatforms {
		t.Run(mode, func(t *testing.T) {
			out, err := helmTemplatePlatform(t, mode)
			if err != nil {
				t.Fatalf("helm template (%s): %v\n%s", mode, err, out)
			}
			// The acceptance criteria are per-platform: no routable path to
			// evidence generation, and the default-deny NetworkPolicy on the
			// DaemonSet.
			if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") {
				t.Fatalf("%s renders no attestation-api Service (evidence generation is node-local only)\n%s", mode, out)
			}
			assertNoLegacyAttestationStrings(t, out)
			var np networkingv1.NetworkPolicy
			if !findDoc(t, out, "NetworkPolicy", "c8s-attestation-api", &np) || len(np.Spec.Ingress) != 0 {
				t.Fatalf("%s renders the attestation-api default-deny NetworkPolicy; got %+v", mode, np.Spec.Ingress)
			}
			// Every consumer of the socket URL must also mount the socket
			// directory (read-only), at the host path so the URL is verbatim.
			assertHasSocketMount := func(c corev1.Container) {
				t.Helper()
				for _, m := range c.VolumeMounts {
					if m.Name == "attestation-api-socket" && m.MountPath == "/run/nri-image-policy" && m.ReadOnly {
						return
					}
				}
				t.Errorf("container %s carries the socket URL but no attestation-api-socket mount; mounts %+v", c.Name, c.VolumeMounts)
			}
			attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
			assertContainerArgs(t, attest, socketURL)
			assertHasSocketMount(attest)
			// The router's credentials-role containers reach the same socket
			// through the inventory directory at the compiled path their
			// clients accept (cmdsutil.RequireNodeVerifier).
			assertHasInventoryMount := func(c corev1.Container) {
				t.Helper()
				for _, m := range c.VolumeMounts {
					if m.Name == "workload-claims" && m.MountPath == "/run/c8s/workload-claims" && m.ReadOnly {
						return
					}
				}
				t.Errorf("container %s names the node's verifier but no inventory mount; mounts %+v", c.Name, c.VolumeMounts)
			}
			assertHasInventoryMount(routerGetCertContainer(t, out, "c8s-cert"))
			assertHasInventoryMount(renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy"))
			for _, w := range renderedPodSpecs(t, out) {
				for _, c := range append(append([]corev1.Container{}, w.spec.InitContainers...), w.spec.Containers...) {
					for _, e := range c.Env {
						if e.Name == "HOST_IP" {
							t.Errorf("%s must not render any HOST_IP env; %s %s container %s carries it", mode, w.kind, w.name, c.Name)
						}
					}
				}
			}
		})
	}
}

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "imagePullSecrets[0].name=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var sa corev1.ServiceAccount
	if !findDoc(t, out, "ServiceAccount", "c8s-operator", &sa) {
		t.Fatalf("render missing ServiceAccount c8s-operator\n%s", out)
	}
	if !hasPullSecret(sa.ImagePullSecrets, "ghcr-secret") {
		t.Fatalf("operator ServiceAccount missing chart-wide pull secret ghcr-secret: %v", sa.ImagePullSecrets)
	}
	// A privileged attestation-api with a read-only root filesystem.
	sc := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api").SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged; got %+v", sc)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("attestation-api must set readOnlyRootFilesystem: true; got %+v", sc)
	}
}

// TestChartGlobalImagePullSecrets proves the chart-wide imagePullSecrets feeds
// every component.
func TestChartGlobalImagePullSecrets(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		"--set", "imagePullSecrets[0].name=ghcr-pull",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The global reaches a non-overriding component (the plugin installer).
	installer := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if !hasPullSecret(installer.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") {
		t.Errorf("nri-image-policy installer missing global pull secret: %v", installer.Spec.Template.Spec.ImagePullSecrets)
	}
	lb := renderedDeployment(t, out, "c8s-router")
	if !hasPullSecret(lb.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") {
		t.Errorf("router missing global pull secret: %v", lb.Spec.Template.Spec.ImagePullSecrets)
	}
}

func hasPullSecret(refs []corev1.LocalObjectReference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}

func TestChartRendersRouterTLSAndDiscovery(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	server := cfg.server(t)
	// The cloud's tls.conf names the mesh leaf, which cds-attest's pinned
	// --front-door-mode=cds attests.
	server.assertDirective(t, "include", "/mnt/c8s-data/nginx/tls.conf")
	files := renderedConfigMap(t, out, "c8s-router-nginx").Data
	if got := files["tls.conf"]; got != "include /mnt/c8s-data/nginx/tls-cds.conf;\n" {
		t.Errorf("tls.conf = %q, want the mesh leaf's snippet", got)
	}
	tls := parseNginxConfig(t, "server {\n"+files["tls-cds.conf"]+"\n}").servers[0]
	tls.assertDirective(t, "ssl_certificate", "/etc/c8s/certs/tls.crt$per_handshake")
	tls.assertDirective(t, "ssl_certificate_key", "/etc/c8s/certs/tls.key$per_handshake")
	if _, ok := files["front-door-mode"]; ok {
		t.Error("the cloud ConfigMap carries front-door-mode, which cds-attest takes as pinned argv")
	}
	ciphers := server.directives["ssl_ciphers"]
	if len(ciphers) != 1 || len(ciphers[0]) != 1 ||
		!slices.Contains(strings.Split(ciphers[0][0], ":"), "ECDHE-RSA-AES128-GCM-SHA256") {
		t.Fatalf("ssl_ciphers missing ECDHE-RSA-AES128-GCM-SHA256; got %v", ciphers)
	}
	cfg.location(t, "exact", "/v1/discovery").assertDirective(t, "alias", "/discovery/discovery.json")
	cfg.location(t, "exact", "/.well-known/cds-cert.pem").assertDirective(t, "alias", "/etc/c8s/certs/tls.crt")
	cfg.location(t, "exact", "/.well-known/mesh-ca.pem").assertDirective(t, "alias", "/etc/c8s/certs/ca.crt")
	// Locations that hold no attest-lb binding close the connection after the
	// response, so a binding cannot lapse under a connection they keep open.
	// Discovery and the allowlist keep a young connection open, so a client can
	// read the allowlist on the connection whose leaf it attested.
	for _, path := range []string{"/.well-known/cds-cert.pem", "/.well-known/mesh-ca.pem", "/readyz", "/healthz"} {
		cfg.location(t, "exact", path).assertDirective(t, "keepalive_timeout", "0")
	}
	for _, path := range []string{"/v1/discovery", "/allowlist"} {
		cfg.location(t, "exact", path).assertDirective(t, "keepalive_time", "1m")
	}
	cfg.location(t, "prefix", "/allowlist/").assertDirective(t, "keepalive_time", "1m")
	cfg.location(t, "named", "@tunnel_busy").assertDirective(t, "keepalive_timeout", "0")
	cfg.location(t, "exact", "/readyz").assertDirective(t, "proxy_set_header", "X-C8s-Connection", "$nginx_start.$pid.$connection")
	// Application requests go to the routing listener, which dials backends
	// itself.
	app := cfg.location(t, "prefix", "/")
	app.assertDirective(t, "proxy_pass", "http://127.0.0.1:8802")
	// $host drops a trailing dot, which M1 keeps.
	app.assertDirective(t, "proxy_set_header", "Host", "$http_host")
	cfg.assertNoDirectivePrefix(t, "proxy_ssl_")

	spec := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	if _, ok := podVolume(spec, "c8s-certs"); !ok {
		t.Fatalf("router missing c8s-certs volume; volumes=%v", spec.Volumes)
	}
	if _, ok := podVolume(spec, "discovery"); !ok {
		t.Fatalf("router missing discovery volume; volumes=%v", spec.Volumes)
	}
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=cds",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
	)
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, "--front-door-mode=cds")
	// nginx is its own entrypoint's child, so the pod shares no process
	// namespace (router_serve_test.go).
	deployment := renderedDeployment(t, out, "c8s-router")
	if got := deployment.Spec.Template.Spec.ShareProcessNamespace; got != nil && *got {
		t.Fatalf("router shareProcessNamespace = %v, want it unset", *got)
	}
}

// The locked node image's measured runtime wrapper denies every runc exec it was not granted,
// and CRI routes exec probes and lifecycle exec hooks through exactly that
// call (internal/cmds/c8srunc). A C8s-owned exec probe would therefore never
// pass on such a node — the component would sit in CrashLoop or never go
// Ready — so the chart must render none.
func TestChartRendersNoExecProbes(t *testing.T) {
	t.Parallel()
	// Every rendering that adds pod templates of its own: the default stack,
	// the worker router's acme front door, and the volumed opt-in.
	renderings := map[string]chartRender{
		"default": {render: helmTemplate},
		"volumed": {render: helmTemplate, args: []string{"--set", "volumed.enabled=true", "--set", "volumed.image.tag=dev"}},
		"worker":  {render: helmTemplateWorker},
	}
	for name, rendering := range renderings {
		t.Run(name, func(t *testing.T) {
			out, err := rendering.render(t, rendering.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			for _, found := range execProbesByTemplate(t, out) {
				t.Errorf("%s renders %s, which a locked node image denies; use an HTTP, TCP or gRPC probe, or SIGTERM handling", found.source, found.what)
			}
		})
	}
}

// execProbe is one exec probe or lifecycle exec hook, with the chart template
// that rendered it.
type execProbe struct {
	source string
	what   string
}

// execProbesByTemplate walks every rendered manifest for exec probes and
// lifecycle exec hooks. The walk is structural rather than typed so it covers
// every workload kind, including pod templates nested in a CronJob.
func execProbesByTemplate(t *testing.T, helmOut string) []execProbe {
	t.Helper()
	var found []execProbe
	for _, doc := range strings.Split(helmOut, "\n---\n") {
		source := manifestSource(doc)
		var obj any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("decode manifest from %s: %v", source, err)
		}
		for _, what := range findExecHooks(obj) {
			found = append(found, execProbe{source: source, what: what})
		}
	}
	return found
}

var manifestSourceRE = regexp.MustCompile(`(?m)^# Source: (\S+)`)

func manifestSource(doc string) string {
	if m := manifestSourceRE.FindStringSubmatch(doc); m != nil {
		return m[1]
	}
	return "<unknown template>"
}

// findExecHooks returns a description of every probe or lifecycle handler in
// the decoded manifest that spawns a process.
func findExecHooks(node any) []string {
	var found []string
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			switch key {
			case "livenessProbe", "readinessProbe", "startupProbe":
				if handler, ok := child.(map[string]any); ok && handler["exec"] != nil {
					found = append(found, key+" with an exec handler")
				}
			case "lifecycle":
				if handlers, ok := child.(map[string]any); ok {
					for _, hook := range []string{"postStart", "preStop"} {
						if h, ok := handlers[hook].(map[string]any); ok && h["exec"] != nil {
							found = append(found, "a lifecycle "+hook+" exec hook")
						}
					}
				}
			}
			found = append(found, findExecHooks(child)...)
		}
	case []any:
		for _, child := range v {
			found = append(found, findExecHooks(child)...)
		}
	}
	return found
}

// TestWorkerChartRouterACMESidecar pins the worker router's acme front door: the
// `c8s acme` native sidecar issues the leaf into a Memory emptyDir it alone
// writes, nginx and cds-attest read it, and the :80 server proxies HTTP-01 to
// the sidecar's loopback challenge port and 301s everything else.
func TestWorkerChartRouterACMESidecar(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	acme := routerGetCertContainer(t, out, "acme")
	if len(acme.Args) == 0 || acme.Args[0] != "acme" {
		t.Fatalf("acme sidecar args must start with the acme subcommand, got %v", acme.Args)
	}
	assertContainerArgs(t, acme, "--challenge-port=8402")
	assertAcmeArgsParse(t, acme.Args)
	if acme.RestartPolicy == nil || *acme.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("acme must be a native sidecar (restartPolicy Always), got %v", acme.RestartPolicy)
	}
	// It proves control of the public names, so it holds the acme role: the
	// one identity of this pod the node lets out of the cluster in the clear.
	// nginx, which forwards application requests, holds another.
	if got := acme.SecurityContext.RunAsUser; got == nil || *got != int64(workloadclaims.AcmeUID) {
		t.Fatalf("acme runAsUser = %v, want the acme role's uid %d", got, workloadclaims.AcmeUID)
	}
	for _, want := range []struct {
		volume string
		path   string
	}{
		{
			volume: "acme-tls",
			path:   "/etc/c8s-acme-tls",
		},
		{
			volume: "acme-key",
			path:   "/etc/c8s-acme-key",
		},
	} {
		if m, ok := containerVolumeMount(acme, want.volume); !ok || m.MountPath != want.path || m.ReadOnly {
			t.Fatalf("acme must mount %s read-write at %s, got (%+v, %v)", want.volume, want.path, m, ok)
		}
	}

	spec := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	for _, name := range []string{"acme-tls", "acme-key"} {
		vol, ok := podVolume(spec, name)
		if !ok || vol.EmptyDir == nil || vol.EmptyDir.Medium != corev1.StorageMediumMemory {
			t.Fatalf("%s must be a Memory-medium emptyDir, got %+v", name, vol)
		}
	}

	// The front door serves the pair, so it is the one container holding
	// both; everything else that reads this credential takes the chain only.
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	for _, name := range []string{"acme-tls", "acme-key"} {
		if m, ok := containerVolumeMount(nginx, name); !ok || !m.ReadOnly {
			t.Fatalf("nginx must mount %s read-only, got (%+v, %v)", name, m, ok)
		}
	}

	// The identity that leaves the cluster in the clear is the sidecar that
	// proves the public names, never the nginx that forwards application
	// requests.
	if got := nginx.SecurityContext.RunAsUser; got == nil || *got == int64(workloadclaims.AcmeUID) {
		t.Errorf("nginx runAsUser = %v: the identity that forwards application requests holds no egress exception", got)
	}
	httpPort, ok := findContainerPort(nginx, "http")
	if !ok || httpPort.ContainerPort != 8080 || httpPort.HostPort != 80 {
		t.Fatalf("nginx http port = (%+v, %v), want containerPort 8080 hostPort 80", httpPort, ok)
	}

	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, "--acme-serving-cert-file=/etc/c8s-acme-tls/cert.pem")
	if m, ok := containerVolumeMount(attest, "acme-tls"); !ok || !m.ReadOnly {
		t.Fatalf("cds-attest must mount acme-tls read-only, got (%+v, %v)", m, ok)
	}
	// It binds the leaf the front door presents; the key is not its to read,
	// and it runs as the same identity, so only the mount keeps it out.
	if m, ok := containerVolumeMount(attest, "acme-key"); ok {
		t.Fatalf("cds-attest mounts the front door's serving key at %s", m.MountPath)
	}

	cfg := parseNginxConfig(t, libRouterNginxFiles(t)["nginx.conf"])
	if len(cfg.servers) != 2 {
		t.Fatalf("nginx config has %d server blocks, want the :443 and :80 pair", len(cfg.servers))
	}
	http := cfg.httpServer(t)
	http.assertDirective(t, "listen", "8080")
	http.location(t, "prefix", "/.well-known/acme-challenge/").
		assertDirective(t, "proxy_pass", "http://127.0.0.1:8402")
	// Everything but the challenge upgrades.
	http.location(t, "prefix", "/").assertDirective(t, "return", "301", "https://$host$request_uri")

	// The Service and the ingress policy must open the :80 path the
	// validators arrive on.
	svc := renderedService(t, out, "c8s-router")
	var httpSvcPort *corev1.ServicePort
	for i, p := range svc.Spec.Ports {
		if p.Name == "http" {
			httpSvcPort = &svc.Spec.Ports[i]
		}
	}
	if httpSvcPort == nil || httpSvcPort.Port != 80 || httpSvcPort.TargetPort.StrVal != "http" {
		t.Fatalf("router Service must expose port 80 -> http, got %+v", svc.Spec.Ports)
	}
	assertRouterFrontDoorPorts(t, out, libRouterNginxFiles(t)["nginx.conf"])
}

// findContainerPort returns the named container port.
// A kubelet probe reaches a port of the router pod only while the pod ruleset
// leaves it uncaptured: the ports the enforcer compiles in as the router's
// listeners, and the mesh endpoint's health port. A captured port is answered
// by the mesh listener, which speaks mTLS, so the probe never passes and the
// container it gates never starts.
func TestChartRouterProbePortsAreUncaptured(t *testing.T) {
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// internal/cmds/nri-image-policy's routerListeners.
	uncaptured := []uint16{8443, 8080, 8403, uint16(workloadclaims.MeshHealthPort)}
	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	for _, container := range append(slices.Clone(pod.InitContainers), pod.Containers...) {
		for kind, probe := range map[string]*corev1.Probe{
			"startup":   container.StartupProbe,
			"readiness": container.ReadinessProbe,
			"liveness":  container.LivenessProbe,
		} {
			if probe == nil || probe.HTTPGet == nil {
				continue
			}
			port := probedPort(t, container, probe.HTTPGet.Port)
			if !slices.Contains(uncaptured, port) {
				t.Errorf("%s's %s probe is on port %d, which the pod ruleset captures into the mesh listener", container.Name, kind, port)
			}
		}
	}
}

// probedPort is the port number a probe reaches, resolving a named port
// against the container that declares it.
func probedPort(t *testing.T, c corev1.Container, port intstr.IntOrString) uint16 {
	t.Helper()
	if port.Type == intstr.Int {
		return uint16(port.IntValue())
	}
	declared, ok := findContainerPort(c, port.StrVal)
	if !ok {
		t.Fatalf("%s is probed on port %q, which it declares nowhere", c.Name, port.StrVal)
	}
	return uint16(declared.ContainerPort)
}

func findContainerPort(c corev1.Container, name string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == name {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

// TestChartRouterAttestFrontDoorMode pins the endpoint-split wiring: the
// front door (mesh-issued serving leaf) runs cds-attest in cds front-door mode
// on loopback with no readiness probe.
func TestChartRouterAttestFrontDoorMode(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, "--front-door-mode=cds", "--host=127.0.0.1")
	if attest.ReadinessProbe != nil {
		t.Fatalf("cds-attest must stay probe-less, got %+v", attest.ReadinessProbe)
	}
}

// TestChartRouterGetCertRedeemsASandboxToken pins the claims flow on the
// router pod. Its own mesh endpoint adopts only a leaf that names a workload
// instance (internal/cmds/armtlsmesh), so get-cert redeems a sandbox token at
// the node inventory: the socket mounted read-only at the compiled path, the
// socket's supplemental group on the pod, and no opt-out flag.
func TestChartRouterGetCertRedeemsASandboxToken(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("c8s-cert init container missing")
	}
	assertContainerArgs(t, cert, "--ca-watch-interval=1m")
	var mount *corev1.VolumeMount
	for i, m := range cert.VolumeMounts {
		if m.Name == "workload-claims" {
			mount = &cert.VolumeMounts[i]
		}
	}
	if mount == nil || mount.MountPath != "/run/c8s/workload-claims" || !mount.ReadOnly {
		t.Fatalf("get-cert must mount the inventory socket read-only at the compiled path, got %+v", cert.VolumeMounts)
	}
	if slices.Contains(cert.Args, "--no-workload-claims") {
		t.Fatalf("get-cert opts out of claims behind the mount that carries them, got %v", cert.Args)
	}
	dep := renderedDeployment(t, out, "c8s-router")
	sc := dep.Spec.Template.Spec.SecurityContext
	if sc == nil || len(sc.SupplementalGroups) != 1 || sc.SupplementalGroups[0] != 65532 {
		t.Fatalf("pod must carry the inventory socket's supplemental group 65532, got %+v", sc)
	}
	var vol *corev1.Volume
	for i, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "workload-claims" {
			vol = &dep.Spec.Template.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.HostPath == nil || vol.HostPath.Path != "/run/nri-image-policy" {
		t.Fatalf("workload-claims hostPath volume missing or wrong, got %+v", dep.Spec.Template.Spec.Volumes)
	}
}

// The router Service is in-cluster only; the front door is the node's host port.
func TestChartRouterServiceIsClusterIP(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := renderedService(t, out, "c8s-router").Spec.Type; got != corev1.ServiceTypeClusterIP {
		t.Fatalf("router Service type = %q, want ClusterIP", got)
	}
}

// routerRoutingArgs are the manifest-routing arguments cds-attest carries in
// every shape at the chart defaults.
var routerRoutingArgs = []string{
	"--routing-host=127.0.0.1",
	"--routing-port=8802",
	"--routes-poll-interval=30s",
	"--backend-timeout=1h",
	"--reserved-paths=/allowlist,/.well-known/c8s/,/.well-known/acme-challenge/,/v1/discovery,/.well-known/cds-cert.pem,/.well-known/mesh-ca.pem,/readyz,/healthz",
}

func TestChartRendersRouterAttestSidecar(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set-string", "router.attest.generation=milan")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// The cds-attest sidecar runs the operator multi-mode image with the
	// cds-attest subcommand, bound to loopback for nginx to proxy to.
	deployment := renderedDeployment(t, out, "c8s-router")
	sidecar := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	if len(sidecar.Args) == 0 || sidecar.Args[0] != "cds-attest" {
		t.Fatalf("cds-attest args = %v, want first arg 'cds-attest'", sidecar.Args)
	}
	assertContainerArgs(t, sidecar, append([]string{
		"--host=127.0.0.1",
		"--port=8800",
		"--generation=milan",
	}, routerRoutingArgs...)...)
	assertContainerHasArgPrefix(t, "cds-attest", sidecar.Args, "--attestation-api-url=unix:///run/nri-image-policy/attestation-api.sock")
	// --cds-url among them: the enforcer mounts the one CDS endpoint this
	// node admits for the router role, and cds-attest reads it there.
	for _, banned := range []string{"--upstream", "--attest-endpoints", "--operator-keys-file", "--cds-measurements", "--cds-rtmrs", "--publish-routes", "--cds-url", "--mesh-identity-"} {
		assertContainerNoArgPrefix(t, "cds-attest", sidecar.Args, banned)
	}
	assertContainerHasArg(t, "cds-attest", sidecar.Args, "--image-policy-file=/mnt/c8s-data/measurements/cds.json")
	if got := len(deployment.Spec.Template.Spec.Containers); got != 3 {
		t.Fatalf("router should have nginx + cds-attest + allowlist-proxy, got %d containers", got)
	}

	// The protocol endpoints take 16k bodies. Tunnel records up to 8 MiB
	// spill to a sized tmpfs, capped per client address only.
	cfg := renderedRouterNginxConfig(t, out)
	protocol := cfg.location(t, "prefix", "/.well-known/c8s/")
	tunnel := cfg.location(t, "exact", "/.well-known/c8s/tunnel")
	for _, loc := range []*nginxBlock{protocol, tunnel} {
		for _, name := range []string{"proxy_buffering", "proxy_request_buffering"} {
			if got := loc.directives[name]; len(got) != 1 || !slices.Equal(got[0], []string{"on"}) {
				t.Fatalf("%s = %v, want exactly on", name, got)
			}
		}
		loc.assertDirective(t, "proxy_pass", "http://127.0.0.1:8800")
		loc.assertDirective(t, "proxy_max_temp_file_size", "0")
		loc.assertDirective(t, "proxy_read_timeout", "3630s")
		loc.assertDirective(t, "proxy_set_header", "X-Real-IP", "$remote_addr")
		loc.assertDirective(t, "proxy_set_header", "X-C8s-Connection", "$nginx_start.$pid.$connection")
	}
	protocol.assertNoDirective(t, "limit_conn")
	protocol.assertDirective(t, "client_max_body_size", "16k")
	protocol.assertDirective(t, "client_body_buffer_size", "16k")
	tunnel.assertDirective(t, "client_max_body_size", "8m")
	tunnel.assertDirective(t, "client_body_buffer_size", "16k")
	tunnel.assertDirective(t, "client_body_temp_path", "/var/lib/c8s-tunnel-body")
	tunnel.assertDirective(t, "client_body_timeout", "10s")
	tunnel.assertDirective(t, "limit_conn", "c8s_tunnel_per_client", "64")
	tunnel.assertDirective(t, "limit_conn_status", "503")
	tunnel.assertDirective(t, "error_page", "503", "@tunnel_busy")
	cfg.location(t, "named", "@tunnel_busy").assertDirective(t, "default_type", "application/json")
	if got := cfg.http.directives["limit_conn_zone"]; len(got) != 1 || !slices.Equal(got[0], []string{"$binary_remote_addr", "zone=c8s_tunnel_per_client:10m"}) {
		t.Fatalf("limit_conn_zone = %v, want only the per-client tunnel zone", got)
	}
	conf := renderedRouterNginxConf(t, out)
	for _, want := range []string{"\nworker_rlimit_nofile 65536;\n", "\n    worker_connections 16384;\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("router nginx.conf lacks %q", want)
		}
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if m, ok := containerVolumeMount(nginx, "nginx-tunnel-body"); !ok || m.MountPath != "/var/lib/c8s-tunnel-body" {
		t.Fatalf("nginx tunnel body mount = %+v, %v, want /var/lib/c8s-tunnel-body", m, ok)
	}
	if v, ok := podVolume(deployment.Spec.Template.Spec, "nginx-tunnel-body"); !ok || v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory || v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.String() != "8Gi" {
		t.Fatalf("nginx-tunnel-body volume = %+v, want an 8Gi memory emptyDir", v)
	}
	cfg.location(t, "exact", "/readyz").assertDirective(t, "proxy_set_header", "X-Real-IP", "$remote_addr")

	assertContainerNoArgPrefix(t, "cds-attest", sidecar.Args, "--tunnel-budget")

	// The sidecar's own establish-rate defaults stand.
	assertContainerNoArgPrefix(t, "cds-attest", sidecar.Args, "--establish-")
}

// TestChartRouterRoutePublication pins router.routePublication.enabled to
// cds-attest --publish-routes.
func TestChartRouterRoutePublication(t *testing.T) {
	out, err := helmTemplate(t, "--set", "router.routePublication.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, renderedDeploymentContainer(t, out, "c8s-router", "cds-attest"), "--publish-routes")

	// A string "false" is truthy in a template; the schema refuses it.
	out, err = helmTemplate(t, "--set-string", "router.routePublication.enabled=false")
	if err == nil || !strings.Contains(out, "routePublication") {
		t.Fatalf("expected a schema refusal of a string routePublication.enabled; err %v\n%s", err, out)
	}
}

// TestChartRouterCDSPins pins that cds-attest and allowlist-proxy verify the
// same CDS: both take their pins from router.cdsPinArgs.
func TestChartRouterCDSPins(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chart   chartRender
		want    string
		mounted bool
	}{
		{name: "an external CDS", chart: chartRender{render: helmTemplate}, want: "--image-policy-file=/mnt/c8s-data/measurements/cds.json", mounted: true},
		{name: "a worker", chart: chartRender{render: helmTemplateWorker}, want: "--image-policy-file=/run/c8s-node/cds.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.chart.render(t, tc.chart.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			// The allowlist proxy holds the credentials role, so the node
			// hands it the pin instead
			// (TestRouterAllowlistProxyTakesItsCDSPinsFromTheNode).
			c := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
			assertContainerArgs(t, c, tc.want)
			m, ok := containerVolumeMount(c, "measurements-config")
			if ok != tc.mounted || (ok && (m.MountPath != "/mnt/c8s-data/measurements" || !m.ReadOnly)) {
				t.Errorf("cds-attest measurements-config mount = (%+v, %v), want present=%v at /mnt/c8s-data/measurements read-only", m, ok, tc.mounted)
			}
		})
	}
}

// TestChartRouterOperatorKeySource pins the router's operator-key source:
// cds.operatorKeys when set, else CDS itself.
func TestChartRouterOperatorKeySource(t *testing.T) {
	t.Parallel()
	keys := []string{"--set-string", "cds.operatorKeys=-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"}
	const keysArg = "--operator-keys-file=/mnt/c8s-data/operator-keys/keys.pem"
	for _, tc := range []struct {
		name     string
		args     []string
		wantKeys bool
	}{
		{name: "pinned CDS"},
		{name: "pinned keys", args: keys, wantKeys: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			c := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
			if got := slices.Contains(c.Args, keysArg); got != tc.wantKeys {
				t.Errorf("cds-attest has %s = %v, want %v", keysArg, got, tc.wantKeys)
			}
			if tc.wantKeys {
				assertContainerMount(t, c, "operator-keys", "/mnt/c8s-data/operator-keys")
			}
		})
	}
}

// TestChartRefusesUnpinnedCDS renders each way a release names its CDS, the
// address and pin of a VM outside the cluster, and the inputs that name none.
func TestChartRefusesUnpinnedCDS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "cds.address and cds.measurementsConfig", args: baseCDSPolicy(t)},
		{
			name: "a CDS named by a DNS name",
			args: []string{"--set-string", "cds.address=cds.example.com:8443", "--set-file", "cds.measurementsConfig=" + baseCDSPin(t)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateUnpinned(t, cloudChartDir, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
		})
	}
	pin := []string{"--set-file", "cds.measurementsConfig=" + baseCDSPin(t)}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "neither", want: "cds_pins_required"},
		{name: "no pin", args: []string{"--set-string", "cds.address=" + baseCDSAddress}, want: "cds_pins_required"},
		{name: "no address", args: pin, want: "cds_address_required"},
		{name: "no port", args: append(pin, "--set-string", "cds.address=10.9.9.9"), want: "cds_address_required"},
		{name: "an uppercase name", args: append(pin, "--set-string", "cds.address=CDS.example.com:8443"), want: "cds_address_required"},
		{name: "a URL, not an endpoint", args: append(pin, "--set-string", "cds.address=https://cds.example.com:8443"), want: "cds_address_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateUnpinned(t, cloudChartDir, tc.args...)
			if err == nil {
				t.Fatalf("helm template accepted a release that names no CDS\n%s", out)
			}
			if got := parseValidationErrorKind(out); got != tc.want {
				t.Fatalf("validation kind = %q, want %s\n%s", got, tc.want, out)
			}
		})
	}
}

func TestRouterCORSAllowsSessionHeaderByDefault(t *testing.T) {
	t.Parallel()
	// Browser clients send X-C8s-Session on the /tunnel request, so the
	// protocol endpoints' CORS allow-headers must include it or the
	// over-encrypted channel breaks cross-origin.
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedRouterNginxConf(t, out)
	if !strings.Contains(conf, "X-C8s-Session") {
		t.Fatalf("CORS Access-Control-Allow-Headers missing X-C8s-Session:\n%s", conf)
	}
}

// protocolCORSLocations are the C8s protocol-owned nginx locations that serve
// wide-open CORS by default: their responses are self-authenticating or
// public by design, and browser verifiers on any origin must be able to
// reach them.
var protocolCORSLocations = []struct{ match, path string }{
	{"exact", "/allowlist"},
	{"prefix", "/allowlist/"},
	{"exact", "/v1/discovery"},
	{"exact", "/.well-known/cds-cert.pem"},
	{"exact", "/.well-known/mesh-ca.pem"},
	{"prefix", "/.well-known/c8s/"},
	{"exact", "/.well-known/c8s/tunnel"},
}

func TestRouterProtocolEndpointsCORSByDefault(t *testing.T) {
	t.Parallel()
	// With no CORS configuration at all, the protocol-owned endpoints must be
	// callable from a browser on any origin — that is the whole point of
	// in-browser attestation — while workload locations stay untouched.
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	for _, loc := range protocolCORSLocations {
		block := cfg.location(t, loc.match, loc.path)
		block.assertDirective(t, "add_header", "Access-Control-Allow-Origin", `"*"`, "always")
	}
	// Application routing inherits nothing from the protocol default.
	cfg.location(t, "prefix", "/").assertNoDirective(t, "add_header")
	// The built-in policy is self-contained: none of the global CORS
	// http-level maps are rendered.
	if _, ok := cfg.maps[nginxMapKey{source: "$http_origin", target: "$cors_origin"}]; ok {
		t.Fatal("global CORS maps rendered without router.cors.enabled")
	}
}

func TestRouterExposesAllowlistThroughCDSByDefault(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	if cfg.http == nil {
		t.Fatal("nginx config missing http block")
	}
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_rate_key", "zone=allowlist_write_per_client:10m", "rate=1r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_total_key", "zone=allowlist_write_total:1m", "rate=8r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_read_rate_key", "zone=allowlist_read_per_client:10m", "rate=20r/s")
	rateMap := cfg.mapBlock(t, "$request_method", "$allowlist_write_rate_key")
	rateMap.assertDirective(t, "default", "$binary_remote_addr")
	rateMap.assertDirective(t, "GET", `""`)
	rateMap.assertDirective(t, "HEAD", `""`)
	rateMap.assertDirective(t, "OPTIONS", `""`)
	// The total key chains off the write key: exempt methods stay exempt, any
	// counted method collapses onto the single "all" bucket.
	totalMap := cfg.mapBlock(t, "$allowlist_write_rate_key", "$allowlist_write_total_key")
	totalMap.assertDirective(t, `""`, `""`)
	totalMap.assertDirective(t, "default", `"all"`)
	readMap := cfg.mapBlock(t, "$request_method", "$allowlist_read_rate_key")
	readMap.assertDirective(t, "default", `""`)
	readMap.assertDirective(t, "GET", "$binary_remote_addr")
	readMap.assertDirective(t, "HEAD", "$binary_remote_addr")

	for _, route := range []struct {
		match string
		path  string
	}{
		{match: "exact", path: "/allowlist"},
		{match: "prefix", path: "/allowlist/"},
	} {
		location := cfg.location(t, route.match, route.path)
		location.assertDirective(t, "proxy_pass", "http://127.0.0.1:8801$request_uri")
		location.assertDirective(t, "proxy_set_header", "Host", "$host")
		location.assertDirective(t, "proxy_set_header", "Authorization", "$http_authorization")
		location.assertDirective(t, "limit_req", "zone=allowlist_write_per_client", "burst=15", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_write_total", "burst=15", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_read_per_client", "burst=40", "nodelay")
		location.assertDirective(t, "limit_req_status", "429")
		location.assertNoDirective(t, "proxy_ssl_verify")
	}

	proxy := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy")
	for _, want := range []string{
		"allowlist-proxy",
		"--host=127.0.0.1",
		"--port=8801",
		"--attestation-api-url=unix:///run/c8s/workload-claims/attestation-api.sock",
	} {
		assertContainerHasArg(t, "allowlist-proxy", proxy.Args, want)
	}
	// No TLS or operator key material: the inventory socket directory holding
	// the node's attestation-api, and the sandbox's plugin-ready gate.
	wantMounts := []string{
		"plugin-ready-gate",
		"workload-claims",
	}
	if names := sortedMountNames(proxy); !slices.Equal(names, wantMounts) {
		t.Fatalf("allowlist-proxy must not receive TLS or operator private keys: mounts=%v", proxy.VolumeMounts)
	}
}

// sortedMountNames is the volumes a container mounts, by name.
func sortedMountNames(c corev1.Container) []string {
	names := make([]string, 0, len(c.VolumeMounts))
	for _, m := range c.VolumeMounts {
		names = append(names, m.Name)
	}
	slices.Sort(names)
	return names
}

// Both lanes rate-limit /allowlist per client and in aggregate below CDS's
// own per-source bucket, which the whole front door shares.
func TestRouterAllowlistRateLimits(t *testing.T) {
	t.Parallel()
	for name, files := range map[string]func(*testing.T) map[string]string{
		"cloud":  cloudRouterNginxFiles,
		"worker": libRouterNginxFiles,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := parseNginxConfig(t, files(t)["nginx.conf"])
			cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_rate_key", "zone=allowlist_write_per_client:10m", "rate=1r/s")
			cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_total_key", "zone=allowlist_write_total:1m", "rate=8r/s")
			cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_read_rate_key", "zone=allowlist_read_per_client:10m", "rate=20r/s")
			for _, key := range []nginxLocationKey{
				{match: "exact", path: "/allowlist"},
				{match: "prefix", path: "/allowlist/"},
			} {
				location := cfg.location(t, key.match, key.path)
				location.assertDirective(t, "limit_req", "zone=allowlist_write_per_client", "burst=15", "nodelay")
				location.assertDirective(t, "limit_req", "zone=allowlist_write_total", "burst=15", "nodelay")
				location.assertDirective(t, "limit_req", "zone=allowlist_read_per_client", "burst=40", "nodelay")
				location.assertDirective(t, "limit_req_status", "429")
			}
		})
	}
}

// The node pins the CDS its credential clients reach, so the chart hands the
// proxy no pin of its own while CDS still takes the operator's.
func TestRouterAllowlistProxyTakesItsCDSPinsFromTheNode(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	proxy := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy")
	// It holds the credentials role, so its node hands it the pins and
	// refuses an argument naming any.
	assertNoArgWithPrefix(t, "allowlist-proxy", proxy.Args, "--cds-measurements", "--image-policy-file")
}

func renderedRouterNginxConf(t *testing.T, manifest string) string {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-router-nginx")
	conf, ok := cm.Data["nginx.conf"]
	if !ok || conf == "" {
		t.Fatalf("router nginx ConfigMap missing nginx.conf\n%s", manifest)
	}
	return conf
}

type nginxConfig struct {
	upstreams map[string]*nginxBlock
	maps      map[nginxMapKey]*nginxBlock
	// locations holds each location of the first server declaring it, the
	// HTTPS server.
	locations map[nginxLocationKey]*nginxBlock
	http      *nginxBlock
	servers   []*nginxBlock
	all       []*nginxBlock
}

type nginxMapKey struct {
	source string
	target string
}

type nginxLocationKey struct {
	match string
	path  string
}

type nginxBlock struct {
	directives map[string][][]string
	locations  map[nginxLocationKey]*nginxBlock
}

func renderedRouterNginxConfig(t *testing.T, manifest string) nginxConfig {
	t.Helper()
	return parseNginxConfig(t, renderedRouterNginxConf(t, manifest))
}

func parseNginxConfig(t *testing.T, conf string) nginxConfig {
	t.Helper()
	cfg := nginxConfig{
		upstreams: make(map[string]*nginxBlock),
		maps:      make(map[nginxMapKey]*nginxBlock),
		locations: make(map[nginxLocationKey]*nginxBlock),
	}

	var stack []*nginxBlock
	var server *nginxBlock
	for line := range strings.SplitSeq(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if before, ok := strings.CutSuffix(trimmed, "{"); ok {
			fields := strings.Fields(strings.TrimSpace(before))
			block := &nginxBlock{directives: make(map[string][][]string), locations: make(map[nginxLocationKey]*nginxBlock)}
			cfg.all = append(cfg.all, block)
			if len(fields) == 1 && fields[0] == "http" {
				cfg.http = block
			}
			if len(fields) == 1 && fields[0] == "server" {
				cfg.servers = append(cfg.servers, block)
				server = block
			}
			if len(fields) == 2 && fields[0] == "upstream" {
				cfg.upstreams[fields[1]] = block
			}
			if len(fields) == 3 && fields[0] == "map" {
				cfg.maps[nginxMapKey{source: fields[1], target: fields[2]}] = block
			}
			if len(fields) >= 2 && fields[0] == "location" {
				key := nginxLocationKey{match: "prefix", path: fields[1]}
				if len(fields) == 3 && fields[1] == "=" {
					key = nginxLocationKey{match: "exact", path: fields[2]}
				}
				if strings.HasPrefix(fields[1], "@") {
					key = nginxLocationKey{match: "named", path: fields[1]}
				}
				if _, seen := cfg.locations[key]; !seen {
					cfg.locations[key] = block
				}
				if server != nil {
					server.locations[key] = block
				}
			}
			stack = append(stack, block)
			continue
		}
		if trimmed == "}" {
			if len(stack) == 0 {
				t.Fatalf("nginx config has unmatched closing brace")
			}
			if stack[len(stack)-1] == server {
				server = nil
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if len(stack) == 0 || !strings.HasSuffix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		current.directives[fields[0]] = append(current.directives[fields[0]], fields[1:])
	}
	if len(stack) != 0 {
		t.Fatalf("nginx config has %d unclosed block(s)", len(stack))
	}
	return cfg
}

func (cfg nginxConfig) location(t *testing.T, match, path string) *nginxBlock {
	t.Helper()
	key := nginxLocationKey{match: match, path: path}
	location, ok := cfg.locations[key]
	if !ok {
		t.Fatalf("nginx config missing location %#v; got %v", key, cfg.locations)
	}
	return location
}

func (b *nginxBlock) location(t *testing.T, match, path string) *nginxBlock {
	t.Helper()
	key := nginxLocationKey{match: match, path: path}
	location, ok := b.locations[key]
	if !ok {
		t.Fatalf("nginx server missing location %#v; got %v", key, b.locations)
	}
	return location
}

// server is the HTTPS server, the one listening with ssl.
func (cfg nginxConfig) server(t *testing.T) *nginxBlock {
	t.Helper()
	var https []*nginxBlock
	for _, s := range cfg.servers {
		if slices.ContainsFunc(s.directives["listen"], func(args []string) bool { return slices.Contains(args, "ssl") }) {
			https = append(https, s)
		}
	}
	if len(https) != 1 {
		t.Fatalf("nginx config has %d HTTPS server blocks, want 1", len(https))
	}
	return https[0]
}

// httpServer is the plain-HTTP server, the one listening without ssl.
func (cfg nginxConfig) httpServer(t *testing.T) *nginxBlock {
	t.Helper()
	var plain []*nginxBlock
	for _, s := range cfg.servers {
		if !slices.ContainsFunc(s.directives["listen"], func(args []string) bool { return slices.Contains(args, "ssl") }) {
			plain = append(plain, s)
		}
	}
	if len(plain) != 1 {
		t.Fatalf("nginx config has %d plain-HTTP server blocks, want 1", len(plain))
	}
	return plain[0]
}

// assertNoDirectivePrefix fails if any block in the config carries a directive
// whose name starts with prefix.
func (cfg nginxConfig) assertNoDirectivePrefix(t *testing.T, prefix string) {
	t.Helper()
	for _, block := range cfg.all {
		for name, args := range block.directives {
			if strings.HasPrefix(name, prefix) {
				t.Fatalf("nginx directive %s %v present, want no %s* directives", name, args, prefix)
			}
		}
	}
}

func (cfg nginxConfig) mapBlock(t *testing.T, source, target string) *nginxBlock {
	t.Helper()
	key := nginxMapKey{source: source, target: target}
	block, ok := cfg.maps[key]
	if !ok {
		t.Fatalf("nginx config missing map %#v; got %v", key, cfg.maps)
	}
	return block
}

func (block *nginxBlock) assertDirective(t *testing.T, name string, args ...string) {
	t.Helper()
	for _, got := range block.directives[name] {
		if slices.Equal(got, args) {
			return
		}
	}
	t.Fatalf("nginx directive %q args %v not found; got %v", name, args, block.directives[name])
}

func (block *nginxBlock) assertNoDirective(t *testing.T, name string) {
	t.Helper()
	if got := block.directives[name]; len(got) > 0 {
		t.Fatalf("nginx directive %q = %v, want absent", name, got)
	}
}

// assertRouterFrontDoorPorts pins the sites that must name the same public
// port set: the nginx containerPorts, the Service's targets and the ingress
// policy, each a port nginx listens on. A port wired in one and missing from
// another is unreachable in exactly one direction, and hostPort must bind all
// of them or none — a partial bind publishes a port the pod does not answer.
// It returns the published ports.
func assertRouterFrontDoorPorts(t *testing.T, manifest, nginxConf string) []int32 {
	t.Helper()
	var listens []int32
	for _, server := range parseNginxConfig(t, nginxConf).servers {
		for _, args := range server.directives["listen"] {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				t.Fatalf("nginx listen %v: %v", args, err)
			}
			listens = append(listens, int32(port))
		}
	}

	nginx := renderedDeploymentContainer(t, manifest, "c8s-router", "nginx")
	byName := make(map[string]int32, len(nginx.Ports))
	var declared, hostBound []int32
	for _, p := range nginx.Ports {
		byName[p.Name] = p.ContainerPort
		declared = append(declared, p.ContainerPort)
		if p.HostPort != 0 {
			hostBound = append(hostBound, p.ContainerPort)
		}
		if !slices.Contains(listens, p.ContainerPort) {
			t.Errorf("nginx declares port %d, but listens on %v", p.ContainerPort, listens)
		}
	}

	var targeted []int32
	for _, p := range renderedService(t, manifest, "c8s-router").Spec.Ports {
		port, ok := byName[p.TargetPort.StrVal]
		if !ok {
			t.Fatalf("router Service targets %q, which no nginx port declares", p.TargetPort.StrVal)
		}
		targeted = append(targeted, port)
	}
	assertSamePorts(t, "Service targets", targeted, declared)

	var np networkingv1.NetworkPolicy
	if !findDoc(t, manifest, "NetworkPolicy", "c8s-router-ingress", &np) {
		t.Fatal("render is missing the router ingress policy")
	}
	var admitted []int32
	for _, rule := range np.Spec.Ingress {
		for _, p := range rule.Ports {
			if p.Port == nil {
				t.Fatal("the front-door rule opens every port")
			}
			admitted = append(admitted, int32(p.Port.IntValue()))
		}
	}
	assertSamePorts(t, "ingress policy", admitted, declared)

	if len(hostBound) != 0 && len(hostBound) != len(declared) {
		t.Errorf("hostPort binds %v of the front-door ports %v", hostBound, declared)
	}
	return declared
}

func assertSamePorts(t *testing.T, site string, got, declared []int32) {
	t.Helper()
	slices.Sort(got)
	want := slices.Clone(declared)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, but nginx declares %v", site, got, want)
	}
}

// TestRouterRejectsInvalidValues pins the router's schema guards;
// helmTemplateRouter prefixes each --set path with router.
func TestRouterRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"soon", "0s", "30"} {
		t.Run(value, func(t *testing.T) {
			out, err := helmTemplateRouter(t, "--set-string", "routing.pollInterval="+value)
			if err == nil || !strings.Contains(out, "router.routing.pollInterval") {
				t.Fatalf("helm template with pollInterval %q = %v, want the schema refusal\n%s", value, err, out)
			}
		})
	}
}

func TestRouterDiscoveryRequiresAdvertisedMeshCA(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	meshCA := cfg.location(t, "exact", "/.well-known/mesh-ca.pem")
	meshCA.assertDirective(t, "alias", "/etc/c8s/certs/ca.crt")
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--ca-path=/etc/c8s/certs/ca.crt",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem")
}

// TestRouterGetCertWritesMeshCABundle pins the mechanism that replaced the
// c8s-cds-mesh-ca ConfigMap mount: the c8s-cert sidecar writes the mesh CA
// bundle to /etc/c8s/certs/ca.crt (the c8s-certs volume that already holds the leaf).
func TestRouterGetCertWritesMeshCABundle(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--ca-path=/etc/c8s/certs/ca.crt")
}

func TestRouterDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--discovery-public-tls-mode=cds")
}

func TestChartOperatorRBACIsScoped(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// Decode the ClusterRole and assert the verbs exactly so a broadened
	// grant fails. The event recorder needs events, but only create/patch
	// (recorder aggregation), never read or delete across the cluster.
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	for _, tc := range []struct {
		apiGroup, resource string
		verbs              []string
	}{
		{"confidential.ai", "confidentialworkloads", []string{"get", "list", "watch"}},
		{"confidential.ai", "confidentialworkloads/status", []string{"get", "update", "patch"}},
		{"", "pods", []string{"get", "list", "watch", "delete"}},
		{"coordination.k8s.io", "leases", []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		{"admissionregistration.k8s.io", "mutatingwebhookconfigurations", []string{"get", "update", "patch"}},
	} {
		if got := operatorVerbsFor(role, tc.apiGroup, tc.resource); !slices.Equal(got, tc.verbs) {
			t.Fatalf("operator %s verbs = %v, want %v", tc.resource, got, tc.verbs)
		}
	}
	if got := operatorVerbsFor(role, "", "events"); !slices.Equal(got, []string{"create", "patch"}) {
		t.Fatalf("operator events verbs = %v, want [create patch]", got)
	}
	// The workload-service reconciler reads workloads (never mutates them)
	// and owns the headless Services it provisions in workload namespaces.
	for _, resource := range []string{"deployments", "statefulsets", "daemonsets"} {
		if got := operatorVerbsFor(role, "apps", resource); !slices.Equal(got, []string{"get", "list", "watch"}) {
			t.Fatalf("operator %s verbs = %v, want read-only [get list watch]", resource, got)
		}
	}
	if got := operatorVerbsFor(role, "", "services"); !slices.Equal(got, []string{"get", "list", "watch", "create", "update", "delete"}) {
		t.Fatalf("operator services verbs = %v", got)
	}
	// No rendered Role/ClusterRole may grant any of these resources at all,
	// and no rendered role grants nodes: only the CDS a baked image runs reads
	// them, to keep its sandbox-digests bound current from the live node list.
	banned := []string{"confidentialworkloads/finalizers", "replicasets", "secrets", "configmaps", "rolebindings"}
	var nodesGrantors []string
	iterateManifests(t, out, func(doc []byte) bool {
		var head docMeta
		if err := sigsyaml.Unmarshal(doc, &head); err != nil || (head.Kind != "ClusterRole" && head.Kind != "Role") {
			return false
		}
		var r struct {
			Rules []rbacv1.PolicyRule `json:"rules"`
		}
		if err := sigsyaml.Unmarshal(doc, &r); err != nil {
			t.Fatalf("decode %s %s rules: %v", head.Kind, head.Metadata.Name, err)
		}
		for _, rule := range r.Rules {
			for _, resource := range banned {
				if slices.Contains(rule.Resources, resource) {
					t.Errorf("%s %s grants broad RBAC resource %q", head.Kind, head.Metadata.Name, resource)
				}
			}
			if slices.Contains(rule.Resources, "nodes") {
				nodesGrantors = append(nodesGrantors, head.Metadata.Name)
			}
		}
		return false
	})
	if len(nodesGrantors) != 0 {
		t.Fatalf("nodes granted to %v, want none", nodesGrantors)
	}
}

// operatorVerbsFor returns the verbs the ClusterRole grants on (apiGroup,
// resource), nil if no rule covers it. It does not expand wildcards: a "*"
// resource or apiGroup matches only a literal "*" lookup, which is intentional
// for least-privilege assertions.
func operatorVerbsFor(role rbacv1.ClusterRole, apiGroup, resource string) []string {
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, apiGroup) && slices.Contains(rule.Resources, resource) {
			return rule.Verbs
		}
	}
	return nil
}

func TestChartWebhookAddsCABundleRBAC(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	if got := operatorVerbsFor(role, "admissionregistration.k8s.io", "mutatingwebhookconfigurations"); !slices.Equal(got, []string{"get", "update", "patch"}) {
		t.Fatalf("operator mutatingwebhookconfigurations verbs = %v, want [get update patch]", got)
	}
}

// On node-CVM the operator gets the host-dir mount source, from which the
// webhook derives the get-cert workload-claims injection.
func TestChartWorkloadClaimsOperatorFlags(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedOperatorArgs(t, out)
	var hasHostDir bool
	for _, a := range args {
		if strings.HasPrefix(a, "--workload-claims-host-dir=") {
			hasHostDir = true
		}
	}
	if !hasHostDir {
		t.Fatalf("operator missing workload-claims-host-dir flag: %v", args)
	}
}

func TestChartNoRuntimeClassOnRouter(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-router")
	if rc := dep.Spec.Template.Spec.RuntimeClassName; rc != nil {
		t.Errorf("c8s-router runtimeClassName = %q, want unset", *rc)
	}
}

// The installer binds upstream containerd's config directory, socket and
// restart.
func TestChartNriImagePolicyBindsContainerdLayout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		args        []string
		wantDir     string
		wantSocket  string
		wantRestart string
	}{
		{
			name:        "chart defaults",
			wantDir:     "/etc/containerd",
			wantSocket:  "/run/containerd/containerd.sock",
			wantRestart: "systemctl restart containerd",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
			if got := hostPathVolume(t, ds, "host-containerd-config"); got != tc.wantDir {
				t.Fatalf("host-containerd-config hostPath = %q, want %q", got, tc.wantDir)
			}
			script := strings.Join(containerArgs(t, &ds, "install"), "\n")
			for _, want := range []string{
				"CONTAINERD_DIR=/host" + tc.wantDir,
				`RESTART_COMMAND="` + tc.wantRestart + `"`,
			} {
				if !strings.Contains(script, want) {
					t.Fatalf("install script missing %q\n%s", want, script)
				}
			}
			if got := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Containerd.Socket; got != tc.wantSocket {
				t.Errorf("boot config containerd socket = %q, want %q", got, tc.wantSocket)
			}
		})
	}
}

// TestChartNriImagePolicyDetachesContainerdRestart: the installer must hand the
// host containerd restart to systemd-run (host PID 1), not run it in this pod's
// process tree. A restart via `nsenter ... sh -c "$RESTART_COMMAND"` is killed
// with the pod when containerd bounces, which on a sole control-plane node
// interrupts the cluster bootstrap and wedges it.
func TestChartNriImagePolicyDetachesContainerdRestart(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "systemd-run") {
		t.Fatalf("install script must detach the containerd restart via systemd-run\n%s", script)
	}
	// The bare in-pod form (nsenter ... -- sh -c "$RESTART_COMMAND") must be
	// gone; the restart now goes nsenter ... -- systemd-run ... sh -c "...".
	if strings.Contains(script, `-p -- sh -c "$RESTART_COMMAND"`) {
		t.Fatalf("install script still runs RESTART_COMMAND in-pod (not detached)\n%s", script)
	}
}

// hostPathVolume returns the hostPath of the named volume on a DaemonSet.
func hostPathVolume(t *testing.T, ds appsv1.DaemonSet, name string) string {
	t.Helper()
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == name {
			if v.HostPath == nil {
				t.Fatalf("DaemonSet volume %q is not a hostPath volume", name)
			}
			return v.HostPath.Path
		}
	}
	t.Fatalf("DaemonSet has no volume %q", name)
	return ""
}

// baseNRIDigest is the nri-image-policy image digest the shared harness pins;
// the seed admits it argv-pinned, so the default fail-closed render is valid.
const baseNRIDigest = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"

// baseCDSDigest is the CDS launch digest testdata/cds-pin.json carries, and
// baseCDSAddress the endpoint the shared harness points a release at: the
// chart refuses a release naming no CDS (kind=cds_pins_required,
// kind=cds_address_required).
var baseCDSDigest = strings.Repeat("ab", armtls.SNPMeasurementSize)

const (
	baseCDSAddress = "10.9.9.9:8443"
	// baseCDSPinPath is that CDS as the pin document an operator passes: the
	// image and the launch file its VM proves, schema 2 as every CDS pin is.
	baseCDSPinPath = "../testdata/cds-pin.json"
)

// baseCDSPin is that document where a render running in any directory reads
// it, which the renders of a copied chart do.
func baseCDSPin(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(baseCDSPinPath)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// baseCDSPinDocument is that document's bytes, for a render that takes the
// content rather than the file.
func baseCDSPinDocument(t *testing.T) string {
	t.Helper()
	document, err := os.ReadFile(baseCDSPinPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

// baseCDSPolicy is that CDS as install arguments: one address and one pin
// document, which is how every non-baked release names its CDS.
func baseCDSPolicy(t *testing.T) []string {
	t.Helper()
	return []string{"--set-string", "cds.address=" + baseCDSAddress, "--set-file", "cds.measurementsConfig=" + baseCDSPin(t)}
}

// helmOutput keeps warnings outside the YAML. Failed commands keep diagnostics.
func helmOutput(cmd *exec.Cmd) ([]byte, error) {
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	out, err := cmd.Output()
	if err != nil {
		out = append(out, diagnostics.Bytes()...)
	}
	return out, err
}

// chartsDir is the repository's charts/ directory.
var chartsDir = testutil.RepoPath("charts")

// cloudChartDir is the cloud chart in the repository layout, where c8s-lib is the
// committed charts/c8s-lib symlink.
var cloudChartDir = filepath.Join(chartsDir, "cloud")

// extractedChart is the cloud chart in the layout `c8s install` renders: the
// tree ExtractTemp writes, where the subchart link is rebuilt from Chart.yaml.
func extractedChart(t *testing.T) string {
	t.Helper()
	dir, err := ExtractTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, CloudChartFSPath)
}

// helmTemplate renders the repository layout.
func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return helmTemplateIn(t, cloudChartDir, args...)
}

// helmTemplateIn is helmTemplate on the chart at chartDir, under a
// placeholder CDS unless the caller names its own: the chart refuses a release
// naming no CDS (kind=cds_pins_required, kind=cds_address_required).
func helmTemplateIn(t *testing.T, chartDir string, args ...string) (string, error) {
	t.Helper()
	pinned := slices.ContainsFunc(args, func(arg string) bool {
		return strings.HasPrefix(arg, "cds.measurementsConfig") || strings.HasPrefix(arg, "cds.address")
	})
	if !pinned {
		args = append(baseCDSPolicy(t), args...)
	}
	return helmTemplateUnpinned(t, chartDir, args...)
}

// helmTemplateUnpinned is helmTemplateIn without the harness CDS pin, for the
// tests that drive the chart's cds_pins_required refusal and the pin sources
// that satisfy it.
func helmTemplateUnpinned(t *testing.T, chartDir string, args ...string) (string, error) {
	t.Helper()
	return renderCloudChart(t, chartDir, append(slices.Clone(basePlatformArgs), args...)...)
}

// helmTemplatePlatform renders the repository layout with a stock values file
// in place of basePlatformArgs. Takes the platform, such as aks-snp.
func helmTemplatePlatform(t *testing.T, platform string, args ...string) (string, error) {
	t.Helper()
	stock := []string{"-f", filepath.Join(cloudChartDir, "values-"+platform+".yaml")}
	return renderCloudChart(t, cloudChartDir, slices.Concat(stock, baseCDSPolicy(t), args)...)
}

// cloudPlatforms name the cloud chart's stock values files.
var cloudPlatforms = []string{
	"aks-snp",
	"aks-tdx",
	"gke-snp",
}

// renderCloudChart is helm template of the chart at chartDir with the
// harness's image tags and mesh values ahead of args.
func renderCloudChart(t *testing.T, chartDir string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	base := []string{
		"template", "c8s", chartDir,
		// Pin the simulated cluster version at the chart's kubeVersion base
		// so the tests do not depend on the helm client's compiled default
		// (helm 3.14 simulates 1.29, below the base).
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "armtlsMesh.image.tag=dev",
		"--set", "nriImagePolicy.image.tag=dev",
		// volumed is off by default, so its image is unused unless a test
		// enables it; set the tag here so those tests need not repeat it (its
		// own image requires a tag or digest, like every component).
		"--set", "volumed.image.tag=dev",
		// A mesh policy needs the resolver a member pod may reach and this
		// cluster's own ranges; both are required values.
		"--set-string", "nriImagePolicy.mesh.clusterRanges[0]=10.42.0.0/16",
		"--set-string", "nriImagePolicy.mesh.resolver=10.43.0.10",
		// The installer image must stay digest-pinned: the seed admits it
		// argv-pinned (c8s.argvPinnedEntries), which a tag cannot pin. No
		// bootstrap entry is needed — the uncovered_component_digest guard
		// exempts it as argvPinned. Tests that exercise the guard pin a
		// different, deliberately-uncovered component digest.
		"--set", "nriImagePolicy.image.digest=" + baseNRIDigest,
	}
	cmd := exec.Command("helm", append(base, args...)...)
	out, err := helmOutput(cmd)
	return string(out), err
}

// basePlatformArgs set the platform keys a stock file sets, for a node that
// attests through /dev/sev-guest.
var basePlatformArgs = []string{
	"--set-string", "attestationApi.devices[0]=/dev/sev-guest",
	"--set-string", `confidentialNodeSelector.cloud\.google\.com/gke-confidential-nodes-instance-type=SEV_SNP`,
	"--set-string", "nriImagePolicy.platform=snp",
	"--set-string", "router.attest.generation=genoa",
	"--set-string", "router.attest.platform=snp",
}

// assertRouterRoutingLocation checks location / proxies to the routing
// listener with no URI (so cds-attest sees the request target as sent), with
// the forwarding headers, streaming settings and timeouts the catch-all
// carried: non-streaming LLM responses send nothing until done, and a dead
// listener must fail fast.
func assertRouterRoutingLocation(t *testing.T, route *nginxBlock, port, readTimeout string) {
	t.Helper()
	for name, want := range map[string]string{
		"proxy_pass":              "http://127.0.0.1:" + port,
		"proxy_connect_timeout":   "5s",
		"proxy_read_timeout":      readTimeout,
		"proxy_send_timeout":      readTimeout,
		"proxy_buffering":         "off",
		"proxy_request_buffering": "off",
		"proxy_http_version":      "1.1",
	} {
		if got := route.directives[name]; len(got) != 1 || !slices.Equal(got[0], []string{want}) {
			t.Errorf("location / %s = %v, want exactly [%s]", name, got, want)
		}
	}
	route.assertDirective(t, "proxy_set_header", "Host", "$http_host")
	route.assertDirective(t, "proxy_set_header", "X-Real-IP", "$remote_addr")
	route.assertDirective(t, "proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for")
	route.assertDirective(t, "proxy_set_header", "X-Forwarded-Proto", "$scheme")
	route.assertDirective(t, "proxy_set_header", "X-C8s-Connection", "$nginx_start.$pid.$connection")
}

func TestChartRouterRoutingLocation(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/")
	assertRouterRoutingLocation(t, route, "8802", "3600s")
	route.assertDirective(t, "include", "/mnt/c8s-data/nginx/request-body.conf")
	route.assertNoDirective(t, "client_max_body_size")
	route.assertNoDirective(t, "add_header")
	cfg.assertNoDirectivePrefix(t, "proxy_ssl_")
	cfg.http.assertNoDirective(t, "resolver")
	if len(cfg.upstreams) != 0 {
		t.Fatalf("nginx renders upstream blocks %v, want none: cds-attest dials every backend", cfg.upstreams)
	}
	if got := renderedConfigMap(t, out, "c8s-router-nginx").Data["request-body.conf"]; got != "client_max_body_size 1048576;\n" {
		t.Errorf("request-body.conf = %q, want the default body limit", got)
	}

	out, err = helmTemplate(t, "--set-string", "router.routing.pollInterval=5s")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, renderedDeploymentContainer(t, out, "c8s-router", "cds-attest"), "--routes-poll-interval=5s")
}

// Both lanes' nginx files name the ports and paths their containers' argv and
// mounts name: the loopback listeners nginx proxies to, the files get-cert
// publishes, and the directories nginx reads its files and settings from.
func TestRouterNginxMatchesItsContainers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		lane     string
		render   func(t *testing.T, args ...string) (string, error)
		files    func(*testing.T) map[string]string
		settings string
	}{
		{lane: "cloud", render: helmTemplate, files: cloudRouterNginxFiles, settings: "/mnt/c8s-data/nginx"},
		{lane: "worker", render: helmTemplateWorker, files: libRouterNginxFiles, settings: "/run/c8s-node/router"},
	} {
		t.Run(tc.lane, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			files := tc.files(t)
			cfg := parseNginxConfig(t, files["nginx.conf"])
			pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
			nginx, _ := findContainer(pod.Containers, "nginx")
			attest, _ := findContainer(pod.Containers, "cds-attest")
			proxy, _ := findContainer(pod.Containers, "allowlist-proxy")
			cert, _ := findContainer(pod.InitContainers, "c8s-cert")

			https, ok := findContainerPort(nginx, "https")
			if !ok {
				t.Fatal("nginx declares no https port")
			}
			cfg.server(t).assertDirective(t, "listen", strconv.Itoa(int(https.ContainerPort)), "ssl")

			attestPort := argValue(t, attest.Args, "--port=")
			for _, key := range []nginxLocationKey{
				{match: "prefix", path: "/.well-known/c8s/"},
				{match: "exact", path: "/.well-known/c8s/tunnel"},
				{match: "exact", path: "/readyz"},
			} {
				cfg.location(t, key.match, key.path).assertDirective(t, "proxy_pass", "http://127.0.0.1:"+attestPort)
			}
			assertContainerArgs(t, attest, "--routing-host=127.0.0.1")
			cfg.location(t, "prefix", "/").assertDirective(t, "proxy_pass", "http://127.0.0.1:"+argValue(t, attest.Args, "--routing-port="))
			backend, err := time.ParseDuration(argValue(t, attest.Args, "--backend-timeout="))
			if err != nil {
				t.Fatal(err)
			}
			// nginx outwaits cds-attest's own timeout reply by 30s.
			cfg.location(t, "exact", "/.well-known/c8s/tunnel").assertDirective(t, "proxy_read_timeout", fmt.Sprintf("%ds", int((backend+30*time.Second).Seconds())))
			for _, key := range []nginxLocationKey{
				{match: "exact", path: "/allowlist"},
				{match: "prefix", path: "/allowlist/"},
			} {
				cfg.location(t, key.match, key.path).assertDirective(t, "proxy_pass", "http://127.0.0.1:"+argValue(t, proxy.Args, "--port=")+"$request_uri")
			}

			cfg.location(t, "exact", "/v1/discovery").assertDirective(t, "alias", argValue(t, cert.Args, "--discovery-out="))
			cfg.location(t, "exact", argValue(t, cert.Args, "--discovery-cds-cert-url=")).assertDirective(t, "alias", argValue(t, cert.Args, "--cert-path="))
			cfg.location(t, "exact", argValue(t, cert.Args, "--discovery-mesh-ca-url=")).assertDirective(t, "alias", argValue(t, cert.Args, "--ca-path="))
			spool, ok := containerVolumeMount(nginx, "nginx-tunnel-body")
			if !ok {
				t.Fatal("nginx mounts no tunnel body spool")
			}
			cfg.location(t, "exact", "/.well-known/c8s/tunnel").assertDirective(t, "client_body_temp_path", spool.MountPath)

			config, ok := containerVolumeMount(nginx, "nginx-config")
			if !ok || !config.ReadOnly {
				t.Fatalf("nginx config mount = (%+v, %v), want read-only", config, ok)
			}
			if want := []string{"/bin/sh", config.MountPath + "/serve.sh"}; !slices.Equal(nginx.Command, want) {
				t.Errorf("nginx command = %v, want %v", nginx.Command, want)
			}
			if want := "nginx -c " + config.MountPath + "/nginx.conf "; !strings.Contains(files["serve.sh"], want) {
				t.Errorf("serve.sh does not start %q", want)
			}
			cfg.server(t).assertDirective(t, "include", tc.settings+"/tls.conf")
			cfg.location(t, "prefix", "/").assertDirective(t, "include", tc.settings+"/request-body.conf")
			if !slices.ContainsFunc(nginx.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.ReadOnly && strings.HasPrefix(tc.settings+"/", m.MountPath+"/")
			}) {
				t.Errorf("nginx mounts nothing read-only over its settings at %s: %+v", tc.settings, nginx.VolumeMounts)
			}

			acmeHTTP := cfg.httpServer(t)
			acmeHTTP.location(t, "prefix", "/.well-known/acme-challenge/").assertDirective(t, "proxy_pass", "http://127.0.0.1:8402")
			acmeHTTP.assertDirective(t, "listen", "8080")
			if acme, ok := findContainer(pod.InitContainers, "acme"); ok {
				assertContainerArgs(t, acme, "--challenge-port=8402", "--http-port=8080")
			}
		})
	}
}

// argValue is the value of the one argument with prefix.
func argValue(t *testing.T, args []string, prefix string) string {
	t.Helper()
	var values []string
	for _, arg := range args {
		if v, ok := strings.CutPrefix(arg, prefix); ok {
			values = append(values, v)
		}
	}
	if len(values) != 1 {
		t.Fatalf("args %v carry %d %s arguments, want 1", args, len(values), prefix)
	}
	return values[0]
}

// TestChartRouterTunnelBusyCORS checks that nginx's tunnel_busy answer carries
// the tunnel's CORS headers, so a browser client can read it.
func TestChartRouterTunnelBusyCORS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	want := cfg.location(t, "exact", "/.well-known/c8s/tunnel").directives["add_header"]
	got := cfg.location(t, "named", "@tunnel_busy").directives["add_header"]
	if len(want) == 0 || !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("@tunnel_busy add_header = %v, want the tunnel's %v", got, want)
	}
}

// TestChartRouterHealthzIsExact pins /healthz as an exact location: a prefix
// one would also claim manifest paths such as /healthz-ui.
func TestChartRouterHealthzIsExact(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.location(t, "exact", "/healthz").assertDirective(t, "return", "200", `"ok\n"`)
	if _, ok := cfg.locations[nginxLocationKey{match: "prefix", path: "/healthz"}]; ok {
		t.Fatal("prefix location /healthz rendered, want only the exact one")
	}
}

// assertRouterWebSocketUpgrade checks location / passes a client's WebSocket
// upgrade on to the routing listener.
func assertRouterWebSocketUpgrade(t *testing.T, cfg nginxConfig, route *nginxBlock) {
	t.Helper()
	upgrade := cfg.mapBlock(t, "$http_upgrade", "$connection_upgrade")
	upgrade.assertDirective(t, "default", "upgrade")
	upgrade.assertDirective(t, `""`, "close")
	route.assertDirective(t, "proxy_set_header", "Upgrade", "$http_upgrade")
	route.assertDirective(t, "proxy_set_header", "Connection", "$connection_upgrade")
	route.assertDirective(t, "proxy_http_version", "1.1")
}

func TestChartRouterWebSocketUpgrade(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	assertRouterWebSocketUpgrade(t, cfg, cfg.location(t, "prefix", "/"))
}

// docMeta is the minimum we decode from each YAML doc to dispatch by kind+name.
type docMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// splitManifestDocs returns each non-empty doc in a multi-doc YAML stream as
// its own raw YAML chunk. helm template emits empty `---\n` separators that
// we silently drop.
func splitManifestDocs(manifest string) []string {
	var out []string
	for doc := range strings.SplitSeq(manifest, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		// The separator's newline ends the doc's last line.
		out = append(out, doc+"\n")
	}
	return out
}

// findDoc returns the first YAML doc matching kind (and name when non-empty),
// decoded into out via sigs.k8s.io/yaml. Returns false if no match.
func findDoc(t *testing.T, manifest, kind, name string, out any) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}
		if meta.Kind != kind {
			continue
		}
		if name != "" && meta.Metadata.Name != name {
			continue
		}
		if err := sigsyaml.Unmarshal([]byte(doc), out); err != nil {
			t.Fatalf("decode %s/%s: %v\n%s", kind, name, err, doc)
		}
		return true
	}
	return false
}

func renderedManifestHasKind(t *testing.T, manifest, kind string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind {
			return true
		}
	}
	return false
}

func renderedManifestHasNamedKind(t *testing.T, manifest, kind, name string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind && meta.Metadata.Name == name {
			return true
		}
	}
	return false
}

func renderedMutatingWebhook(t *testing.T, manifest, name string) admissionregv1.MutatingWebhook {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		for _, hook := range cfg.Webhooks {
			if hook.Name == name {
				return hook
			}
		}
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration webhook %q\n%s", name, manifest)
	return admissionregv1.MutatingWebhook{}
}

func renderedMutatingWebhookNames(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		names := make([]string, 0, len(cfg.Webhooks))
		for _, hook := range cfg.Webhooks {
			names = append(names, hook.Name)
		}
		return names
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration\n%s", manifest)
	return nil
}

func selectorExpressionValues(selector *metav1.LabelSelector, key string, op metav1.LabelSelectorOperator) []string {
	if selector == nil {
		return nil
	}
	for _, expression := range selector.MatchExpressions {
		if expression.Key == key && expression.Operator == op {
			return expression.Values
		}
	}
	return nil
}

func renderedOperatorArgs(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "Deployment" {
			continue
		}
		var dep appsv1.Deployment
		if err := sigsyaml.Unmarshal([]byte(doc), &dep); err != nil {
			t.Fatalf("decode Deployment %q: %v\n%s", meta.Metadata.Name, err, doc)
		}
		for _, container := range dep.Spec.Template.Spec.Containers {
			if container.Name == "operator" {
				return container.Args
			}
		}
	}
	t.Fatalf("rendered manifest missing operator container\n%s", manifest)
	return nil
}

// TestChartCertDependentPodStrategies pins router's rollout strategy to
// Recreate: two pods on a node would collide on the host port, and a surge pod
// could never schedule on a single-node cluster, deadlocking the roll.
func TestChartCertDependentPodStrategies(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	router := renderedDeployment(t, out, "c8s-router")
	if router.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("c8s-router strategy = %q, want Recreate (host-port binding forbids two concurrent pods on a node)", router.Spec.Strategy.Type)
	}
	assertRouterGracePeriodBelowDefault(t, router.Spec.Template.Spec)
}

// Both charts' router pods name a grace period below the Kubernetes default.
func assertRouterGracePeriodBelowDefault(
	t *testing.T,
	pod corev1.PodSpec,
) {
	t.Helper()
	grace := pod.TerminationGracePeriodSeconds
	if grace == nil {
		t.Errorf("the router pod names no termination grace period, so it takes the default %ds", corev1.DefaultTerminationGracePeriodSeconds)
		return
	}
	if *grace >= corev1.DefaultTerminationGracePeriodSeconds {
		t.Errorf("router termination grace period = %ds, want below the default %ds", *grace, corev1.DefaultTerminationGracePeriodSeconds)
	}
}

// TestChartRouterHostPort pins nginx's TLS listener to the node's host port,
// the one `c8s install` preflights for a conflict (RouterHostPort); the in-pod
// listener stays on an unprivileged port.
func TestChartRouterHostPort(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	p, ok := namedContainerPort(nginx, "https")
	if !ok {
		t.Fatal("nginx container has no https port")
	}
	if p.ContainerPort != 8443 || int(p.HostPort) != RouterHostPort {
		t.Fatalf("https = containerPort %d / hostPort %d, want 8443 / %d", p.ContainerPort, p.HostPort, RouterHostPort)
	}
}

// TestChartNoTeeProxyRemnants sweeps the default render for any leftover
// tee-proxy wiring after the component's removal.
func TestChartNoTeeProxyRemnants(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		render func(t *testing.T, args ...string) (string, error)
	}{
		{"default", helmTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			if strings.Contains(strings.ToLower(out), "tee-proxy") {
				t.Fatalf("render still references tee-proxy\n%s", out)
			}
		})
	}
}

// TestChartGetCertRetriesInProcess proves the injected c8s-cert sidecar retries
// CDS in-process (--initial-retry-timeout) on the bootstrap fetch instead of
// exiting into kubelet CrashLoopBackOff on a transient CDS/mesh outage during
// a roll.
func TestChartGetCertRetriesInProcess(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	inits := renderedDeploymentInitContainers(t, out, "c8s-router")
	var cert *corev1.Container
	for i := range inits {
		if inits[i].Name == "c8s-cert" {
			cert = &inits[i]
		}
	}
	if cert == nil {
		t.Fatalf("router has no c8s-cert init container\n%s", out)
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--initial-retry-timeout=2m")
}

func renderedDeployment(t *testing.T, manifest, name string) appsv1.Deployment {
	t.Helper()
	var dep appsv1.Deployment
	if !findDoc(t, manifest, "Deployment", name, &dep) {
		t.Fatalf("rendered manifest missing Deployment %q\n%s", name, manifest)
	}
	return dep
}

func renderedDaemonSet(t *testing.T, manifest, name string) appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	if !findDoc(t, manifest, "DaemonSet", name, &ds) {
		t.Fatalf("rendered manifest missing DaemonSet %q\n%s", name, manifest)
	}
	return ds
}

type nriRuntimeConfig struct {
	Allowlist struct {
		Pull struct {
			URL                   string `yaml:"url"`
			CDSAddressFile        string `yaml:"cds_address_file"`
			CDSMeasurementsConfig string `yaml:"cds_measurements_config"`
			Interval              string `yaml:"interval"`
			Timeout               string `yaml:"timeout"`
			AttestationApiURL     string `yaml:"attestation_api_url"`
			MeasurePolicies       bool   `yaml:"measure_policies"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
	Mesh *struct {
		ExemptNamespaces []string `yaml:"exempt_namespaces"`
		Resolver         string   `yaml:"resolver"`
		Capture          struct {
			Outbound uint16 `yaml:"outbound"`
			Inbound  uint16 `yaml:"inbound"`
			Health   uint16 `yaml:"health"`
		} `yaml:"capture"`
		Roles []struct {
			Name string `yaml:"name"`
			UID  uint32 `yaml:"uid"`
		} `yaml:"roles"`
		ClusterRanges []string `yaml:"cluster_ranges"`
	} `yaml:"mesh"`
}

func renderedNRIBootConfig(t *testing.T, manifest, daemonSetName string) nriRuntimeConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, daemonSetName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	raw := extractHeredoc(t, script, "IMAGE_POLICY_EOF")
	var cfg nriRuntimeConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode %s boot config: %v\n%s", daemonSetName, err, raw)
	}
	return cfg
}

func extractHeredoc(t *testing.T, script, marker string) string {
	t.Helper()
	startMarker := "<<'" + marker + "'\n"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("script missing heredoc start marker %q\n%s", marker, script)
	}
	bodyStart := start + len(startMarker)
	end := strings.Index(script[bodyStart:], "\n"+marker)
	if end < 0 {
		t.Fatalf("script missing heredoc end marker %q\n%s", marker, script)
	}
	return script[bodyStart : bodyStart+end]
}

func renderedConfigMap(t *testing.T, manifest, name string) corev1.ConfigMap {
	t.Helper()
	var cm corev1.ConfigMap
	if !findDoc(t, manifest, "ConfigMap", name, &cm) {
		t.Fatalf("rendered manifest missing ConfigMap %q\n%s", name, manifest)
	}
	return cm
}

func renderedService(t *testing.T, manifest, name string) corev1.Service {
	t.Helper()
	var svc corev1.Service
	if !findDoc(t, manifest, "Service", name, &svc) {
		t.Fatalf("rendered manifest missing Service %q\n%s", name, manifest)
	}
	return svc
}

func renderedDaemonSetContainer(t *testing.T, manifest, daemonSetName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDaemonSet(t, manifest, daemonSetName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered DaemonSet %q missing container %q\n%s", daemonSetName, containerName, manifest)
	return corev1.Container{}
}

func renderedDeploymentInitContainers(t *testing.T, manifest, name string) []corev1.Container {
	t.Helper()
	return renderedDeployment(t, manifest, name).Spec.Template.Spec.InitContainers
}

func renderedDeploymentContainer(t *testing.T, manifest, deploymentName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDeployment(t, manifest, deploymentName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered Deployment %q missing container %q\n%s", deploymentName, containerName, manifest)
	return corev1.Container{}
}

// helmTemplateRouter renders the router component from the parent C8s chart in
// isolation: siblings are disabled and every caller-supplied --set/--set-string
// path is prefixed with router., so callers write router-relative paths
// (cors.*, allowlist.*, routing.*). The release is named "c8s" so
// router.fullname resolves to c8s-router, matching the resource names the
// parent-chart router tests assert.
func helmTemplateRouter(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	base := append([]string{
		"template", "c8s", cloudChartDir,
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
	}, basePlatformArgs...)
	base = append(base,
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "armtlsMesh.image.tag=dev",
		"--set-string", "nriImagePolicy.mesh.clusterRanges[0]=10.42.0.0/16",
		"--set-string", "nriImagePolicy.mesh.resolver=10.43.0.10",
		// nri-image-policy is enabled in this render
		// (require_host_image_policy); pin its digest so the render is valid
		// (the seed admits it argv-pinned). Output is scoped to the router
		// templates below, so its manifests do not appear here.
		"--set", "nriImagePolicy.image.tag=dev",
		"--set", "nriImagePolicy.image.digest="+baseNRIDigest,
		"--show-only", "templates/router-configmap.yaml",
		"--show-only", "templates/router-deployment.yaml",
	)
	base = append(base, baseCDSPolicy(t)...)
	cmd := exec.Command("helm", append(base, prefixRouterSetArgs(args)...)...)
	out, err := helmOutput(cmd)
	return string(out), err
}

// prefixRouterSetArgs rewrites the value path of each --set/--set-string pair to
// live under the parent chart's router key, leaving the value (right of '=')
// untouched.
func prefixRouterSetArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != "--set" && out[i] != "--set-string" {
			continue
		}
		out[i+1] = "router." + out[i+1]
		i++
	}
	return out
}

// containerVolumeMount returns the named volume mount from a container
// (read-only state checked separately by the caller).
func containerVolumeMount(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

func podVolume(spec corev1.PodSpec, name string) (corev1.Volume, bool) {
	for _, v := range spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

// seedEntry finds a seed entry whose containers all carry digest.
func seedEntry(seed *pkgallowlist.Allowlist, digest string) (pkgallowlist.Workload, bool) {
	for _, w := range seed.Workloads {
		// Multi-image entries such as the router's also list the digest.
		if len(w.Containers) > 0 && !slices.ContainsFunc(w.Containers, func(c pkgallowlist.Container) bool { return c.Digest.String() != digest }) {
			return w, true
		}
	}
	return pkgallowlist.Workload{}, false
}

// generatedEntryName is the one entry named prefix plus the chart's
// 8-hex policy hash, or "" when there is not exactly one.
func generatedEntryName(seed *pkgallowlist.Allowlist, prefix string) string {
	var names []string
	for name := range seed.Workloads {
		if rest, ok := strings.CutPrefix(name, prefix+"-"); ok && len(rest) == 8 {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return ""
	}
	return names[0]
}

// seedLabel is the label of the entry admitting digest, or "" when none does.
func seedLabel(seed *pkgallowlist.Allowlist, digest string) string {
	w, _ := seedEntry(seed, digest)
	return w.Label
}

// anyArgvEntryArgs renders one bootstrapAllowlist.workloads entry admitting
// digest under any command, args, and mounts, as `helm --set-string` arguments.
func anyArgvEntryArgs(name, digest, image string) []string {
	p := "nriImagePolicy.bootstrapAllowlist.workloads." + name + "."
	return []string{
		"--set-string", p + "label=" + image,
		"--set-string", p + "containers[0].digest=" + digest,
		"--set-string", p + "containers[0].image=" + image,
		"--set-string", p + "containers[0].command.policy=any",
		"--set-string", p + "containers[0].args.policy=any",
		"--set-string", p + "containers[0].mounts.policy=any",
	}
}

// TestChartSeedsCDSAllowlistFromBootstrapEntries proves a
// bootstrapAllowlist.workloads entry and the CDS image self-entry are rendered
// into CDS's --allowlist-seed ConfigMap, so CDS's served /allowlist is
// non-empty on the first worker pull, and that an entry admitting its digest
// under any argv also reaches every plugin's base allowlist. Decoded with the
// same typed Allowlist shape CDS parses, not substring-matched.
func TestChartSeedsCDSAllowlistFromBootstrapEntries(t *testing.T) {
	t.Parallel()
	const bootDigest = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t, anyArgvEntryArgs("coredns", bootDigest, "ghcr.io/x/coredns:v1")...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	raw, ok := cm.Data["allowlist-seed.json"]
	if !ok {
		t.Fatalf("seed ConfigMap missing allowlist-seed.json key: %v", cm.Data)
	}

	seed, err := pkgallowlist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("seed JSON does not parse as a Allowlist (CDS would fail closed): %v\n%s", err, raw)
	}

	w, ok := seed.Workloads["coredns"]
	if !ok {
		t.Fatalf("seed entry coredns missing\nseed: %v", seed.Workloads)
	}
	if w.Label != "ghcr.io/x/coredns:v1" || len(w.InitContainers) != 0 || len(w.Containers) != 1 {
		t.Errorf("seed entry = %#v, want label ghcr.io/x/coredns:v1 with one main container", w)
	}
	if c := w.Containers[0]; c.Digest.String() != bootDigest || c.Image != "ghcr.io/x/coredns:v1" || !c.AnyArgv() {
		t.Errorf("seed container = %#v, want %s under any command and args", c, bootDigest)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if got := baseImages(worker.Allowlist.Base)[bootDigest]; got != "ghcr.io/x/coredns:v1" {
		t.Errorf("base[%s] = %q, want the entry's image\nbase: %v", bootDigest, got, worker.Allowlist.Base.Workloads)
	}
	// No entry admits the CDS: it runs outside the cluster, and its image is
	// no workload of this one.
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	for _, al := range []pkgallowlist.Allowlist{*seed, worker.Allowlist.Base} {
		for name, entry := range al.Workloads {
			for _, c := range entry.Containers {
				if c.Digest.String() == cdsDigest {
					t.Errorf("entry %s admits the CDS image: %+v", name, c)
				}
			}
		}
	}
}

func TestChartBasePreservesOperatorMountConstraints(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		policy string
		want   pkgallowlist.MountPolicy
	}{
		{"omitted", "", pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}},
		{"deny", pkgallowlist.PolicyDeny, pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}},
		{"exact", pkgallowlist.PolicyExact, pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact, Rules: []pkgallowlist.MountRule{{Destination: "/cache", Kind: pkgallowlist.MountEmptyDir}}}},
	}
	var args []string
	for i, tc := range cases {
		p := "nriImagePolicy.bootstrapAllowlist.workloads." + tc.name + ".containers[0]."
		args = append(args,
			"--set-string", p+"digest="+fmt.Sprintf("sha256:abcdef%058d", i),
			"--set-string", p+"command.policy=any",
			"--set-string", p+"args.policy=any",
		)
		if tc.policy != "" {
			args = append(args, "--set-string", p+"mounts.policy="+tc.policy)
		}
		if tc.policy == pkgallowlist.PolicyExact {
			args = append(args,
				"--set-string", p+"mounts.rules[0].destination=/cache",
				"--set-string", p+"mounts.rules[0].kind=emptyDir",
			)
		}
	}
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	base := baseImages(worker.Allowlist.Base)
	for _, tc := range cases {
		entry, ok := seed.Workloads[tc.name]
		if !ok || len(entry.Containers) != 1 {
			t.Fatalf("operator entry %q missing from served seed", tc.name)
		}
		c := entry.Containers[0]
		if !reflect.DeepEqual(c.Mounts, tc.want) {
			t.Errorf("operator entry %q mount policy = %+v, want %+v", tc.name, c.Mounts, tc.want)
		}
		if _, ok := base[c.Digest.String()]; ok {
			t.Errorf("operator entry %q with constrained mounts entered the boot base", tc.name)
		}
	}
}

// An entry that pins a command line is seed-only: the base allowlist admits
// by digest alone, so it carries only what the seed admits under any command
// and args.
func TestChartBaseSkipsPinnedEntries(t *testing.T) {
	t.Parallel()
	const pinned = "sha256:abcdef0000000000000000000000000000000000000000000000000000000001"
	p := "nriImagePolicy.bootstrapAllowlist.workloads.infer.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", p+"digest="+pinned,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/bin/vllm",
		"--set-string", p+"args.policy=any",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if _, ok := seed.Workloads["infer"]; !ok {
		t.Fatalf("pinned entry missing from the seed: %v", seed.Workloads)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if _, ok := baseImages(worker.Allowlist.Base)[pinned]; ok {
		t.Errorf("a pinned entry's digest reached the base allowlist, where it would be admitted under any argv: %v", worker.Allowlist.Base.Workloads)
	}
}

// The chart derives entry names with the rule pkg/allowlist DigestEntryName
// pins (TestDigestEntryName), tag and digest stripping and the "image"
// fallback included, then appends a policy hash; the image segment is cut to
// 41 bytes so the name stays within 63. Driven through the operator image,
// whose repository the operator sets freely.
func TestChartSeedEntryNamesMatchMigration(t *testing.T) {
	t.Parallel()
	const d = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	for _, tc := range []struct{ repository, want string }{
		{"ghcr.io/x/coredns:v1", "coredns"},
		{"registry:5000/team/app", "app"},
		{"busybox", "busybox"},
		{"ghcr.io/x/not a name!", "image"},
		{"ghcr.io/x/" + strings.Repeat("y", 60), strings.Repeat("y", 41)},
	} {
		t.Run(tc.want, func(t *testing.T) {
			out, err := helmTemplate(t,
				"--set-string", "image.repository="+tc.repository,
				"--set-string", "image.digest="+d,
			)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
			}
			if generatedEntryName(seed, tc.want+"-abcdef000000") == "" {
				t.Errorf("repository %q: entry %q-<policy> missing\nseed: %v", tc.repository, tc.want+"-abcdef000000", seed.Workloads)
			}
		})
	}
}

// The derived name lowercases the digest whatever case the values key used, so
// the chart and pkg/allowlist DigestEntryName agree on it.
func TestChartSeedEntryNameIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	const d = "sha256:ABCDEF0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t, "--set-string", "image.digest="+d)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if generatedEntryName(renderedSeed(t, out), "c8s-operator-abcdef000000") == "" {
		t.Fatalf("seed entry c8s-operator-abcdef000000-<policy> missing\nseed: %v", renderedSeed(t, out).Workloads)
	}
}

// A bootstrapAllowlist.workloads entry sharing a derived entry's name replaces
// it whole in the seed, so an operator can narrow a component's policy without
// the chart re-widening it; the component stays in the base allowlist regardless.
func TestChartSeedWorkloadsOverrideDerivedEntry(t *testing.T) {
	t.Parallel()
	const d = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	p := "nriImagePolicy.bootstrapAllowlist.workloads.c8s-operator-000000000000.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", "image.digest="+d,
		"--set-string", p+"digest="+d,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/c8s",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	w, ok := seed.Workloads["c8s-operator-000000000000"]
	if !ok || len(w.Containers) != 1 {
		t.Fatalf("seed entry = %#v, want one container", w)
	}
	if c := w.Containers[0]; c.Command.Policy != pkgallowlist.PolicyExact || c.Digest.String() != d {
		t.Errorf("operator entry did not win over the derived one: %#v", c)
	}
	if w.Label != "" {
		t.Errorf("derived label leaked into the operator's entry: %q", w.Label)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if _, ok := baseImages(worker.Allowlist.Base)[d]; !ok {
		t.Errorf("narrowing the seed entry dropped the operator from the base allowlist: %v", worker.Allowlist.Base.Workloads)
	}
}

// TestChartDerivesComponentDigestsIntoAllowlist proves that when the C8s
// component images are digest-pinned, each is auto-derived into the NRI
// allowlist seed with a repo@digest reference matching the rendered pod image —
// so a digest-pinned install self-allows the C8s components it deploys.
// nri-image-policy is not in the derive set: the chart seeds it argv-pinned
// (c8s.argvPinnedEntries), which carries the same repo@digest label.
func TestChartDerivesComponentDigestsIntoAllowlist(t *testing.T) {
	t.Parallel()
	const (
		opD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		asD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a2"
		rmD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a4"
		nriD = "sha256:00000000000000000000000000000000000000000000000000000000000000a5"
	)
	out, err := helmTemplate(t,
		"--set-string", "image.digest="+opD,
		"--set-string", "attestationApi.image.digest="+asD,
		"--set-string", "armtlsMesh.image.digest="+rmD,
		"--set-string", "nriImagePolicy.image.digest="+nriD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}

	// Each derived entry's reference must be repo@digest for the image the chart
	// actually deploys.
	want := map[string]string{
		opD:  "ghcr.io/confidential-dot-ai/c8s-operator@" + opD,
		asD:  "ghcr.io/confidential-dot-ai/attestation-api@" + asD,
		rmD:  "ghcr.io/confidential-dot-ai/armtls-mesh@" + rmD,
		nriD: "ghcr.io/confidential-dot-ai/nri-image-policy@" + nriD,
	}
	for digest, ref := range want {
		if got := seedLabel(seed, digest); got != ref {
			t.Errorf("derived entry %s = %q, want %q\nseed: %v", digest, got, ref, seed.Workloads)
		}
	}

	// The same derived base must reach the worker plugin's base,
	// decoded as typed config (not substring-matched). The nri digest
	// reaches it under the host sweep's argv pin alone.
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	for digest, ref := range want {
		if got := baseImages(worker.Allowlist.Base)[digest]; got != ref {
			t.Errorf("worker base[%s] = %q, want %q\nfloor: %v", digest, got, ref, baseImages(worker.Allowlist.Base))
		}
	}
}

// The router nginx image is a chart-deployed non-c8s system image: it is not in
// the tag-locked component derive set, so the chart self-seeds it from its
// pinned digest or the NRI plugin would reject the router nginx container.
func TestChartAllowlistsRouterNginxSelfEntry(t *testing.T) {
	t.Parallel()
	nxDigest := chartImageDigest(t, componentsFile, "routerNginx", "image", "digest")
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v", err)
	}
	if got, want := seedLabel(seed, nxDigest), "nginxinc/nginx-unprivileged@"+nxDigest; got != want {
		t.Errorf("router nginx self-entry = %q, want %q\nseed: %v", got, want, seed.Workloads)
	}
}

// volumed runs its own image, so like every other component its digest must be
// derived into the NRI base when it is enabled — otherwise the plugin denies
// the daemon's own container (the failure mode observed in testing). It must be
// absent when volumed is off (the default), so a plain install neither resolves
// nor allowlists an image it does not deploy.
func TestChartDerivesVolumedImageIntoFloor(t *testing.T) {
	t.Parallel()
	const volD = "sha256:00000000000000000000000000000000000000000000000000000000000000d1"

	t.Run("enabled: digest in the base", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set", "volumed.enabled=true",
			"--set-string", "volumed.image.digest="+volD,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seedEntry(seed, volD); !ok {
			t.Errorf("volumed digest not derived into the base; the plugin would deny volumed's own image\nseed: %v", seed.Workloads)
		}
	})

	t.Run("disabled: digest absent", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set-string", "volumed.image.digest="+volD,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seedEntry(seed, volD); ok {
			t.Errorf("volumed digest derived into the base while volumed is disabled: %v", seed.Workloads)
		}
	})
}

// The volumed image entrypoint is ["/app/c8s", "volumed"], so the DaemonSet's
// args must NOT repeat the subcommand. Shipping it once produced
// `unknown command "volumed" for "c8s volumed"` and a CrashLoopBackOff daemon
// that no chart test caught, because nothing asserted on the invocation.
func TestChartComponentArgsDoNotRepeatTheEntrypointSubcommand(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		"--set", "volumed.enabled=true",
		"--set-string", "volumed.image.tag=dev",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		forbid string
	}{
		{"volumed", renderedDaemonSetContainer(t, out, "c8s-volumed", "volumed").Args, "volumed"},
	} {
		if len(tc.args) == 0 {
			t.Errorf("%s: no args rendered", tc.name)
			continue
		}
		if tc.args[0] == tc.forbid {
			t.Errorf("%s: args start with %q, but the image entrypoint already supplies it; the container would run `c8s %s %s ...` and exit",
				tc.name, tc.forbid, tc.forbid, tc.forbid)
		}
		if !strings.HasPrefix(tc.args[0], "-") {
			t.Errorf("%s: first arg %q is not a flag; args must begin where the entrypoint leaves off", tc.name, tc.args[0])
		}
	}
}

// installerBootConfig is a typed view of the image-policy.yaml the installer
// writes. It mirrors the fields of the plugin's own config
// (internal/cmds/nri-image-policy/config.go, which is unexported) needed by the
// chart tests, so assertions are against typed fields rather than substrings.
type installerBootConfig struct {
	Allowlist struct {
		Base pkgallowlist.Allowlist `yaml:"base"`
		Pull struct {
			URL                   string `yaml:"url"`
			CDSAddressFile        string `yaml:"cds_address_file"`
			CDSMeasurementsConfig string `yaml:"cds_measurements_config"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
	Policy struct {
		Mode               string   `yaml:"mode"`
		ExemptNamespaces   []string `yaml:"exempt_namespaces"`
		ExemptSnapshotPath string   `yaml:"exempt_snapshot_path"`
	} `yaml:"policy"`
	Containerd struct {
		Socket string `yaml:"socket"`
	} `yaml:"containerd"`
}

// baseImages indexes a boot config's base allowlist by digest: digest ->
// the entry's image reference.
func baseImages(f pkgallowlist.Allowlist) map[string]string {
	out := map[string]string{}
	for _, w := range f.Workloads {
		for _, c := range append(w.InitContainers, w.Containers...) {
			out[c.Digest.String()] = c.Image
		}
	}
	return out
}

// bootConfigHeredocRE captures the image-policy.yaml body the installer writes
// via a `write_file ... <<'IMAGE_POLICY_EOF' ... IMAGE_POLICY_EOF` heredoc.
var bootConfigHeredocRE = regexp.MustCompile(`(?s)<<'IMAGE_POLICY_EOF'\n(.*?)\nIMAGE_POLICY_EOF`)

// bootConfigFromInstaller decodes the image-policy.yaml an installer DaemonSet
// writes into a typed installerBootConfig. It uses gopkg.in/yaml.v3 — the same
// library the plugin's loadConfig uses — which (unlike sigs.k8s.io/yaml's JSON
// path) rejects the duplicate mapping keys that would crash the plugin at
// startup. (KnownFields is intentionally NOT set: the goal is duplicate-key
// detection plus typed field access, not mirroring the plugin's full schema.)
func bootConfigFromInstaller(t *testing.T, manifest, dsName string) installerBootConfig {
	t.Helper()
	body := bootConfigYAML(t, manifest, dsName)
	var cfg installerBootConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("plugin would reject its boot config for %s (yaml.v3): %v\n%s", dsName, err, body)
	}
	if err := cfg.Allowlist.Base.Normalize(); err != nil {
		t.Fatalf("boot config base allowlist for %s does not validate the way the plugin's loader would: %v\n%s", dsName, err, body)
	}
	return cfg
}

// bootConfigYAML is the image-policy.yaml body an installer DaemonSet's
// install script writes to the node.
func bootConfigYAML(t *testing.T, manifest, dsName string) []byte {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, dsName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	m := bootConfigHeredocRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("install script for %s has no IMAGE_POLICY_EOF heredoc\n%s", dsName, script)
	}
	return []byte(m[1])
}

// TestChartBootConfigParsesAsPluginYAML decodes each archetype's boot config
// exactly as the plugin does (yaml.v3 rejects duplicate keys, so a malformed
// render would crash-loop it) and validates the base allowlist the way the
// plugin's loader does, then asserts the archetype-specific mode.
func TestChartBootConfigParsesAsPluginYAML(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		// deriveComponents on (and a second component digest) so the installer
		// image reaches the base allowlist both explicitly and via derivation.
		"--set-string", "image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000c5",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The single installer is pull-mode: it names the CDS it pulls from and
	// never a push block. Asserting both confirms the typed decode landed on
	// the boot config document, not just that some YAML parsed.
	if wl := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist; wl.Pull.CDSAddressFile == "" || wl.Push.PersistPath != "" {
		t.Errorf("worker boot config should configure pull, not push: pull.cds_address_file=%q push.persist_path=%q", wl.Pull.CDSAddressFile, wl.Push.PersistPath)
	}
}

// With exemptNamespaces cleared the rendered worker boot config admits by the
// digest base alone: policy.exempt_namespaces is empty, and so is the
// snapshot path that comes with it. The mesh policy's own exempt list is a
// different key, so this reads the decoded values. The exempting render is
// covered below.
func TestChartBootConfigExemptsNoNamespaceFromImageAdmission(t *testing.T) {
	out, err := helmTemplate(t, "--set-json", "nriImagePolicy.policy.exemptNamespaces=[]")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if len(cfg.Policy.ExemptNamespaces) != 0 || cfg.Policy.ExemptSnapshotPath != "" {
		t.Errorf("worker boot config exempts %v from image admission, with snapshot %q",
			cfg.Policy.ExemptNamespaces, cfg.Policy.ExemptSnapshotPath)
	}
}

// Setting nriImagePolicy.policy.exemptNamespaces renders the exempt_namespaces
// list, a snapshot path under the cache dir, and the install-time rm that
// re-captures on a boot config rewrite. Decoding through yaml.v3 also proves
// the block does not collide with the rest of the boot config.
func TestChartBootConfigRendersExemptNamespaces(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,gatekeeper-system}",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if got := cfg.Policy.ExemptNamespaces; !slices.Equal(got, []string{"kube-system", "gatekeeper-system"}) {
		t.Errorf("exempt_namespaces = %v, want [kube-system gatekeeper-system]", got)
	}
	if !strings.HasSuffix(cfg.Policy.ExemptSnapshotPath, "/exempt-snapshot.json") {
		t.Errorf("exempt_snapshot_path = %q, want a .../exempt-snapshot.json path", cfg.Policy.ExemptSnapshotPath)
	}

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "rm -f") || !strings.Contains(script, "exempt-snapshot.json") {
		t.Error("install script must delete the exempt snapshot on a boot config change so it re-captures")
	}
}

// Every boot config this chart can render must load in the plugin that reads
// it: the plugin refuses a policy-exempt namespace the mesh gate does not
// exempt too, so an exemption the installer advises must survive its own
// validation rather than exit the plugin 41 ms after containerd starts it.
func TestChartBootConfigLoadsInThePlugin(t *testing.T) {
	t.Parallel()
	for _, platform := range cloudPlatforms {
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			out, err := helmTemplatePlatform(t, platform)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			body := bootConfigAsStagedOnANode(t, bootConfigYAML(t, out, "c8s-nri-image-policy-worker"))
			if err := nriimagepolicy.CheckBootConfig(body); err != nil {
				t.Errorf("plugin refuses the %s boot config: %v\n%s", platform, err, body)
			}
		})
	}

	t.Run("exempting the router namespace", func(t *testing.T) {
		t.Parallel()
		out, err := helmTemplatePlatform(t, "gke-snp",
			"--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,"+workloadclaims.RouterNamespace+"}",
		)
		if err == nil {
			t.Fatalf("chart rendered a config the plugin refuses at start\n%s", out)
		}
		if !strings.Contains(out, "whose pods serve the router's ports") {
			t.Errorf("render failed without naming the router's pods: %s", out)
		}
	})
}

// nodeCDSAddressFile is where the installer stages this cluster's CDS address
// beside the boot config.
const nodeCDSAddressFile = "/etc/nri/conf.d/cds-address"

// bootConfigAsStagedOnANode points the boot config at a CDS address file
// holding what the installer mounts from the measurements ConfigMap, which is
// the one input the plugin reads from the node rather than the config.
func bootConfigAsStagedOnANode(t *testing.T, body []byte) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-address")
	if err := os.WriteFile(path, []byte(baseCDSAddress), 0o600); err != nil {
		t.Fatalf("stage the CDS address file: %v", err)
	}
	staged := strings.Replace(string(body), nodeCDSAddressFile, path, 1)
	if staged == string(body) {
		t.Fatalf("boot config names no %s\n%s", nodeCDSAddressFile, body)
	}
	return []byte(staged)
}

// criticalPriorityPod is a rendered pod template that asks for the critical
// priority class, with the namespace it is created in.
type criticalPriorityPod struct {
	object    string
	namespace string
}

// criticalPriorityClass is the one critical class the chart renders
// (c8s.criticalPriorityClass).
const criticalPriorityClass = "system-node-critical"

// criticalPriorityPods lists the release's pod templates that ask for the
// critical priority class.
func criticalPriorityPods(t *testing.T, helmOut string) []criticalPriorityPod {
	t.Helper()
	var pods []criticalPriorityPod
	iterateManifests(t, helmOut, func(doc []byte) (stop bool) {
		var obj struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			t.Fatalf("decode manifest: %v\n%s", err, doc)
		}
		if obj.Spec.Template.Spec.PriorityClassName != criticalPriorityClass {
			return false
		}
		pods = append(pods, criticalPriorityPod{
			object:    obj.Kind + "/" + obj.Metadata.Name,
			namespace: obj.Metadata.Namespace,
		})
		return false
	})
	return pods
}

// capsPods reports whether q limits the number of pods.
func capsPods(q corev1.ResourceQuota) bool {
	_, capped := q.Spec.Hard[corev1.ResourcePods]
	return capped
}

// scopesToPriorityClass reports whether q counts the pods of class and no
// others.
func scopesToPriorityClass(q corev1.ResourceQuota, class string) bool {
	if q.Spec.ScopeSelector == nil {
		return false
	}
	for _, expr := range q.Spec.ScopeSelector.MatchExpressions {
		if expr.ScopeName == corev1.ResourceQuotaScopePriorityClass &&
			expr.Operator == corev1.ScopeSelectorOpIn &&
			slices.Contains(expr.Values, class) {
			return true
		}
	}
	return false
}

// renderedResourceQuotas decodes every ResourceQuota in a render.
func renderedResourceQuotas(t *testing.T, helmOut string) []corev1.ResourceQuota {
	t.Helper()
	var quotas []corev1.ResourceQuota
	iterateManifests(t, helmOut, func(doc []byte) (stop bool) {
		var meta docMeta
		if err := sigsyaml.Unmarshal(doc, &meta); err != nil {
			t.Fatalf("decode manifest: %v\n%s", err, doc)
		}
		if meta.Kind != "ResourceQuota" {
			return false
		}
		var q corev1.ResourceQuota
		if err := sigsyaml.Unmarshal(doc, &q); err != nil {
			t.Fatalf("decode ResourceQuota %s: %v\n%s", meta.Metadata.Name, err, doc)
		}
		quotas = append(quotas, q)
		return false
	})
	return quotas
}

// GKE rejects a critical-priority pod in a namespace whose quotas do not cover
// its PriorityClass, so every critical pod the chart renders needs a quota of
// that scope in the release namespace — or its DaemonSet stays at zero and the
// node is left without the agent that gates its images.
func TestChartCriticalPriorityPodsAreCoveredByAQuota(t *testing.T) {
	t.Parallel()
	wantPods := []string{
		"DaemonSet/c8s-nri-image-policy-worker",
		"DaemonSet/c8s-volumed",
	}
	for _, platform := range cloudPlatforms {
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			out, err := helmTemplatePlatform(t, platform, "--set", "volumed.enabled=true")
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			pods := criticalPriorityPods(t, out)
			var objects []string
			for _, pod := range pods {
				objects = append(objects, pod.object)
				if pod.namespace != "c8s-system" {
					t.Errorf("%s is created in %s, which the release namespace's quota does not cover", pod.object, pod.namespace)
				}
			}
			slices.Sort(objects)
			if !slices.Equal(objects, wantPods) {
				t.Errorf("critical-priority pod templates = %v, want %v", objects, wantPods)
			}
			quotas := renderedResourceQuotas(t, out)
			covered := slices.ContainsFunc(quotas, func(q corev1.ResourceQuota) bool {
				return q.Namespace == "c8s-system" && capsPods(q) && scopesToPriorityClass(q, criticalPriorityClass)
			})
			if !covered {
				t.Errorf("no rendered ResourceQuota admits %s in c8s-system", criticalPriorityClass)
			}
		})
	}
}

// projectedConfigMap is the ConfigMap a component volume projects, or "". The
// chart projects its ConfigMaps so they sit on tmpfs, which the component
// entries' data rules admit on any node.
func projectedConfigMap(v corev1.Volume) string {
	if v.Projected == nil || len(v.Projected.Sources) != 1 || v.Projected.Sources[0].ConfigMap == nil {
		return ""
	}
	return v.Projected.Sources[0].ConfigMap.Name
}

// The nri-image-policy component is exempt from the uncovered-component guard:
// the chart seeds it argv-pinned (c8s.argvPinnedEntries), so it never needs a
// bootstrapAllowlist.digests entry — and must not get one that holds (a
// same-named workloads entry is the override path).
func TestChartNriComponentCoveredByArgvPin(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", "nriImagePolicy.image.digest=sha256:bbbb000000000000000000000000000000000000000000000000000000000000",
	)
	if err != nil {
		t.Fatalf("nri digest without a base entry must render (argv-pinned): %v\n%s", err, out)
	}
}

// --- install-time image pull secret (imagePullSecret, a Secret name) ---

// pullSecretNames flattens an imagePullSecrets list to the referenced names.
func pullSecretNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return names
}

// The invariant the value exists for: every pod the default chart ships can
// authenticate its image pull from first start — either its pod spec lists the
// install-time Secret or its ServiceAccount does (kubelet merges both). And
// the chart must not render a Secret of its own: the named Secret pre-exists
// (kubectl / external-secrets), and helm cannot adopt an object it does not
// own, so rendering one would abort the install.
func TestChartImagePullSecretReachesEveryPodSpecWithoutCreatingASecret(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set-string", "imagePullSecret=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const secretName = "ghcr-secret"

	if kinds := renderedKinds(t, out); kinds["Secret"] > 0 {
		t.Errorf("imagePullSecret mode rendered %d Secret(s), want 0 (the Secret pre-exists)", kinds["Secret"])
	}

	sasWithSecret := map[string]bool{}
	iterateManifests(t, out, func(doc []byte) bool {
		var sa corev1.ServiceAccount
		if err := sigsyaml.Unmarshal(doc, &sa); err != nil || sa.Kind != "ServiceAccount" {
			return false
		}
		if slices.Contains(pullSecretNames(sa.ImagePullSecrets), secretName) {
			sasWithSecret[sa.Name] = true
		}
		return false
	})

	type workload struct {
		kind, name string
		spec       corev1.PodSpec
	}
	var workloads []workload
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "Job":
			workloads = append(workloads, workload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	// The pod-bearing workloads of a default render, so a decode that misses
	// one cannot leave the loop below passing vacuously.
	want := []string{
		"DaemonSet/c8s-attestation-api",
		"DaemonSet/c8s-nri-image-policy-worker",
		"Deployment/c8s-operator",
		"Deployment/c8s-router",
	}
	var decoded []string
	for _, w := range workloads {
		decoded = append(decoded, w.kind+"/"+w.name)
	}
	slices.Sort(decoded)
	if !slices.Equal(decoded, want) {
		t.Fatalf("decoded pod-bearing workloads = %v, want %v", decoded, want)
	}

	for _, w := range workloads {
		if slices.Contains(pullSecretNames(w.spec.ImagePullSecrets), secretName) {
			continue
		}
		if sasWithSecret[w.spec.ServiceAccountName] {
			continue
		}
		t.Errorf("%s %q can't reach the pull secret: pod spec lists %v, serviceAccount %q",
			w.kind, w.name, pullSecretNames(w.spec.ImagePullSecrets), w.spec.ServiceAccountName)
	}
}

// An operator who also lists the install-time Secret explicitly in the
// chart-wide imagePullSecrets must not get a duplicate entry.
func TestChartImagePullSecretDedupsExplicitReference(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set", "imagePullSecrets[0].name=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	installer := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	names := pullSecretNames(installer.Spec.Template.Spec.ImagePullSecrets)
	want := []string{"ghcr-secret"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("nri-image-policy installer imagePullSecrets = %v, want %v (no duplicate)", names, want)
	}
}

// Without imagePullSecret (and with the imagePullSecrets lists empty), no
// manifest may carry an imagePullSecrets block at all — the with-guard in the
// c8s.imagePullSecrets helper must keep suppressing empty lists.
func TestChartDefaultRendersNoPullSecretRefs(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	iterateManifests(t, out, func(doc []byte) bool {
		var raw map[string]any
		if err := yaml.Unmarshal(doc, &raw); err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		if path := findKey(raw, "imagePullSecrets"); path != "" {
			var meta docMeta
			_ = sigsyaml.Unmarshal(doc, &meta)
			t.Errorf("default render carries an imagePullSecrets block: %s %s at %s", meta.Kind, meta.Metadata.Name, path)
		}
		return false
	})
}

// TestAttestationApiSeccomp pins the seccomp profile on the attestation-api
// container. It must run privileged (device-cgroup access to the TEE device),
// but seccomp is independent of privileged and RuntimeDefault narrows the
// syscall surface of the node's widest container; it is easy to drop silently.
func TestAttestationApiSeccomp(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-attestation-api")
	c, ok := findContainer(ds.Spec.Template.Spec.Containers, "attestation-api")
	if !ok {
		t.Fatalf("attestation-api container not found; got %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged (TEE device access); got %+v", sc)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("attestation-api must set seccompProfile.type: RuntimeDefault; got %+v", sc.SeccompProfile)
	}
}

// The injected credential clients read the node's CDS policy from the mount
// the enforcer gives them, so the operator renders no pins into their args: a
// pin the control plane could pass is a pin the control plane could choose.
// This asserts the chart end of that rule.
func TestChartOperatorPassesNoCDSPins(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := strings.Join(renderedDeploymentContainer(t, out, "c8s-operator", "operator").Args, " ")
	for _, unwanted := range []string{"--cds-measurements", "--cds-rtmrs", "--image-policy-file", "--image-policy-json"} {
		if strings.Contains(args, unwanted) {
			t.Errorf("operator carries %s; the injected clients read the node policy instead: %s", unwanted, args)
		}
	}
}

// volumed is off by default: it runs privileged with hostPID and a writable
// bind of the kubelet directory, and nothing needs it until a workload
// consumes a volume.
func TestChartVolumedOffByDefault(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-volumed") {
		t.Error("volumed DaemonSet rendered without volumed.enabled")
	}
}

// The privileges the daemon cannot work without: hostPID so SO_PEERCRED
// resolves a caller in another pod's namespace to a real PID, privileged plus
// Bidirectional propagation so the mount it makes reaches the workload's pod
// directory, and the device and cgroup trees it reads.
func TestChartVolumedDaemonSetShape(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-volumed")
	spec := ds.Spec.Template.Spec

	if !spec.HostPID {
		t.Error("hostPID is off; a peer in another pod's PID namespace resolves to PID 0")
	}
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("volumed mounts an API token it has no use for")
	}

	c, ok := findContainer(spec.Containers, "volumed")
	if !ok {
		t.Fatalf("volumed container missing; have %v", containerNames(spec.Containers))
	}
	// volumed runs its own debian-slim image carrying cryptsetup/veritysetup,
	// NOT the distroless operator image (which has neither, so every open
	// would fail with "executable file not found").
	if !strings.Contains(c.Image, "/volumed") {
		t.Errorf("volumed image = %q, want its own /volumed image (not the operator image)", c.Image)
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Error("volumed is not privileged; device-mapper and mount(2) need it")
	}
	// The image is nonroot (USER 65532) and privileged grants no effective
	// caps to a non-root process: without runAsUser 0 the daemon cannot even
	// bind its socket.
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Error("volumed must set runAsUser: 0; the nonroot image user has no effective capabilities")
	}
	// RuntimeDefault seccomp blocks mount(2), so the daemon must not carry one.
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		t.Errorf("seccomp profile %v would block mount(2)", c.SecurityContext.SeccompProfile.Type)
	}

	kubelet, ok := containerVolumeMount(c, "kubelet-root")
	if !ok {
		t.Fatal("no kubelet-root mount; there is nowhere to mount a volume")
	}
	if kubelet.MountPropagation == nil {
		t.Error("kubelet-root sets no mount propagation; the mount would not reach the pod")
	} else if *kubelet.MountPropagation != corev1.MountPropagationBidirectional {
		t.Errorf("kubelet-root propagation = %s, want Bidirectional; the mount would not reach the pod", *kubelet.MountPropagation)
	}
	if kubelet.ReadOnly {
		t.Error("kubelet-root is read-only; the daemon mounts into it")
	}

	for _, name := range []string{"dev", "sys", "cgroup", "inventory-socket-dir"} {
		if _, ok := containerVolumeMount(c, name); !ok {
			t.Errorf("missing %s mount", name)
		}
		if _, ok := podVolume(spec, name); !ok {
			t.Errorf("missing %s volume", name)
		}
	}
	// /sys whole rather than /sys/block: the block entries are symlinks into
	// /sys/devices, and the volume's serial is read through them.
	if v, ok := podVolume(spec, "sys"); ok && (v.HostPath == nil || v.HostPath.Path != "/sys") {
		t.Errorf("sys volume = %+v, want a hostPath of /sys", v.HostPath)
	}
}

// The daemon's socket has to land in the inventory's socket directory — the
// one nri-image-policy NRI-mounts into cw-pod sidecars, which the operator
// names via --workload-claims-host-dir. A daemon serving anywhere else is a
// daemon no confidential pod can reach. And the directory must not surface in
// the VAP: the pod spec carries no hostPath, so a carve-out would only reopen
// tenant access to the node filesystem.
func TestChartVolumedSocketDirTracksTheInventoryDir(t *testing.T) {
	t.Parallel()
	const runtimeDir = "/run/nri-image-policy"
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	c, ok := findContainer(renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec.Containers, "volumed")
	if !ok {
		t.Fatal("volumed container missing")
	}
	if got := argAfter(c.Args, "--socket-dir"); got != runtimeDir {
		t.Errorf("--socket-dir = %q, want the inventory socket dir %q", got, runtimeDir)
	}
	operator := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	if !slices.Contains(operator.Args, "--workload-claims-host-dir="+runtimeDir) {
		t.Errorf("operator args %v missing --workload-claims-host-dir=%s", operator.Args, runtimeDir)
	}

	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &vap) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, strconv.Quote(runtimeDir)) {
			t.Errorf("the VAP names the socket dir %s; hostPath must be denied without carve-outs, expression=%q", runtimeDir, v.Expression)
		}
	}
}

// volumed resolves pod volume directories beneath the kubelet root, so the
// rendered arg, mount, and hostPath must agree.
func TestChartVolumedKubeletRoot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "/var/lib/kubelet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--set", "volumed.enabled=true"}, tc.args...)
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			spec := renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec
			c, ok := findContainer(spec.Containers, "volumed")
			if !ok {
				t.Fatal("volumed container missing")
			}
			if got := argAfter(c.Args, "--kubelet-root"); got != tc.want {
				t.Errorf("--kubelet-root = %q, want %q", got, tc.want)
			}
			mount, ok := containerVolumeMount(c, "kubelet-root")
			if !ok {
				t.Fatal("no kubelet-root mount")
			}
			if mount.MountPath != tc.want {
				t.Errorf("kubelet-root mountPath = %q, want %q", mount.MountPath, tc.want)
			}
			v, ok := podVolume(spec, "kubelet-root")
			if !ok || v.HostPath == nil {
				t.Fatal("no kubelet-root hostPath volume")
			}
			if v.HostPath.Path != tc.want {
				t.Errorf("kubelet-root hostPath = %q, want %q", v.HostPath.Path, tc.want)
			}
		})
	}
}

// argAfter returns the value following flag in an argv, or "" if absent.
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// The sidecar reaches volumed through the directory the webhook mounts into cw
// pods, which the operator learns from --workload-claims-host-dir. If the two
// templates ever disagree the socket is simply not there, and every
// volume-consuming pod hangs waiting for a mount.
func TestChartVolumedAndWebhookAgreeOnTheSocketDir(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	daemon, ok := findContainer(renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec.Containers, "volumed")
	if !ok {
		t.Fatal("volumed container missing")
	}
	socketDir := argAfter(daemon.Args, "--socket-dir")
	if socketDir == "" {
		t.Fatal("volumed has no --socket-dir")
	}

	operator := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	var hostDir string
	for _, a := range operator.Args {
		if v, ok := strings.CutPrefix(a, "--workload-claims-host-dir="); ok {
			hostDir = v
		}
	}
	if hostDir != socketDir {
		t.Errorf("the operator mounts %q into cw pods but volumed serves in %q", hostDir, socketDir)
	}
}

// schemaCoveredPaths are the values subtrees values.schema.json seals: the
// component blocks the docs tell operators to write by hand.
var schemaCoveredPaths = []string{"cds", "nriImagePolicy", "router", "volumed"}

// readChartFile decodes a file of a chart directory. JSON is a subset of
// YAML, so one decoder serves values.yaml and values.schema.json alike.
func readChartFile(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// Helm accepts values a chart never reads, so a misspelled key under a
// documented path is applied, silently dropped at render, and shows up only as
// whatever the un-applied value was protecting against. The schema turns that
// into a render-time error naming the key.
func TestChartValuesSchemaRejectsUnknownKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		set  string
	}{
		// The singular of the key whose loss bricked a cluster.
		{"nriImagePolicy.policy", "nriImagePolicy.policy.exemptNamespace=kube-system"},
		{"nriImagePolicy top level", "nriImagePolicy.exemptNamespaces=kube-system"},
		// A values file from a release that still had these keys.
		{"router.hostPort", "router.hostPort=true"},
		{"router.routing", "router.routing.prot=9900"},
		{"cds", "cds.addresss=10.9.9.9:8443"},
		{"volumed", "volumed.enable=true"},
		// The control-plane chart's own schema, through the cloud chart.
		{"controlPlane.webhook", "controlPlane.webhook.extraExclude=tenant-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, _, _ := strings.Cut(tc.set, "=")
			out, err := helmTemplate(t, "--set", tc.set)
			if err == nil {
				t.Fatalf("helm template accepted the unknown key %s\n%s", key, out)
			}
			// Helm's wording for the same rejection differs by version
			// ("Additional property X is not allowed" vs "additional
			// properties 'X' not allowed"), so match on the shared stem.
			unknown := key[strings.LastIndexByte(key, '.')+1:]
			if !strings.Contains(strings.ToLower(out), "additional propert") || !strings.Contains(out, unknown) {
				t.Errorf("render failure does not name the unknown key %q:\n%s", unknown, out)
			}
		})
	}
}

// The schema is only as good as its coverage: a key added to values.yaml but
// not to the schema makes every render of the chart fail on its own default.
// This is the lockstep guard, checked against the chart's own values.
func TestChartValuesSchemaCoversValuesYAML(t *testing.T) {
	t.Parallel()
	assertChartSchemaCovers(t, cloudChartDir, schemaCoveredPaths)
}

// assertChartSchemaCovers walks each covered subtree of a chart's values.yaml
// against its values.schema.json.
func assertChartSchemaCovers(t *testing.T, chart string, covered []string) {
	t.Helper()
	var values map[string]any
	readChartFile(t, filepath.Join(chart, "values.yaml"), &values)
	var schema struct {
		Properties map[string]any `yaml:"properties"`
	}
	readChartFile(t, filepath.Join(chart, "values.schema.json"), &schema)

	for _, top := range covered {
		node, ok := schema.Properties[top]
		if !ok {
			t.Errorf("values.schema.json does not cover %s", top)
			continue
		}
		assertSchemaCovers(t, values[top], node, top)
	}
}

// assertSchemaCovers walks a values subtree against its schema node: every key
// of a sealed object (one carrying "properties") must be declared, and the
// walk continues into each. A node with no "properties" is deliberately open —
// a label map, a digest map, a resources block — and ends the walk.
func assertSchemaCovers(t *testing.T, values, node any, path string) {
	t.Helper()
	schema, ok := node.(map[string]any)
	if !ok {
		t.Errorf("%s: schema node is not an object (%T)", path, node)
		return
	}
	props, sealed := schema["properties"].(map[string]any)
	if !sealed {
		return
	}
	if blocked, ok := schema["additionalProperties"].(bool); !ok || blocked {
		t.Errorf("%s: declares properties but does not set additionalProperties: false, so a typo still passes", path)
	}
	m, ok := values.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		child, ok := props[k]
		if !ok {
			t.Errorf("values.yaml sets %s.%s but values.schema.json does not declare it; every render would fail", path, k)
			continue
		}
		assertSchemaCovers(t, v, child, path+"."+k)
	}
}

// The pod's route authority runs as the upstream role's reserved identity: the
// one identity of this pod the node leaves uncaptured into the cluster,
// because it authenticates the member it reaches itself. The front door, which
// forwards application requests, holds the router role's.
func TestChartRouterRunsTheRouteAuthorityAsTheRoutingIdentity(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	if got := attest.SecurityContext.RunAsUser; got == nil || *got != int64(workloadclaims.UpstreamUID) {
		t.Errorf("cds-attest runAsUser = %v, want the upstream role's uid %d", got, workloadclaims.UpstreamUID)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if got := nginx.SecurityContext.RunAsUser; got == nil || *got != int64(workloadclaims.RouterUID) {
		t.Errorf("nginx runAsUser = %v, want the router role's uid %d", got, workloadclaims.RouterUID)
	}
}

// The chart renders the router pod itself, and every pod of the router role's
// namespace holds platform-role containers only. So each of its containers
// must take a role from the node's measured base, which pins the argv — and
// for the endpoint the mounts — it grants.
func TestChartRouterPodTakesTheMeasuredRoles(t *testing.T) {
	const (
		meshDigest     = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000001"
		operatorDigest = "sha256:" + "bb00000000000000000000000000000000000000000000000000000000000002"
	)
	nginxDigest := chartImageDigest(t, componentsFile, "routerNginx", "image", "digest")
	measured := measuredBaseAllowlist(t, map[string]string{
		"@MESH_DIGEST@":     meshDigest,
		"@OPERATOR_DIGEST@": operatorDigest,
		"@ROUTER_DIGEST@":   nginxDigest,
	}).BuildIndex()
	wantRoles := map[string]string{
		"c8s-mesh":        "mesh",
		"c8s-cert":        "credentials",
		"c8s-cert-wait":   "credentials",
		"allowlist-proxy": "credentials",
		"nginx":           "router",
		"cds-attest":      "upstream",
		"acme":            "acme",
	}
	// The measured base is the worker's, whose launch file carries the
	// front-door mode, so one render covers both: the acme sidecar is there
	// either way and the pinned argv names the configuration directory that
	// node measures (router.configDir).
	args := []string{
		"--set-string", "armtlsMesh.image.digest=" + meshDigest,
		"--set-string", "image.digest=" + operatorDigest,
	}
	out, err := helmTemplateWorker(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	pins := componentPins(t, out, args)
	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	for _, container := range append(slices.Clone(pod.InitContainers), pod.Containers...) {
		want, held := wantRoles[container.Name]
		if !held {
			t.Errorf("router container %q holds no platform role, so the enforcer refuses the pod", container.Name)
			continue
		}
		launch := renderedLaunch(t, pod, container, pins[digestOf(container.Image)])
		if got := measured.RoleOf(launch); got != want {
			t.Errorf("the measured base grants %s the role %q, want %q", container.Name, got, want)
		}
	}
	// The front door's entry admits no arguments at all, so the container
	// must pass none (image-policy.yaml.in, args: deny).
	if got := renderedDeploymentContainer(t, out, "c8s-router", "nginx").Args; len(got) != 0 {
		t.Errorf("nginx runs with arguments %v, which its measured entry denies", got)
	}
}

// The enforcer admits no container of a member pod until the pod's own mesh
// endpoint has started, so the endpoint leads: the first entry of
// initContainers, a native sidecar whose startup probe holds every later
// container back.
func TestChartRouterPodStartsTheMeshEndpointFirst(t *testing.T) {
	for name, render := range map[string]func(t *testing.T, args ...string) (string, error){
		"cds front door":    helmTemplate,
		"worker front door": helmTemplateWorker,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
			names := containerNames(append(slices.Clone(pod.InitContainers), pod.Containers...))
			if len(names) == 0 || names[0] != "c8s-mesh" {
				t.Fatalf("the router's containers run in the order %v, want the mesh endpoint before every other one", names)
			}
			endpoint := pod.InitContainers[0]
			if endpoint.RestartPolicy == nil || *endpoint.RestartPolicy != corev1.ContainerRestartPolicyAlways {
				t.Error("the mesh endpoint is no native sidecar, so the containers behind it do not wait for its start")
			}
			if endpoint.StartupProbe == nil {
				t.Error("the mesh endpoint carries no startup probe, so the next container starts before it serves")
			}
		})
	}
}

// measuredBaseAllowlist is the node image's measured base, with the digests
// mkosi.sync substitutes at build time.
func measuredBaseAllowlist(t *testing.T, digests map[string]string) *pkgallowlist.Allowlist {
	t.Helper()
	body, err := os.ReadFile("../../images/node-guest/worker/image-policy.yaml.in")
	if err != nil {
		t.Fatalf("read the measured base: %v", err)
	}
	rendered := string(body)
	for placeholder, digest := range digests {
		rendered = strings.ReplaceAll(rendered, placeholder, digest)
	}
	var doc struct {
		Allowlist struct {
			Base pkgallowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("parse the measured base: %v", err)
	}
	return &doc.Allowlist.Base
}

// podVolumeSource is the host source the kubelet gives a pod volume.
func podVolumeSource(volume string) string {
	return "/var/lib/kubelet/pods/5a1d-pod/volumes/kubernetes.io~empty-dir/" + volume
}

func digestOf(image string) string {
	_, digest, _ := strings.Cut(image, "@")
	return digest
}

// The measured image bakes its own pull interval. A drift from the chart's
// surfaces only as a policy change that bites later than the chart says.
func TestChartRefreshIntervalMatchesTheBakedNRIPull(t *testing.T) {
	t.Parallel()
	const bakedPath = "../../images/node-guest/worker/image-policy.yaml.in"
	baked, err := os.ReadFile(bakedPath)
	if err != nil {
		t.Fatalf("read %s: %v", bakedPath, err)
	}
	m := regexp.MustCompile(`(?m)^\s*interval:\s*"([^"]+)"`).FindSubmatch(baked)
	if m == nil {
		t.Fatalf("%s carries no allowlist pull interval", bakedPath)
	}
	want, err := time.ParseDuration(string(m[1]))
	if err != nil {
		t.Fatalf("baked pull interval %q: %v", m[1], err)
	}

	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	got, err := time.ParseDuration(renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker").Allowlist.Pull.Interval)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("baked NRI pull interval is %s but the chart's is %s — a tightened entry reaches a worker's gate on the baked value (%s)",
			want, got, bakedPath)
	}
}

// The root key set is closed, so a values file carried over from an older
// release — or one with a typo above the sealed subtrees — is refused instead
// of being silently dropped. This is the class that caused the incident the
// schema was added for; sealing only four subtrees left it open everywhere else.
func TestChartValuesSchemaRejectsUnknownRootKeys(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"webhookk", "clusterName", "nriImagePolicyy", "teeProxy"} {
		t.Run(key, func(t *testing.T) {
			out, err := helmTemplate(t, "--set", key+".enabled=true")
			if err == nil {
				t.Fatalf("helm template accepted unknown root key %q\n%s", key, out)
			}
			// Wording differs across helm versions; match the shared stem.
			if lower := strings.ToLower(out); !strings.Contains(lower, "additional propert") ||
				!strings.Contains(lower, strings.ToLower(key)) {
				t.Errorf("failure does not name %q as an unknown key:\n%s", key, out)
			}
		})
	}
}

// A render that names no confidential VMs would deploy an attestation-api
// with no TEE device and a router advertising no evidence platform, so the
// chart refuses it and names the flag that sets them.
func TestChartRefusesARenderWithoutThePlatformKeys(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		"attestationApi.devices",
		"nriImagePolicy.platform",
		"router.attest.platform",
	} {
		t.Run(key, func(t *testing.T) {
			args := slices.Concat(baseCDSPolicy(t), withoutPlatformKey(key))
			out, err := renderCloudChart(t, cloudChartDir, args...)
			if err == nil {
				t.Fatalf("helm template rendered without %s\n%s", key, out)
			}
			for _, want := range []string{"platform_values", key, "--platform"} {
				if !strings.Contains(out, want) {
					t.Errorf("the refusal of an unset %s does not name %q:\n%s", key, want, out)
				}
			}
		})
	}
}

// A mock attestation API reads no TEE device, so a present empty device list
// is an answer and renders; an absent key stays unset
// (TestChartRefusesARenderWithoutThePlatformKeys).
func TestChartAcceptsAnEmptyAttestationDeviceList(t *testing.T) {
	t.Parallel()
	args := slices.Concat(baseCDSPolicy(t), withoutPlatformKey("attestationApi.devices"),
		[]string{"--set-json", "attestationApi.devices=[]"})
	out, err := renderCloudChart(t, cloudChartDir, args...)
	if err != nil {
		t.Fatalf("helm template refused an empty attestationApi.devices: %v\n%s", err, out)
	}
	if strings.Contains(out, "type: CharDevice") {
		t.Errorf("an empty attestationApi.devices still mounted a device:\n%s", out)
	}
}

// withoutPlatformKey is basePlatformArgs less the pair setting key.
func withoutPlatformKey(key string) []string {
	var args []string
	for i := 0; i < len(basePlatformArgs); i += 2 {
		if !strings.HasPrefix(basePlatformArgs[i+1], key+"=") && !strings.HasPrefix(basePlatformArgs[i+1], key+"[") {
			args = append(args, basePlatformArgs[i], basePlatformArgs[i+1])
		}
	}
	return args
}

// A relative plugin path, a mistyped policy mode or platform, or a device
// outside /dev would be accepted silently and surface only on the node.
func TestChartValuesSchemaConstrainsTheEnumsAndRanges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, set string }{
		{"plugin directory outside an absolute path", "nriImagePolicy.hostPaths.pluginDir=opt/nri"},
		{"unknown policy mode", "nriImagePolicy.policy.mode=failclosed"},
		{"unknown TEE family", "nriImagePolicy.platform=sev"},
		{"unknown evidence platform", "router.attest.platform=gcp-snp"},
		{"a device outside /dev", "attestationApi.devices[0]=/etc/shadow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := helmTemplate(t, "--set-string", tc.set); err == nil {
				t.Fatalf("helm template accepted --set-string %s\n%s", tc.set, out)
			}
		})
	}

	// The other real mode still renders.
	if out, err := helmTemplate(t, "--set-string", "nriImagePolicy.policy.mode=audit"); err != nil {
		t.Fatalf("a valid mode was refused: %v\n%s", err, out)
	}
}

// Every component that serves a port had no ingress policy at all, so anything
// on the pod network could reach any port they happened to bind — the router
// sidecars bind loopback by intention, not by enforcement. These policies are
// default-deny with the declared ports carved back out.
func TestChartComponentIngressPoliciesAreDefaultDeny(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		policy    string
		component string
		ports     []int32
		manifest  string
	}{
		{"c8s-operator-ingress", "operator", []int32{9443, 8081, 8080}, out},
		{"c8s-volumed-ingress", "volumed", nil, out},
		{"c8s-router-ingress", "", []int32{8443}, out},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			var np networkingv1.NetworkPolicy
			if !findDoc(t, tc.manifest, "NetworkPolicy", tc.policy, &np) {
				t.Fatalf("render is missing NetworkPolicy %q", tc.policy)
			}
			// Ingress only: armtls-mesh's tcp-only-egress selects every pod and
			// allows all TCP, so an egress rule here would be unioned away.
			if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress {
				t.Errorf("policyTypes = %v, want [Ingress]", np.Spec.PolicyTypes)
			}
			if tc.component != "" && np.Spec.PodSelector.MatchLabels["app.kubernetes.io/component"] != tc.component {
				t.Errorf("podSelector = %v, want component %q", np.Spec.PodSelector.MatchLabels, tc.component)
			}
			if len(np.Spec.PodSelector.MatchLabels) == 0 {
				t.Error("podSelector is empty: this policy would apply to every pod in the namespace")
			}

			var got []int32
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) != 0 {
					t.Errorf("ingress rule restricts source (%v); these policies narrow which port answers, never who connects — router is a public front door and the API server dialling the webhook has no selectable address", rule.From)
				}
				for _, p := range rule.Ports {
					if p.Port == nil {
						t.Fatalf("ingress rule opens every port on %s", tc.policy)
					}
					got = append(got, int32(p.Port.IntValue()))
				}
			}
			if !slices.Equal(got, tc.ports) {
				t.Errorf("allowed ports = %v, want %v", got, tc.ports)
			}
		})
	}
}

// router is the public front door, so its policy must leave the front-door port
// open to every source. A `from` here would also be unsatisfiable in principle:
// externalTrafficPolicy defaults to Local precisely to preserve arbitrary public
// client IPs, and no selector can enumerate the internet.
func TestChartRouterIngressPolicyStaysReachableFromOffCluster(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "c8s-router-ingress", &np) {
		t.Fatal("render is missing the router ingress policy")
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("ingress rules = %d, want 1", len(np.Spec.Ingress))
	}
	if len(np.Spec.Ingress[0].From) != 0 {
		t.Fatalf("the front-door rule names sources (%v); external clients would be refused", np.Spec.Ingress[0].From)
	}

	// The cloud runs no acme sidecar, so nginx's :80 server stays unpublished.
	if published := assertRouterFrontDoorPorts(t, out, renderedRouterNginxConf(t, out)); !slices.Equal(published, []int32{8443}) {
		t.Errorf("the cloud router publishes %v, want only the HTTPS port 8443", published)
	}
}

func TestRouterWaitsForCredentialsWithoutLivenessRestarts(t *testing.T) {
	t.Parallel()

	base, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, base)
	}
	nginx := renderedDeploymentContainer(t, base, "c8s-router", "nginx")
	if nginx.LivenessProbe != nil {
		t.Fatal("nginx liveness restarts the wrapper while credentials are absent")
	}
	p := nginx.ReadinessProbe
	if p == nil || p.HTTPGet == nil {
		t.Fatalf("router readiness should be httpGet; got %+v", p)
	}
	if p.HTTPGet.Scheme != corev1.URISchemeHTTPS || p.HTTPGet.Path != "/healthz" {
		t.Fatalf("router readiness = %+v, want HTTPS /healthz", p.HTTPGet)
	}
}

func TestChartSweepMountAdmission(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatal(err)
	}
	idx := seed.BuildIndex()
	for _, tc := range []struct {
		name            string
		argv            []string
		hostMount, want bool
	}{
		{"sweep", []string{"/bin/sh", "-c", HostSweepScript()}, true, true},
		{"pause", []string{"/bin/sleep", "2147483647"}, false, true},
		{"pause with host mount", []string{"/bin/sleep", "2147483647"}, true, false},
		{"shell pause with host mount", []string{"/bin/sh", "-c", "sleep infinity"}, true, false},
		{"unpinned script", []string{"/bin/sh", "-c", "echo unexpected"}, true, false},
	} {
		mounts := []pkgallowlist.ObservedMount{}
		if tc.hostMount {
			mounts = append(mounts, pkgallowlist.ObservedMount{
				Source:      "/",
				Destination: "/host",
				Class:       pkgallowlist.MountHost,
				Storage:     pkgallowlist.MountUnknown,
			})
		}
		container := pkgallowlist.RunningContainer{
			Digest: baseNRIDigest,
			Argv:   tc.argv,
			Mounts: mounts,
		}
		if got := idx.AdmitsContainer(container); got != tc.want {
			t.Errorf("%s admitted=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestChartRouterReservedPathsCoverNginxLocations: every path nginx serves
// itself is a --reserved-paths entry, so the tunnel never routes a request to
// a manifest backend that the public path would have answered (route policy
// M6). A location added without its reserved path fails here.
func TestChartRouterReservedPathsCoverNginxLocations(t *testing.T) {
	location := regexp.MustCompile(`(?m)^\s*location\s+(?:=\s+)?(\S+)\s*\{`)
	for _, tc := range []struct {
		lane   string
		render func(t *testing.T, args ...string) (string, error)
		files  func(*testing.T) map[string]string
	}{
		{lane: "cloud", render: helmTemplate, files: cloudRouterNginxFiles},
		{lane: "worker", render: helmTemplateWorker, files: libRouterNginxFiles},
	} {
		t.Run(tc.lane, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var reserved []string
			for _, arg := range renderedDeploymentContainer(t, out, "c8s-router", "cds-attest").Args {
				if v, ok := strings.CutPrefix(arg, "--reserved-paths="); ok {
					reserved = strings.Split(v, ",")
				}
			}
			if len(reserved) == 0 {
				t.Fatal("cds-attest has no --reserved-paths")
			}
			// M3 prefix match, as routes.Table.Select applies a reserved path.
			covered := func(p string) bool {
				return slices.ContainsFunc(reserved, func(r string) bool {
					return p == r || strings.HasPrefix(p, r) && (strings.HasSuffix(r, "/") || p[len(r)] == '/')
				})
			}
			matches := location.FindAllStringSubmatch(tc.files(t)["nginx.conf"], -1)
			if len(matches) < 3 {
				t.Fatalf("found %d nginx locations, want the router's protocol endpoints", len(matches))
			}
			for _, m := range matches {
				if p := m[1]; p != "/" && !strings.HasPrefix(p, "@") && !covered(p) {
					t.Errorf("nginx serves location %s, which --reserved-paths %v does not cover", p, reserved)
				}
			}
		})
	}
}

// The pod validator is rendered fail-closed over both pod resources and both
// write operations, so a pod cannot reach the API server without its injected
// shape while the webhook is down. The operator is told the
// configuration name so it patches the serving CA onto it.
func TestChartRendersPodValidatorFailClosed(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var cfg admissionregv1.ValidatingWebhookConfiguration
	if !findDoc(t, out, "ValidatingWebhookConfiguration", "c8s-pod-validator", &cfg) {
		t.Fatalf("chart missing ValidatingWebhookConfiguration c8s-pod-validator\n%s", out)
	}
	if len(cfg.Webhooks) != 1 {
		t.Fatalf("webhooks = %d, want one", len(cfg.Webhooks))
	}
	wh := cfg.Webhooks[0]
	if wh.FailurePolicy == nil || *wh.FailurePolicy != admissionregv1.Fail {
		t.Errorf("failurePolicy = %v, want Fail", wh.FailurePolicy)
	}
	if wh.ClientConfig.Service == nil || wh.ClientConfig.Service.Path == nil || *wh.ClientConfig.Service.Path != "/validate-pods" {
		t.Errorf("clientConfig path = %+v, want /validate-pods", wh.ClientConfig.Service)
	}
	if len(wh.Rules) != 1 {
		t.Fatalf("rules = %d, want one", len(wh.Rules))
	}
	rule := wh.Rules[0]
	for _, want := range []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update} {
		if !slices.Contains(rule.Operations, want) {
			t.Errorf("rule operations = %v, want %v included", rule.Operations, want)
		}
	}
	for _, want := range []string{"pods", "pods/ephemeralcontainers"} {
		if !slices.Contains(rule.Resources, want) {
			t.Errorf("rule resources = %v, want %v included", rule.Resources, want)
		}
	}

	// The operator is told the injector's name and derives this one, so the
	// two must stay named beside each other.
	args := renderedOperatorArgs(t, out)
	if !slices.Contains(args, "--exclude-namespaces=local-path-storage") {
		t.Error("external storage namespace must also be excluded from reinjection")
	}
	if !slices.Contains(args, "--webhook-config-name=c8s-pod-injector") {
		t.Errorf("operator args missing --webhook-config-name=c8s-pod-injector\n%v", args)
	}
	// Every covered pod gets an endpoint, so the operator must know its image.
	if !slices.ContainsFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "--mesh-image=") }) {
		t.Errorf("operator args carry no --mesh-image, so no pod would get an endpoint\n%v", args)
	}

	// The operator's own namespace and the system namespaces are out of the
	// validator's scope, so the operator can always boot to patch the caBundle
	// this fail-closed webhook needs.
	excluded := selectorExpressionValues(wh.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	for _, want := range []string{"c8s-system", "kube-system", "kube-public", "kube-node-lease", "local-path-storage"} {
		if !slices.Contains(excluded, want) {
			t.Errorf("validator namespaceSelector missing excluded namespace %q: %v", want, excluded)
		}
	}
	if wh.MatchPolicy == nil || *wh.MatchPolicy != admissionregv1.Equivalent {
		t.Errorf("matchPolicy = %v, want Equivalent", wh.MatchPolicy)
	}
}

// The install lane renders the mesh policy in the same shape the node image
// measures, so the enforcer it installs hosts member pods there too (the lane
// is for test clusters, decision 5).
func TestChartBootConfigRendersTheMeshPolicy(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")

	if cfg.Mesh == nil {
		t.Fatal("the install lane renders no mesh policy, so its enforcer hosts no member pods")
	}
	for _, ns := range []string{"c8s-system", "kube-system", "local-path-storage"} {
		if !slices.Contains(cfg.Mesh.ExemptNamespaces, ns) {
			t.Errorf("mesh.exempt_namespaces = %v, want %s exempt", cfg.Mesh.ExemptNamespaces, ns)
		}
	}
	if cfg.Mesh.Capture.Outbound != 15001 || cfg.Mesh.Capture.Inbound != 15006 || cfg.Mesh.Capture.Health != 15021 {
		t.Errorf("mesh.capture = %+v, want the ports the injected endpoint binds", cfg.Mesh.Capture)
	}
	roles := map[string]uint32{}
	for _, role := range cfg.Mesh.Roles {
		roles[role.Name] = role.UID
	}
	// The credential role is bound by the plugin, from the node's own address
	// and the CDS node port, so the rendered policy names the mesh role alone.
	if len(roles) != 1 || roles["mesh"] != 1337 {
		t.Errorf("mesh.roles = %+v, want the reserved mesh id alone", cfg.Mesh.Roles)
	}
	// The router's namespace, listeners and egress ports are compiled into the
	// enforcer, so the cluster's own ranges are the one router input the
	// rendered policy carries: the acme egress exception excludes them.
	if !slices.Equal(cfg.Mesh.ClusterRanges, []string{"10.42.0.0/16"}) {
		t.Errorf("mesh.cluster_ranges = %v, want the configured cluster ranges", cfg.Mesh.ClusterRanges)
	}
}

// The mesh gate's exempt list is derived from the image policy's rather than
// set a second time, so exempting a namespace cannot produce a config the
// plugin refuses.
func TestChartBootConfigMeshExemptsEveryImagePolicyExemptNamespace(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,gmp-system}")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if cfg.Mesh == nil {
		t.Fatal("no mesh policy rendered")
	}
	want := []string{
		"c8s-system",
		"gmp-system",
		"kube-system",
		"local-path-storage",
	}
	got := slices.Clone(cfg.Mesh.ExemptNamespaces)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("mesh.exempt_namespaces = %v, want %v", cfg.Mesh.ExemptNamespaces, want)
	}
}

// The chart's mesh identity and ports must be the constants the injector
// builds the containers from and the enforcer matches on; a drift would seal a
// pod against its own endpoint.
func TestChartMeshPolicyMatchesTheSharedConstants(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if cfg.Mesh == nil {
		t.Fatal("no mesh policy rendered")
	}
	if cfg.Mesh.Capture.Outbound != uint16(workloadclaims.MeshOutboundPort) ||
		cfg.Mesh.Capture.Inbound != uint16(workloadclaims.MeshInboundPort) ||
		cfg.Mesh.Capture.Health != uint16(workloadclaims.MeshHealthPort) {
		t.Errorf("mesh.capture = %+v, want the workloadclaims ports", cfg.Mesh.Capture)
	}
	ids := map[string]uint32{}
	for _, role := range cfg.Mesh.Roles {
		ids[role.Name] = role.UID
	}
	if ids["mesh"] != workloadclaims.MeshUID {
		t.Errorf("mesh role uid = %d, want %d", ids["mesh"], workloadclaims.MeshUID)
	}
}

// A regular Helm install never reads launch files.
func TestChartRouterDefaultIgnoresLaunchFiles(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, unwanted := range []string{"/run/c8s-node", "/usr/lib/c8s", "--domains-file", "--discovery-public-tls-mode-file", "--front-door-mode-file"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("unbaked render contains %q", unwanted)
		}
	}
}

// confidentialNodeWorkloads are the cloud chart's pods that must run inside a
// node's TEE: the node agents and the router.
var confidentialNodeWorkloads = []string{
	"c8s-attestation-api",
	"c8s-nri-image-policy-worker",
	"c8s-router",
	"c8s-volumed",
}

// Every one of them selects the nodes its stock file marks as confidential.
func TestChartPlacesNodeAgentsOnConfidentialNodes(t *testing.T) {
	t.Parallel()
	for _, platform := range cloudPlatforms {
		out, err := helmTemplatePlatform(t, platform, "--set", "volumed.enabled=true")
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", platform, err, out)
		}
		want := stockConfidentialNodeSelector(t, platform)
		placed := map[string]bool{}
		for _, w := range renderedPodSpecs(t, out) {
			if !slices.Contains(confidentialNodeWorkloads, w.name) {
				continue
			}
			placed[w.name] = true
			if !maps.Equal(w.spec.NodeSelector, want) {
				t.Errorf("%s: %s %s nodeSelector = %v, want %v", platform, w.kind, w.name, w.spec.NodeSelector, want)
			}
		}
		for _, name := range confidentialNodeWorkloads {
			if !placed[name] {
				t.Errorf("%s renders no %s", platform, name)
			}
		}
	}
}

// stockConfidentialNodeSelector reads the labels values-<platform>.yaml marks
// a confidential node with.
func stockConfidentialNodeSelector(t *testing.T, platform string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cloudChartDir, "values-"+platform+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		ConfidentialNodeSelector map[string]string `yaml:"confidentialNodeSelector"`
	}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	if len(values.ConfidentialNodeSelector) == 0 {
		t.Fatalf("values-%s.yaml marks no confidential node", platform)
	}
	return values.ConfidentialNodeSelector
}

// The injector selects the same confidential nodes as the node agents.
func TestChartGivesTheOperatorTheConfidentialNodeLabels(t *testing.T) {
	t.Parallel()
	for _, platform := range cloudPlatforms {
		out, err := helmTemplatePlatform(t, platform)
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", platform, err, out)
		}
		args := renderedOperatorArgs(t, out)
		for label, value := range stockConfidentialNodeSelector(t, platform) {
			assertContainerHasArg(t, "operator", args, fmt.Sprintf("--confidential-node-selector=%s=%s", label, value))
		}
	}
}

// The schema requires the labels.
func TestChartRefusesWithoutConfidentialNodeSelector(t *testing.T) {
	t.Parallel()
	unset := filepath.Join(t.TempDir(), "unset.yaml")
	if err := os.WriteFile(unset, []byte("confidentialNodeSelector: null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplatePlatform(t, "aks-snp", "-f", unset)
	if err == nil {
		t.Fatalf("a release marking no confidential node rendered\n%s", out)
	}
	if !strings.Contains(out, "confidentialNodeSelector") {
		t.Errorf("refusal does not name the key: %s", out)
	}
}
