package helmchart

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestPodProviderRequiresAnExistingSecret(t *testing.T) {
	out, err := helmTemplate(t, "--set", "operator.podCVMProvider.enabled=true")
	if err == nil || !strings.Contains(out, "operator.podCVMProvider.existingSecret is required") {
		t.Fatalf("expected missing Secret refusal: %v\n%s", err, out)
	}
}

func TestPodProviderMountAndPermissionsAreOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := map[bool]string{false: "disabled", true: "enabled"}[enabled]
		t.Run(name, func(t *testing.T) {
			var args []string
			if enabled {
				args = []string{"--set", "operator.podCVMProvider.enabled=true", "--set", "operator.podCVMProvider.existingSecret=pod-launch-config"}
			}
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			deployment := renderedDeployment(t, out, "c8s-operator")
			operator := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
			flag := "--pod-cvm-provider-config=/mnt/c8s-data/pod-cvm/config.json"
			if slices.Contains(operator.Args, flag) != enabled {
				t.Fatalf("provider args=%v", operator.Args)
			}
			mounted := false
			for _, m := range operator.VolumeMounts {
				if m.Name == "pod-cvm-provider" {
					mounted = true
					if !m.ReadOnly || m.MountPath != "/mnt/c8s-data/pod-cvm" {
						t.Fatalf("unsafe config mount: %+v", m)
					}
				}
			}
			if mounted != enabled {
				t.Fatalf("config mounted=%t", mounted)
			}
			var secret *corev1.SecretVolumeSource
			for _, v := range deployment.Spec.Template.Spec.Volumes {
				if v.Name == "pod-cvm-provider" {
					secret = v.Secret
				}
			}
			if enabled && (secret == nil || secret.SecretName != "pod-launch-config" || secret.DefaultMode == nil || *secret.DefaultMode != 0o440) {
				t.Fatalf("config volume=%+v", secret)
			}
			if !enabled && secret != nil {
				t.Fatal("disabled provider mounts credentials")
			}
			var role rbacv1.Role
			found := findDoc(t, out, "Role", "c8s-operator-pod-cvm", &role)
			if found != enabled {
				t.Fatalf("provider Role present=%t", found)
			}
			if enabled && role.Namespace != deployment.Namespace {
				t.Fatal("record Secret role escapes release namespace")
			}
			var operatorRole, providerRole rbacv1.ClusterRole
			if !findDoc(t, out, "ClusterRole", "c8s-operator", &operatorRole) {
				t.Fatal("operator ClusterRole missing")
			}
			if findDoc(t, out, "ClusterRole", "c8s-operator-pod-cvm", &providerRole) != enabled {
				t.Fatalf("provider ClusterRole present=%t", !enabled)
			}
			nodes, podStatus, events := false, false, false
			for _, rule := range append(operatorRole.Rules, providerRole.Rules...) {
				if slices.Contains(rule.Resources, "secrets") {
					t.Fatal("provider has cluster-wide Secret access")
				}
				nodes = nodes || slices.Contains(rule.Resources, "nodes")
				podStatus = podStatus || slices.Contains(rule.Resources, "pods/status")
				events = events || slices.Contains(rule.APIGroups, "events.k8s.io") && slices.Contains(rule.Resources, "events") && slices.Contains(rule.Verbs, "create")
			}
			if nodes != enabled || podStatus != enabled || events != enabled {
				t.Fatalf("provider RBAC nodes=%t podStatus=%t events=%t", nodes, podStatus, events)
			}
			var binding rbacv1.RoleBinding
			if enabled && (!findDoc(t, out, "RoleBinding", "c8s-operator-pod-cvm", &binding) || len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != "c8s-operator") {
				t.Fatalf("provider RoleBinding subjects = %+v, want the operator's ServiceAccount", binding.Subjects)
			}
		})
	}
}
