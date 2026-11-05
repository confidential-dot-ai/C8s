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
			var clusterRole rbacv1.ClusterRole
			if !findDoc(t, out, "ClusterRole", "c8s-operator", &clusterRole) {
				t.Fatal("operator ClusterRole missing")
			}
			nodes, podStatus := false, false
			for _, rule := range clusterRole.Rules {
				if slices.Contains(rule.Resources, "secrets") {
					t.Fatal("provider has cluster-wide Secret access")
				}
				nodes = nodes || slices.Contains(rule.Resources, "nodes")
				podStatus = podStatus || slices.Contains(rule.Resources, "pods/status")
			}
			if nodes != enabled || podStatus != enabled {
				t.Fatalf("provider RBAC nodes=%t podStatus=%t", nodes, podStatus)
			}
		})
	}
}
