// Run the production fixture generator and validate its output against the
// rendered policies, so fixture drift cannot mask the intended integration check.
package helmchart

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	sigsyaml "sigs.k8s.io/yaml"
)

const clusterFixtureDir = "../../test/integration/cluster"

// clusterFixtureHarness is the harness source: run.sh and the lib.sh it sources.
func clusterFixtureHarness(t *testing.T) string {
	t.Helper()
	var harness strings.Builder
	for _, file := range []string{"lib.sh", "run.sh"} {
		data, err := os.ReadFile(filepath.Join(clusterFixtureDir, file))
		if err != nil {
			t.Fatal(err)
		}
		harness.Write(data)
		harness.WriteString("\n")
	}
	return harness.String()
}

func clusterFixtureImage(t *testing.T, harness, variable string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(variable) + `=(\S+)$`).FindStringSubmatch(harness)
	if len(match) != 2 {
		t.Fatalf("missing literal %s assignment in cluster harness", variable)
	}
	return strings.Trim(match[1], `"'`)
}

func clusterFixtureObject(t *testing.T, pod *corev1.Pod) map[string]any {
	t.Helper()
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func TestClusterDeploymentFixturesMeetRestrictedPolicy(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	image := clusterFixtureImage(t, clusterFixtureHarness(t), "WORKLOAD_IMAGE")
	if !strings.HasPrefix(image, "nginxinc/nginx-unprivileged@sha256:") {
		t.Fatalf("workload image must remain pinned and non-root, got %q", image)
	}
	for _, file := range []string{"workload.yaml", "adopt-me.yaml"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(clusterFixtureDir, "manifests", file))
			if err != nil {
				t.Fatal(err)
			}
			deployments := 0
			iterateManifests(t, string(data), func(doc []byte) bool {
				var deployment appsv1.Deployment
				if err := sigsyaml.Unmarshal(doc, &deployment); err != nil {
					t.Fatal(err)
				}
				if deployment.Kind != "Deployment" {
					return false
				}
				deployments++
				pod := &corev1.Pod{
					ObjectMeta: deployment.Spec.Template.ObjectMeta,
					Spec:       deployment.Spec.Template.Spec,
				}
				allTrue(t, validations, clusterFixtureObject(t, pod))
				if len(pod.Spec.Containers) != 1 {
					t.Fatalf("expected one fixture app container, got %d", len(pod.Spec.Containers))
				}
				app := pod.Spec.Containers[0]
				if app.Image != image {
					t.Errorf("fixture image %q differs from pre-pull/floor image %q", app.Image, image)
				}
				if len(app.Ports) != 1 || app.Ports[0].ContainerPort != 8080 {
					t.Errorf("fixture must expose nginx's unprivileged backend port 8080: %+v", app.Ports)
				}
				return false
			})
			if deployments != 1 {
				t.Fatalf("expected one Deployment, got %d", deployments)
			}
		})
	}
}

// Evaluate the label policy's actual CEL variables before its validations.
func clusterFixtureLabelDenials(t *testing.T, policy admissionregv1.ValidatingAdmissionPolicy, object map[string]any) []string {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("variables", cel.DynType),
	)
	if err != nil {
		t.Fatal(err)
	}
	variables := map[string]any{}
	activation := map[string]any{"object": object, "oldObject": nil, "variables": variables}
	evaluate := func(expression string) any {
		t.Helper()
		ast, issues := env.Compile(expression)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("compile label policy: %v", issues.Err())
		}
		program, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := program.Eval(activation)
		if err != nil {
			t.Fatalf("evaluate label policy %q: %v", expression, err)
		}
		return value.Value()
	}
	for _, variable := range policy.Spec.Variables {
		variables[variable.Name] = evaluate(variable.Expression)
	}
	var denied []string
	for _, validation := range policy.Spec.Validations {
		if evaluate(validation.Expression) != true {
			denied = append(denied, validation.Message)
		}
	}
	return denied
}

func TestClusterGeneratedPodFixturesMeetIntendedPolicies(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var labelPolicy admissionregv1.ValidatingAdmissionPolicy
	iterateManifests(t, out, func(doc []byte) bool {
		var policy admissionregv1.ValidatingAdmissionPolicy
		if err := sigsyaml.Unmarshal(doc, &policy); err != nil {
			return false
		}
		if policy.Kind == "ValidatingAdmissionPolicy" && policy.Name == "c8s-cw-label-integrity" {
			labelPolicy = policy
			return true
		}
		return false
	})
	if len(labelPolicy.Spec.Validations) == 0 {
		t.Fatal("label integrity policy not rendered")
	}
	image := clusterFixtureImage(t, clusterFixtureHarness(t), "CURL_IMAGE")
	command := []string{"sh", "-c", `printf '%s\n' 'spaces and "quotes" $literal'; curl 'https://example.test/a?x=1&y=2'`}
	for _, mode := range []string{"client", "bad-label", "bad-hostnet", "front-door"} {
		t.Run(mode, func(t *testing.T) {
			args := append([]string{filepath.Join(clusterFixtureDir, "pod-fixture.py"), mode, "fixture", "demo", image, "--"}, command...)
			data, err := exec.Command("python3", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("production fixture renderer: %v\n%s", err, data)
			}
			var pod corev1.Pod
			if err := json.Unmarshal(data, &pod); err != nil {
				t.Fatal(err)
			}
			if pod.Kind != "Pod" || pod.Name != "fixture" || pod.Namespace != "demo" || len(pod.Spec.Containers) != 1 {
				t.Fatalf("unexpected generated Pod identity or container count: %+v", pod)
			}
			app := pod.Spec.Containers[0]
			if app.Image != image || !reflect.DeepEqual(app.Command, command) {
				t.Fatalf("renderer changed the image or command arguments: %+v", app)
			}
			if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.RunAsUser == nil || *pod.Spec.SecurityContext.RunAsUser != 1000 {
				t.Fatal("curl requires numeric non-root UID 1000 to satisfy kubelet runAsNonRoot verification")
			}
			if mode == "front-door" {
				if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].ConfigMap == nil || pod.Spec.Volumes[0].ConfigMap.Name != "it-mesh-ca" {
					t.Fatalf("front-door fixture lost its mesh CA volume: %+v", pod.Spec.Volumes)
				}
				if len(app.VolumeMounts) != 1 || app.VolumeMounts[0].Name != pod.Spec.Volumes[0].Name || app.VolumeMounts[0].MountPath != "/ca" || !app.VolumeMounts[0].ReadOnly {
					t.Fatalf("front-door fixture must mount the CA read-only at /ca: %+v", app.VolumeMounts)
				}
			}
			object := clusterFixtureObject(t, &pod)
			if mode == "bad-hostnet" {
				denials := 0
				for _, validation := range validations {
					if !evalPolicy(t, validation.Expression, object) {
						denials++
						if !strings.HasPrefix(validation.Message, "hostNetwork is reserved") {
							t.Errorf("hostNetwork negative fixture fails an unrelated restriction: %s", validation.Message)
						}
					}
				}
				if denials != 1 {
					t.Fatalf("expected only the hostNetwork denial, got %d", denials)
				}
				pod.Spec.HostNetwork = false
				object = clusterFixtureObject(t, &pod)
			}
			allTrue(t, validations, object)
			labelDenials := clusterFixtureLabelDenials(t, labelPolicy, object)
			if mode == "bad-label" {
				mismatch := false
				for _, denial := range labelDenials {
					mismatch = mismatch || strings.Contains(denial, "pod label must match")
				}
				if !mismatch {
					t.Fatalf("rogue label fixture did not trigger label/annotation mismatch: %v", labelDenials)
				}
				delete(pod.Labels, "confidential.ai/cw")
				labelDenials = clusterFixtureLabelDenials(t, labelPolicy, clusterFixtureObject(t, &pod))
			}
			if len(labelDenials) != 0 {
				t.Errorf("otherwise-compliant fixture fails label policy: %v", labelDenials)
			}
		})
	}
}

func TestClusterHarnessKeepsImageAndBackendRoutingAligned(t *testing.T) {
	harness := clusterFixtureHarness(t)
	for _, required := range []string{
		`images pull "docker.io/$WORKLOAD_IMAGE"`,
		`grep -Fq "docker.io/$WORKLOAD_IMAGE" "$WORKDIR/floor.tsv"`,
		`--workload-ref web=adopted/deployment/web:8080`,
		`{ port: 80, targetPort: 8080 }`,
		`python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" "$mode" "$name" "$ns" "$CURL_IMAGE" -- "$@"`,
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("cluster harness lost fixture wiring %q", required)
		}
	}
	if strings.Contains(harness, "$POD_IP:80/") || strings.Contains(harness, "kubectl run ") {
		t.Error("cluster harness uses the old backend port or bypasses the Restricted Pod renderer")
	}
}
