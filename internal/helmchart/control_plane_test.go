package helmchart

import (
	"os/exec"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// helmTemplateControlPlane renders the c8s-control-plane chart on its own.
func helmTemplateControlPlane(t *testing.T, args ...string) string {
	t.Helper()
	base := []string{
		"template", "c8s", controlPlaneChart,
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
	}
	out, err := helmOutput(exec.Command("helm", append(base, args...)...))
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return string(out)
}

// renderedWebhookConfigurations decodes the injector and the validator.
func renderedWebhookConfigurations(t *testing.T, manifest string) (admissionregv1.MutatingWebhookConfiguration, admissionregv1.ValidatingWebhookConfiguration) {
	t.Helper()
	var mutating admissionregv1.MutatingWebhookConfiguration
	var validating admissionregv1.ValidatingWebhookConfiguration
	if !findDoc(t, manifest, "MutatingWebhookConfiguration", "c8s-pod-injector", &mutating) ||
		!findDoc(t, manifest, "ValidatingWebhookConfiguration", "c8s-pod-validator", &validating) {
		t.Fatalf("missing admission webhooks\n%s", manifest)
	}
	return mutating, validating
}

// The API server reaches both webhooks through the operator's Service, each
// under its own path.
func TestControlPlaneWebhookClientConfig(t *testing.T) {
	t.Parallel()
	mutating, validating := renderedWebhookConfigurations(t, helmTemplateControlPlane(t))
	for _, tc := range []struct {
		role   string
		config admissionregv1.WebhookClientConfig
		path   string
	}{
		{
			role:   "injector",
			config: mutating.Webhooks[0].ClientConfig,
			path:   "/mutate-pods",
		},
		{
			role:   "validator",
			config: validating.Webhooks[0].ClientConfig,
			path:   "/validate-pods",
		},
	} {
		service := webhookService(t, tc.config)
		if service.Namespace != "c8s-system" || service.Name != "c8s-operator" {
			t.Errorf("%s calls Service %s/%s, want c8s-system/c8s-operator", tc.role, service.Namespace, service.Name)
		}
		if *service.Path != tc.path {
			t.Errorf("%s path = %q, want %q", tc.role, *service.Path, tc.path)
		}
		if *service.Port != 443 {
			t.Errorf("%s port = %d, want 443", tc.role, *service.Port)
		}
	}
}

// webhookService is the operator Service a webhook client config names.
func webhookService(t *testing.T, config admissionregv1.WebhookClientConfig) *admissionregv1.ServiceReference {
	t.Helper()
	if config.URL != nil || config.Service == nil || config.Service.Path == nil || config.Service.Port == nil {
		t.Fatalf("client config names no Service with a path and port: %+v", config)
	}
	return config.Service
}

func TestControlPlaneWebhooksShareAnnotations(t *testing.T) {
	t.Parallel()
	mutating, validating := renderedWebhookConfigurations(t, helmTemplateControlPlane(t))
	if len(mutating.Annotations) != 0 || len(validating.Annotations) != 0 {
		t.Errorf("default annotations = %v and %v, want none", mutating.Annotations, validating.Annotations)
	}

	mutating, validating = renderedWebhookConfigurations(t, helmTemplateControlPlane(t,
		"--set-string", `webhook.annotations.admissions\.enforcer/disabled=true`,
		"--set-string", "webhook.annotations.team=platform",
	))
	for _, annotations := range []map[string]string{mutating.Annotations, validating.Annotations} {
		if annotations["admissions.enforcer/disabled"] != "true" || annotations["team"] != "platform" {
			t.Errorf("annotations = %v, want both webhook.annotations entries", annotations)
		}
	}
}

// An injection the mutator never made must not reach the API server, and the
// mutator judges the pod as submitted.
func TestControlPlaneInjectorFailClosed(t *testing.T) {
	t.Parallel()
	mutating, _ := renderedWebhookConfigurations(t, helmTemplateControlPlane(t))
	injector := mutating.Webhooks[0]
	if injector.FailurePolicy == nil || *injector.FailurePolicy != admissionregv1.Fail {
		t.Errorf("injector failurePolicy = %v, want Fail", injector.FailurePolicy)
	}
	if injector.ReinvocationPolicy == nil || *injector.ReinvocationPolicy != admissionregv1.NeverReinvocationPolicy {
		t.Error("the initial-input mutator permits reinvocation")
	}
}

func TestControlPlaneValuesSchemaCoversValuesYAML(t *testing.T) {
	t.Parallel()
	assertChartSchemaCovers(t, controlPlaneChart, []string{"webhook"})
}
