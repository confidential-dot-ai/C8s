//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

// webhookPort is the port the operator's webhook serves on (controller-runtime's).
const webhookPort = "9443"

// operatorUser is the user c8s's operator authenticates as, beside the
// workers' control plane.
const operatorUser = "c8s-operator"

type workerControlPlaneConfig struct {
	nodeImageRenderConfig
	document    string
	webhookHost string
}

func newWorkerControlPlaneCmd() *cobra.Command {
	var cfg workerControlPlaneConfig
	cmd := &cobra.Command{Use: "control-plane", Short: "Render what a control plane outside the workers holds"}
	render := &cobra.Command{
		Use:   "render",
		Short: "Render the objects a cluster of workers holds",
		Long: `Render, into --output-dir/cluster.yaml, the objects a cluster of workers holds:
the chart's, as the worker image's build renders them, less the operator's own
Deployment, Service, account and NetworkPolicy, the allowlist seed, the
router's nginx ConfigMap and the host-namespace admission policies, with its
webhooks at https://<--webhook-host>:9443,
its grants bound to the user c8s-operator and the router free to run on any
worker; the grants the workers' static pods and the Cilium operator (the user
c8s-cilium-operator) need; and the kube-dns Service at the document's
clusterDNS. The image flags must be the worker image build's, so the router
this renders is the one its floor pins.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return renderWorkerControlPlane(cmd.Context(), cfg)
		},
	}
	f := render.Flags()
	f.StringVar(&cfg.document, "document", "", "the workers' document (required)")
	f.StringVar(&cfg.webhookHost, "webhook-host", "127.0.0.1", "host the API server reaches the operator's webhook at")
	f.StringVar(&cfg.platform, "hardware-platform", "", "CPU TEE: tdx or sev-snp (required)")
	f.StringVar(&cfg.kubeVersion, "kube-version", "", "the worker image's Kubernetes semantic version (required)")
	f.StringVar(&cfg.imageDigest, "image-digest", "", "digest of the operator/get-cert container image (sha256:..., required)")
	f.StringVar(&cfg.imageRepository, "image-repository", "", "operator/get-cert container repository; empty uses the chart default")
	f.StringVar(&cfg.armtlsMeshImageDigest, "armtls-mesh-image-digest", "", "digest of the armTLS mesh container image (sha256:..., required)")
	f.StringVar(&cfg.armtlsMeshImageRepository, "armtls-mesh-image-repository", "", "armTLS mesh container repository; empty uses the chart default")
	f.StringVar(&cfg.chartDir, "chart-dir", "", "chart source directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for cluster.yaml (required)")
	cmd.AddCommand(render, newWorkerCredentialsCmd())
	return cmd
}

func renderWorkerControlPlane(ctx context.Context, cfg workerControlPlaneConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.document == "" || cfg.webhookHost == "" {
		return fmt.Errorf("--document and --webhook-host are required")
	}
	data, err := os.ReadFile(cfg.document)
	if err != nil {
		return err
	}
	doc, err := worker.Parse(data)
	if err != nil {
		return fmt.Errorf("--document: %w", err)
	}
	cluster, err := renderWorkerCluster(ctx, cfg.nodeImageRenderConfig, cfg.webhookHost, doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cfg.outputDir, "cluster.yaml"), cluster, 0o644)
}

// renderWorkerCluster renders the objects a cluster of workers holds for doc,
// the chart in the worker image's shape, with the operator's webhooks at host.
func renderWorkerCluster(ctx context.Context, cfg nodeImageRenderConfig, host string, doc *worker.Document) ([]byte, error) {
	// Workers pull what the node image bakes; nothing else on the router's
	// launch differs from the image build's render.
	extra := []string{
		"--set-string", "router.nginx.imagePullPolicy=IfNotPresent",
	}
	for _, input := range cfg.images() {
		extra = append(extra, "--set-string", input.valuePath+".pullPolicy=IfNotPresent")
	}
	rendered, err := renderNodeImageChart(ctx, cfg, extra)
	if err != nil {
		return nil, err
	}
	chart, err := workerClusterObjects(rendered, host)
	if err != nil {
		return nil, err
	}
	own, err := worker.ControlPlaneObjects(doc)
	if err != nil {
		return nil, err
	}
	return append(chart, own...), nil
}

// The chart's objects a cluster of workers holds, and those it leaves out: the
// operator's own, since the operator runs beside the control plane, and what
// the worker image carries. Any other object fails the render, so a new one is
// a decision for workers.
var (
	workerClusterKeeps = []string{
		"Namespace//c8s-router",
		"CustomResourceDefinition//confidentialworkloads.confidential.ai",
		"ClusterRole//c8s-operator",
		"ClusterRoleBinding//c8s-operator",
		"MutatingWebhookConfiguration//c8s-pod-injector",
		"ValidatingWebhookConfiguration//c8s-pod-validator",
		"NetworkPolicy/c8s-router/c8s-router-ingress",
		"Service/c8s-router/c8s-router",
		"Deployment/c8s-router/c8s-router",
	}
	workerClusterDrops = []string{
		"ServiceAccount/c8s-system/c8s-operator",
		"Service/c8s-system/c8s-operator",
		"Deployment/c8s-system/c8s-operator",
		"NetworkPolicy/c8s-system/c8s-operator-ingress",
		"ConfigMap/c8s-system/c8s-allowlist-seed",
		// The worker image bakes these files where the router mounts them.
		"ConfigMap/c8s-router/c8s-router-nginx",
	}
	// The workers' node floor checks each container's privileges instead of the
	// chart's admission policies.
	workerClusterDroppedKinds = []string{
		"ValidatingAdmissionPolicy",
		"ValidatingAdmissionPolicyBinding",
	}
)

// workerClusterObjects selects the chart's objects a cluster of workers holds,
// with the operator's webhooks at https://host:9443 and its grants bound to
// operatorUser.
func workerClusterObjects(rendered []byte, host string) ([]byte, error) {
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	// The release namespace, which holds the operator's leader lease.
	var out bytes.Buffer
	out.WriteString("---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + nodeImageNamespace + "\n")
	var kept []string
	for {
		var object unstructured.Unstructured
		if err := dec.Decode(&object.Object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("chart render: %w", err)
		}
		if len(object.Object) == 0 {
			continue
		}
		key := strings.Join([]string{object.GetKind(), object.GetNamespace(), object.GetName()}, "/")
		switch {
		case slices.Contains(workerClusterDroppedKinds, object.GetKind()):
			continue
		case slices.Contains(workerClusterDrops, key):
			continue
		case !slices.Contains(workerClusterKeeps, key):
			return nil, fmt.Errorf("the chart renders %s, which a cluster of workers neither holds nor leaves out", key)
		}
		if err := forWorkerCluster(&object, key, host); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		data, err := yaml.Marshal(object.Object)
		if err != nil {
			return nil, err
		}
		out.WriteString("---\n")
		out.Write(data)
		kept = append(kept, key)
	}
	for _, key := range workerClusterKeeps {
		if !slices.Contains(kept, key) {
			return nil, fmt.Errorf("the chart rendered no %s", key)
		}
	}
	return out.Bytes(), nil
}

// forWorkerCluster points a webhook configuration at host and rebinds the
// operator's grants from its service account to operatorUser.
func forWorkerCluster(object *unstructured.Unstructured, key, host string) error {
	switch key {
	case "MutatingWebhookConfiguration//c8s-pod-injector", "ValidatingWebhookConfiguration//c8s-pod-validator":
		webhooks, _, err := unstructured.NestedSlice(object.Object, "webhooks")
		if err != nil {
			return err
		}
		for i, hook := range webhooks {
			config, ok := hook.(map[string]any)["clientConfig"].(map[string]any)
			path, _, _ := unstructured.NestedString(config, "service", "path")
			if !ok || path == "" {
				return fmt.Errorf("webhook %d names no Service path", i)
			}
			delete(config, "service")
			config["url"] = "https://" + net.JoinHostPort(host, webhookPort) + path
		}
		return unstructured.SetNestedSlice(object.Object, webhooks, "webhooks")
	case "ClusterRoleBinding//c8s-operator":
		subjects, _, err := unstructured.NestedSlice(object.Object, "subjects")
		if err != nil {
			return err
		}
		operator := map[string]any{"kind": "ServiceAccount", "name": operatorUser, "namespace": nodeImageNamespace}
		if len(subjects) != 1 || !reflect.DeepEqual(subjects[0], operator) {
			return fmt.Errorf("binds %v, not the operator's service account alone", subjects)
		}
		return unstructured.SetNestedSlice(object.Object, []any{map[string]any{
			"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": operatorUser,
		}}, "subjects")
	}
	return nil
}
