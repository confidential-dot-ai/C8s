//go:build !c8s_node

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

// webhookPort is the port the operator's webhook serves on (controller-runtime's).
const webhookPort = "9443"

// The objects a cluster of workers holds, and those the worker image bakes
// instead. Any other object fails the render, so a new template of the worker
// chart is a decision for workers.
var (
	workerClusterObjects = []string{
		"ClusterRole//c8s-operator",
		"ClusterRole//c8s-router",
		"ClusterRole//c8s-worker-cilium",
		"ClusterRole//c8s-worker-cilium-operator",
		"ClusterRoleBinding//c8s-operator",
		"ClusterRoleBinding//c8s-router",
		"ClusterRoleBinding//c8s-worker-bootstrap",
		"ClusterRoleBinding//c8s-worker-bootstrap-client-cert",
		"ClusterRoleBinding//c8s-worker-cilium",
		"ClusterRoleBinding//c8s-worker-cilium-operator",
		"ClusterRoleBinding//c8s-worker-client-cert-renewal",
		"ClusterRoleBinding//c8s-worker-kube-proxy",
		"CustomResourceDefinition//confidentialworkloads.confidential.ai",
		"Deployment/c8s-router/c8s-router",
		"MutatingWebhookConfiguration//c8s-pod-injector",
		"Namespace//c8s-router",
		"Namespace//c8s-system",
		"NetworkPolicy/c8s-router/c8s-router-ingress",
		"Role/kube-system/c8s-worker-cilium-operator-lease",
		"RoleBinding/kube-system/c8s-worker-cilium-operator-lease",
		"Service/c8s-router/c8s-router",
		"Service/kube-system/dcgm-exporter",
		"Service/kube-system/kube-dns",
		"ServiceAccount/c8s-router/c8s-router",
		"ValidatingWebhookConfiguration//c8s-pod-validator",
	}
	workerImageObjects = []string{
		"ConfigMap/c8s-system/c8s-allowlist-seed",
	}
	// The operator's Pod CVM provider grants, held only with --pod-cvm-provider.
	workerClusterPodCVMProviderObjects = []string{
		"ClusterRole//c8s-operator-pod-cvm",
		"ClusterRoleBinding//c8s-operator-pod-cvm",
		"Role/c8s-system/c8s-operator-pod-cvm",
		"RoleBinding/c8s-system/c8s-operator-pod-cvm",
	}
	workerOperatorObjects = []string{
		"ClusterRoleBinding//c8s-operator-pod",
		"Deployment/c8s-system/c8s-operator",
		"ServiceAccount/c8s-system/c8s-operator",
	}
)

type workerControlPlaneConfig struct {
	nodeImageRenderConfig
	document    string
	webhookHost string
	// podCVMProvider grants the operator what its Pod CVM provider needs.
	podCVMProvider bool
	// controlPlaneNodes renders the operator's own objects, for a control
	// plane whose hosts run a kubelet.
	controlPlaneNodes bool
}

func newWorkerControlPlaneCmd() *cobra.Command {
	var cfg workerControlPlaneConfig
	cmd := &cobra.Command{Use: "control-plane", Short: "Render what a control plane outside the workers holds"}
	render := &cobra.Command{
		Use:   "render",
		Short: "Render the objects a cluster of workers holds",
		Long: `Render, into --output-dir/cluster.yaml, the objects a cluster of workers holds:
the c8s-worker chart's CRD, its cluster templates and its control-plane
subchart, with the operator's webhooks at https://<--webhook-host>:9443, its
grants bound to the user c8s-operator, and the kube-dns Service at the
document's clusterDNS. The image flags must be the worker image build's, so the
router this renders is the one its floor pins. --pod-cvm-provider adds the
grants the operator's Pod CVM provider needs (run the operator with
--pod-cvm-provider-config); its records are Secrets in c8s-system.
--control-plane-nodes also writes --output-dir/operator.yaml, which runs c8s
operator as a pod on those nodes instead of by hand beside each API server.`,
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
	f.StringVar(&cfg.chartDir, "chart-dir", "", "c8s-worker chart directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for cluster.yaml, and operator.yaml with --control-plane-nodes (required)")
	f.BoolVar(&cfg.podCVMProvider, "pod-cvm-provider", false, "grant the operator's Pod CVM provider its nodes, pods/status and c8s-system Secrets")
	f.BoolVar(&cfg.controlPlaneNodes, "control-plane-nodes", false, "the control-plane hosts are nodes of this cluster, which run c8s operator as a pod (operator.yaml)")
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
	render, cleanup, err := cfg.resolveWorkerChart()
	if err != nil {
		return err
	}
	defer cleanup()
	cfg.nodeImageRenderConfig = render
	cluster, operator, err := renderWorkerCluster(ctx, cfg, doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.outputDir, "cluster.yaml"), cluster, 0o644); err != nil {
		return err
	}
	if operator == nil {
		return nil
	}
	return os.WriteFile(filepath.Join(cfg.outputDir, "operator.yaml"), operator, 0o644)
}

// renderWorkerCluster renders the objects a cluster of workers holds for doc,
// and, where its hosts are control-plane nodes, the operator's own objects.
func renderWorkerCluster(ctx context.Context, cfg workerControlPlaneConfig, doc *worker.Document) ([]byte, []byte, error) {
	args := []string{
		"--include-crds",
		"--set-string", "clusterDNS=" + doc.Kubernetes.ClusterDNS,
		"--set-string", "controlPlane.webhook.url=" + operatorWebhookBaseURL(cfg.webhookHost),
	}
	held := workerClusterObjects
	if cfg.podCVMProvider {
		args = append(args, "--set", "operator.podCVMProvider.enabled=true")
		held = slices.Sorted(slices.Values(slices.Concat(held, workerClusterPodCVMProviderObjects)))
	}
	var operatorHeld []string
	if cfg.controlPlaneNodes {
		args = append(args,
			"--set", "operator.deployment.enabled=true",
			"--set-string", "operator.deployment.webhookHost="+cfg.webhookHost,
		)
		operatorHeld = workerOperatorObjects
	}
	rendered, err := templateWorkerChart(ctx, cfg.nodeImageRenderConfig, args...)
	if err != nil {
		return nil, nil, err
	}
	return splitRenderedObjects(rendered, held, operatorHeld)
}

// splitRenderedObjects sorts the render's objects into the two files a
// cluster of workers applies, each object as helm wrote it: cluster.yaml holds
// the objects named in cluster, operator.yaml those named in operator (nil
// without --control-plane-nodes). An object in neither list is an error.
func splitRenderedObjects(rendered []byte, cluster, operator []string) ([]byte, []byte, error) {
	var clusterOut, operatorOut bytes.Buffer
	var held []string
	reader := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(rendered)))
	for {
		document, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("the worker chart's render: %w", err)
		}
		key, err := renderedObjectKey(document)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case key == "" || slices.Contains(workerImageObjects, key):
			continue
		case slices.Contains(cluster, key):
			clusterOut.WriteString("---\n")
			clusterOut.Write(document)
		case slices.Contains(operator, key):
			operatorOut.WriteString("---\n")
			operatorOut.Write(document)
		default:
			return nil, nil, fmt.Errorf("the worker chart renders %s, which a cluster of workers neither holds nor leaves to the image", key)
		}
		held = append(held, key)
	}
	for _, key := range slices.Concat(cluster, operator) {
		if !slices.Contains(held, key) {
			return nil, nil, fmt.Errorf("the worker chart rendered no %s", key)
		}
	}
	if operator == nil {
		return clusterOut.Bytes(), nil, nil
	}
	return clusterOut.Bytes(), operatorOut.Bytes(), nil
}

// renderedObjectKey is the document's object as kind/namespace/name, and "" for
// a document that declares no object.
func renderedObjectKey(document []byte) (string, error) {
	var object struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(document, &object); err != nil {
		return "", fmt.Errorf("the worker chart's render: %w", err)
	}
	if object.Kind == "" {
		return "", nil
	}
	return strings.Join([]string{object.Kind, object.Metadata.Namespace, object.Metadata.Name}, "/"), nil
}

// operatorWebhookBaseURL is the URL the API server reaches the operator's
// webhooks at, which the chart appends each webhook's path to.
func operatorWebhookBaseURL(host string) string {
	return "https://" + net.JoinHostPort(host, webhookPort)
}
