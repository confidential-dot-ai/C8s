//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/version"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const nodeImageNamespace = "c8s-system"

// nodeImageRenderConfig contains build inputs only. The role, endpoint and
// attested measurement policy are supplied by authenticated boot staging.
type nodeImageRenderConfig struct {
	platform                 string
	kubeVersion              string
	imageDigest              string
	imageRepository          string
	cdsImageDigest           string
	cdsImageRepository       string
	ratlsMeshImageDigest     string
	ratlsMeshImageRepository string
	routerImageDigest        string
	routerImageRepository    string
	chartDir                 string
	outputDir                string
}

func init() {
	rootCmd.AddCommand(newNodeImageCmd())
}

func newNodeImageCmd() *cobra.Command {
	var cfg nodeImageRenderConfig
	cmd := &cobra.Command{Use: "node-image", Short: "Build measured node-image integration artifacts"}
	render := &cobra.Command{
		Use:   "render",
		Short: "Render core Kubernetes workloads and their pinned image inventory at image build time",
		Long:  "Render the bundled chart as complete Kubernetes manifests for the measured node image. Requires Helm at build time; no Helm is installed or run in the guest. Authenticated launch settings are mounted read-only from /run/c8s-node at boot.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return renderNodeImage(cmd.Context(), cfg)
		},
	}
	f := render.Flags()
	f.StringVar(&cfg.platform, "hardware-platform", "", "CPU TEE: tdx or sev-snp (required)")
	f.StringVar(&cfg.kubeVersion, "kube-version", "", "Kubernetes semantic version from the baked RKE2 release (required)")
	f.StringVar(&cfg.imageDigest, "image-digest", "", "digest of the operator/get-cert container image (sha256:..., required)")
	f.StringVar(&cfg.imageRepository, "image-repository", "", "operator/get-cert container repository; empty uses the chart default")
	f.StringVar(&cfg.cdsImageDigest, "cds-image-digest", "", "digest of the CDS container image (sha256:..., required)")
	f.StringVar(&cfg.cdsImageRepository, "cds-image-repository", "", "CDS container repository; empty uses the chart default")
	f.StringVar(&cfg.ratlsMeshImageDigest, "ratls-mesh-image-digest", "", "digest of the RA-TLS mesh container image (sha256:..., required)")
	f.StringVar(&cfg.ratlsMeshImageRepository, "ratls-mesh-image-repository", "", "RA-TLS mesh container repository; empty uses the chart default")
	f.StringVar(&cfg.routerImageDigest, "router-image-digest", "", "digest of the nginx container image; empty uses the pinned chart default")
	f.StringVar(&cfg.routerImageRepository, "router-image-repository", "", "nginx container repository; empty uses the chart default")
	f.StringVar(&cfg.chartDir, "chart-dir", "", "chart source directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for c8s-integration.yaml, allowlist-seed.json and images.txt (required)")
	cmd.AddCommand(render)
	return cmd
}

var nodeImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (cfg nodeImageRenderConfig) validate() error {
	if err := validateHardwarePlatform(cfg.platform); err != nil {
		return err
	}
	if _, err := version.ParseSemantic(cfg.kubeVersion); err != nil {
		return fmt.Errorf("--kube-version must specify the baked Kubernetes semantic version: %w", err)
	}
	for _, input := range cfg.images() {
		if (input.required || input.digest != "") && !nodeImageDigestPattern.MatchString(input.digest) {
			return fmt.Errorf("--%s-digest must be sha256 followed by 64 lowercase hexadecimal digits", input.flag)
		}
		if input.repository == "" {
			continue
		}
		repo, err := reference.ParseNormalizedNamed(input.repository)
		if err != nil {
			return fmt.Errorf("--%s-repository: %w", input.flag, err)
		}
		if !reference.IsNameOnly(repo) {
			return fmt.Errorf("--%s-repository must not contain a tag or digest; use --%s-digest", input.flag, input.flag)
		}
	}
	if cfg.outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}
	return nil
}

// nodeImageInput ties one image build flag to the chart value it pins.
type nodeImageInput struct {
	flag       string // build flag prefix, e.g. "cds-image"
	valuePath  string // chart value the repository and digest are set under
	repository string
	digest     string
	required   bool // the image must be pinned for the render to succeed
}

// images maps build flags to the chart's authoritative image values.
func (cfg nodeImageRenderConfig) images() []nodeImageInput {
	return []nodeImageInput{
		{flag: "image", valuePath: "image", repository: cfg.imageRepository, digest: cfg.imageDigest, required: true},
		{flag: "cds-image", valuePath: "cds.image", repository: cfg.cdsImageRepository, digest: cfg.cdsImageDigest, required: true},
		{flag: "ratls-mesh-image", valuePath: "ratlsMesh.image", repository: cfg.ratlsMeshImageRepository, digest: cfg.ratlsMeshImageDigest, required: true},
		{flag: "router-image", valuePath: "router.nginx.image", repository: cfg.routerImageRepository, digest: cfg.routerImageDigest},
	}
}

func renderNodeImage(ctx context.Context, cfg nodeImageRenderConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	chartDir := cfg.chartDir
	if chartDir == "" {
		tmp, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract node integration chart: %w", err)
		}
		defer os.RemoveAll(tmp)
		chartDir = filepath.Join(tmp, helmchart.ChartRoot)
	}
	args, err := appendCvmModeInstallArgs(nil, "bare-metal", cfg.platform)
	if err != nil {
		return err
	}
	args = appendDistroInstallArgs(args, "rke2")
	args = appendSingleNodeInstallArgs(args, true)
	args = append(args,
		"--set", "node.baked=true",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		// volumed is deployed per cluster with `c8s install --volumes`, not
		// baked: it needs the operator's kubelet-root and cgroup host paths,
		// which are not known at build time. A baked node therefore serves
		// plain PVCs through local-path; encrypted volumes (docs/volumes.md)
		// require that separate install.
		"--set", "volumed.enabled=false",
		"--set", "router.attest.enabled=true",
	)
	for _, input := range cfg.images() {
		args = append(args, "--set-string", input.valuePath+".pullPolicy=Never")
		if input.repository != "" {
			args = append(args, "--set-string", input.valuePath+".repository="+input.repository)
		}
		if input.digest != "" {
			args = append(args, "--set-string", input.valuePath+".digest="+input.digest)
		}
	}
	args = append([]string{"template", "c8s", chartDir, "--namespace", nodeImageNamespace, "--kube-version", cfg.kubeVersion, "--include-crds"}, args...)
	helm := exec.CommandContext(ctx, "helm", args...)
	var stderr bytes.Buffer
	helm.Stderr = &stderr
	rendered, err := helm.Output()
	if err != nil {
		return fmt.Errorf("render node integration with helm: %w: %s", err, stderr.String())
	}
	artifacts, err := collectNodeImageArtifacts(rendered)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for _, artifact := range []struct {
		name string
		body []byte
	}{
		{"c8s-integration.yaml", artifacts.integration},
		{"allowlist-seed.json", artifacts.seed},
		{"images.txt", []byte(strings.Join(artifacts.images, "\n") + "\n")},
	} {
		if err := os.WriteFile(filepath.Join(cfg.outputDir, artifact.name), artifact.body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", artifact.name, err)
		}
	}
	return nil
}

type nodeImageArtifacts struct {
	integration []byte
	seed        []byte
	images      []string
}

// collectNodeImageArtifacts retains complete chart resources and copies the seed
// for host NRI bootstrap. Every workload image must be pinned and present in the
// seed; the same inventory drives image preloading into the measured rootfs.
func collectNodeImageArtifacts(rendered []byte) (*nodeImageArtifacts, error) {
	namespace, err := yaml.Marshal(corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeImageNamespace,
			Labels: map[string]string{
				"confidential.ai/baked":              "true",
				"pod-security.kubernetes.io/enforce": "privileged",
				"pod-security.kubernetes.io/warn":    "privileged",
				"pod-security.kubernetes.io/audit":   "privileged",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode node namespace: %w", err)
	}
	var artifacts nodeImageArtifacts
	var manifests bytes.Buffer
	manifests.Write(namespace)
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	required := map[string]bool{
		"Deployment/c8s-operator":  false,
		"Deployment/c8s-cds":       false,
		"Deployment/c8s-router":    false,
		"DaemonSet/c8s-ratls-mesh": false,
		"CustomResourceDefinition/confidentialworkloads.confidential.ai": false,
		"ConfigMap/c8s-router-nginx":                                     false,
		"ConfigMap/c8s-cds-allowlist-seed":                               false,
	}
	seen := make(map[string]bool)
	images := make(map[string]string)
	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode rendered chart: %w", err)
		}
		if len(raw.Raw) == 0 || bytes.Equal(raw.Raw, []byte("null")) {
			continue
		}
		var object unstructured.Unstructured
		if err := object.UnmarshalJSON(raw.Raw); err != nil {
			return nil, fmt.Errorf("decode chart resource: %w", err)
		}
		kind, name := object.GetKind(), object.GetName()
		if object.GetAPIVersion() == "" || kind == "" || name == "" {
			return nil, fmt.Errorf("rendered chart resource requires apiVersion, kind and metadata.name")
		}
		if err := setNodeImageNamespace(&object); err != nil {
			return nil, err
		}
		key := kind + "/" + name
		if seen[key] {
			return nil, fmt.Errorf("duplicate node-image resource %s", key)
		}
		seen[key] = true
		switch kind {
		case "Deployment", "DaemonSet":
			if _, expected := required[key]; !expected {
				return nil, fmt.Errorf("unexpected node-image workload %s", key)
			}
			if err := collectWorkloadImages(object, key, images); err != nil {
				return nil, err
			}
		case "ConfigMap":
			if err := collectConfigMapArtifact(object, key, name, &artifacts); err != nil {
				return nil, err
			}
		case "CustomResourceDefinition", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Service", "PersistentVolumeClaim", "PodDisruptionBudget", "NetworkPolicy", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
		default:
			return nil, fmt.Errorf("unexpected node-image resource %s", key)
		}
		if _, needed := required[key]; needed {
			required[key] = true
		}
		doc, err := yaml.Marshal(object.Object)
		if err != nil {
			return nil, fmt.Errorf("encode node-image resource %s: %w", key, err)
		}
		manifests.WriteString("---\n")
		manifests.Write(doc)
	}
	for key, found := range required {
		if !found {
			return nil, fmt.Errorf("rendered chart lacks required node-image resource %s", key)
		}
	}
	seed, err := pkgallowlist.ParseJSON(artifacts.seed)
	if err != nil {
		return nil, fmt.Errorf("decode node-image bootstrap seed: %w", err)
	}
	seedDigests := make(map[string]bool)
	for _, workload := range seed.Workloads {
		for _, c := range append(workload.InitContainers, workload.Containers...) {
			if c.IsUnconstrained() {
				seedDigests[c.Digest.String()] = true
			}
		}
	}
	for image, digest := range images {
		if !seedDigests[digest] {
			return nil, fmt.Errorf("node-image image %s lacks an unrestricted bootstrap seed entry", image)
		}
		artifacts.images = append(artifacts.images, image)
	}
	slices.Sort(artifacts.images)
	artifacts.integration = manifests.Bytes()
	return &artifacts, nil
}

// setNodeImageNamespace pins a namespaced resource to the node-image namespace
// and rejects one the chart placed elsewhere. Cluster-scoped kinds must carry
// no namespace at all, so a namespaced rendering of them is an error.
func setNodeImageNamespace(object *unstructured.Unstructured) error {
	kind, name := object.GetKind(), object.GetName()
	switch kind {
	case "Deployment", "DaemonSet", "ConfigMap", "ServiceAccount", "Role", "RoleBinding", "Service", "PersistentVolumeClaim", "PodDisruptionBudget", "NetworkPolicy":
		if namespace := object.GetNamespace(); namespace != "" && namespace != nodeImageNamespace {
			return fmt.Errorf("node-image resource %s/%s has unexpected namespace %q", kind, name, namespace)
		}
		object.SetNamespace(nodeImageNamespace)
	default:
		if object.GetNamespace() != "" {
			return fmt.Errorf("cluster-scoped node-image resource %s/%s has a namespace", kind, name)
		}
	}
	return nil
}

// collectWorkloadImages records every container image a baked workload runs,
// keyed by reference. The rootfs preloads exactly these, so an unpinned or
// tag-only image would leave the node pulling at boot: reject it here.
func collectWorkloadImages(object unstructured.Unstructured, key string, images map[string]string) error {
	pod, found, err := unstructured.NestedMap(object.Object, "spec", "template", "spec")
	if err != nil || !found {
		return fmt.Errorf("node-image workload %s lacks a valid pod spec", key)
	}
	var spec corev1.PodSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(pod, &spec); err != nil {
		return fmt.Errorf("decode node-image workload %s: %w", key, err)
	}
	if len(spec.Containers) == 0 || len(spec.EphemeralContainers) != 0 {
		return fmt.Errorf("node-image workload %s requires containers and no ephemeral containers", key)
	}
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		ref, err := reference.ParseDockerRef(c.Image)
		if err != nil {
			return fmt.Errorf("node-image workload %s container %q image: %w", key, c.Name, err)
		}
		pinned, ok := ref.(reference.Canonical)
		if !ok || !nodeImageDigestPattern.MatchString(pinned.Digest().String()) {
			return fmt.Errorf("node-image workload %s container %q image must be pinned by sha256 digest", key, c.Name)
		}
		images[ref.String()] = pinned.Digest().String()
	}
	return nil
}

// collectConfigMapArtifact lifts the two ConfigMaps the build consumes as
// files: the CDS bootstrap seed, which is written beside the manifests, and
// the router's nginx.conf, which is only checked for being non-empty.
func collectConfigMapArtifact(object unstructured.Unstructured, key, name string, artifacts *nodeImageArtifacts) error {
	if key != "ConfigMap/c8s-cds-allowlist-seed" && key != "ConfigMap/c8s-router-nginx" {
		return nil
	}
	var cm corev1.ConfigMap
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &cm); err != nil {
		return fmt.Errorf("decode chart ConfigMap %q: %w", name, err)
	}
	if name == "c8s-cds-allowlist-seed" {
		artifacts.seed = []byte(cm.Data["allowlist-seed.json"])
	} else if cm.Data["nginx.conf"] == "" {
		return fmt.Errorf("rendered nginx ConfigMap has no nginx.conf")
	}
	return nil
}
