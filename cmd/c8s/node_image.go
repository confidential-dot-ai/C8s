//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
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

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const nodeImageNamespace = "c8s-system"

// nodeImageRenderConfig contains build inputs only. The role, endpoint and
// attested measurement policy are supplied by authenticated boot staging.
type nodeImageRenderConfig struct {
	platform                  string
	kubeVersion               string
	imageDigest               string
	imageRepository           string
	cdsImageDigest            string
	cdsImageRepository        string
	armtlsMeshImageDigest     string
	armtlsMeshImageRepository string
	routerImageDigest         string
	routerImageRepository     string
	chartDir                  string
	outputDir                 string
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
	f.StringVar(&cfg.armtlsMeshImageDigest, "armtls-mesh-image-digest", "", "digest of the armTLS mesh container image (sha256:..., required)")
	f.StringVar(&cfg.armtlsMeshImageRepository, "armtls-mesh-image-repository", "", "armTLS mesh container repository; empty uses the chart default")
	f.StringVar(&cfg.routerImageDigest, "router-image-digest", "", "digest of the nginx container image; empty uses the pinned chart default")
	f.StringVar(&cfg.routerImageRepository, "router-image-repository", "", "nginx container repository; empty uses the chart default")
	f.StringVar(&cfg.chartDir, "chart-dir", "", "chart source directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for c8s-integration.yaml, allowlist-seed.json, images.txt and router-nginx/ (required)")
	cmd.AddCommand(render, newNodeImageCheckImagesCmd())
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
		{flag: "armtls-mesh-image", valuePath: "armtlsMesh.image", repository: cfg.armtlsMeshImageRepository, digest: cfg.armtlsMeshImageDigest, required: true},
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
		// A baked node runs volumed as the host service volumed.service, not
		// the chart DaemonSet, which the chart refuses on a baked node.
		"--set", "volumed.enabled=false",
		"--set", "router.attest.enabled=true",
		// Always on: the value is part of the measured image, and
		// c8s verify --operator-keys reads the publication.
		"--set", "router.routePublication.enabled=true",
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
	if err := os.MkdirAll(filepath.Join(cfg.outputDir, "router-nginx"), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	type artifact struct {
		name string
		body []byte
	}
	files := []artifact{
		{"c8s-integration.yaml", artifacts.integration},
		{"allowlist-seed.json", artifacts.seed},
		{"images.txt", []byte(strings.Join(artifacts.images, "\n") + "\n")},
		{"router-image.txt", []byte(artifacts.routerImage + "\n")},
	}
	for _, name := range routerNginxFiles {
		files = append(files, artifact{filepath.Join("router-nginx", name), []byte(artifacts.routerNginx[name])})
	}
	for _, artifact := range files {
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
	routerNginx map[string]string

	// routerImage is the front door's own image, which the measured base
	// pins for the router role. Only the chart carries that digest.
	routerImage string
}

// routerNginxFiles are the c8s-router-nginx ConfigMap keys the image installs
// in /usr/lib/c8s/router-nginx (the chart's router.bakedNginxDir), where the
// baked router mounts them instead of the ConfigMap.
var routerNginxFiles = []string{"nginx.conf", "reload.sh", "tls-cds.conf", "tls-acme.conf"}

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
		"Deployment/c8s-operator": false,
		"Deployment/c8s-cds":      false,
		"Deployment/c8s-router":   false,
		// The namespace the measured mesh policy names for the router role.
		"Namespace/" + workloadclaims.RouterNamespace:                    false,
		"CustomResourceDefinition/confidentialworkloads.confidential.ai": false,
		"ConfigMap/c8s-router-nginx":                                     false,
		"ConfigMap/c8s-cds-allowlist-seed":                               false,
	}
	seen := make(map[string]bool)
	images := make(map[string]*bakedImage)
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
		if err := requireNodeImageNamespace(&object); err != nil {
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
			if key == routerWorkloadKey {
				image, err := frontDoorImage(object)
				if err != nil {
					return nil, err
				}
				artifacts.routerImage = image
			}
		case "ConfigMap":
			if err := collectConfigMapArtifact(object, key, name, &artifacts); err != nil {
				return nil, err
			}
			if key == "ConfigMap/c8s-router-nginx" {
				// Shipped as image files; a ConfigMap would only be an
				// editable copy nothing mounts.
				required[key] = true
				continue
			}
		case "Namespace", "CustomResourceDefinition", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Service", "PersistentVolumeClaim", "PodDisruptionBudget", "NetworkPolicy", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
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
	if artifacts.routerImage == "" {
		return nil, fmt.Errorf("rendered chart names no front-door image for %s, which the measured base pins", routerWorkloadKey)
	}
	seed, err := pkgallowlist.ParseJSON(artifacts.seed)
	if err != nil {
		return nil, fmt.Errorf("decode node-image bootstrap seed: %w", err)
	}
	// A baked component must start before CDS serves policy, with the
	// arguments and mounts its manifest gives it: the seed must carry an
	// entry for its image with a container admitting each.
	seeded := seedContainers(seed)
	for image, baked := range images {
		if len(seeded[baked.digest]) == 0 {
			return nil, fmt.Errorf("node-image image %s lacks a bootstrap seed entry", image)
		}
		for _, k := range baked.containers {
			if !slices.ContainsFunc(seeded[baked.digest], func(c pkgallowlist.Container) bool { return admitsBaked(c, baked.digest, k, nil) }) {
				if len(k.command) == 0 {
					return nil, fmt.Errorf("node-image image %s: container %s runs the image's entrypoint, which the bootstrap seed cannot check: give it an explicit command", image, k.name)
				}
				return nil, fmt.Errorf("node-image image %s: the bootstrap seed does not admit container %s with argv %q, mounts %+v and the env its manifest, image and runtime set", image, k.name, k.argv(), k.mounts)
			}
		}
		artifacts.images = append(artifacts.images, image)
	}
	slices.Sort(artifacts.images)
	artifacts.integration = manifests.Bytes()
	return &artifacts, nil
}

// seedContainers indexes the seed's containers by image digest.
func seedContainers(seed *pkgallowlist.Allowlist) map[string][]pkgallowlist.Container {
	seeded := make(map[string][]pkgallowlist.Container)
	for _, workload := range seed.Workloads {
		for _, c := range append(workload.InitContainers, workload.Containers...) {
			seeded[c.Digest.String()] = append(seeded[c.Digest.String()], c)
		}
	}
	return seeded
}

// nodeImageResourceNamespaces is where the chart must place each namespaced
// resource a baked node runs: the release namespace, except the router's own
// resources, whose pods serve the router role's ports from the namespace the
// measured mesh policy names.
var nodeImageResourceNamespaces = map[string]string{
	"Deployment/c8s-operator":          nodeImageNamespace,
	"Deployment/c8s-cds":               nodeImageNamespace,
	"ConfigMap/c8s-cds-allowlist-seed": nodeImageNamespace,
	routerWorkloadKey:                  workloadclaims.RouterNamespace,
	"Service/c8s-router":               workloadclaims.RouterNamespace,
	"ConfigMap/c8s-router-nginx":       workloadclaims.RouterNamespace,
	"NetworkPolicy/c8s-router-ingress": workloadclaims.RouterNamespace,
}

// requireNodeImageNamespace rejects a namespaced resource the chart placed
// anywhere but its own namespace, and a cluster-scoped kind carrying a
// namespace at all. The chart is what names the namespace of every namespaced
// resource.
func requireNodeImageNamespace(object *unstructured.Unstructured) error {
	kind, name := object.GetKind(), object.GetName()
	key := kind + "/" + name
	if !namespacedNodeImageKind(kind) {
		if object.GetNamespace() != "" {
			return fmt.Errorf("cluster-scoped node-image resource %s has a namespace", key)
		}
		return nil
	}
	want, named := nodeImageResourceNamespaces[key]
	if !named {
		want = nodeImageNamespace
	}
	if got := object.GetNamespace(); got != want {
		return fmt.Errorf("node-image resource %s has namespace %q, want %q", key, got, want)
	}
	return nil
}

// bakedImage is one container image a baked workload runs: its digest and
// every container that runs it.
type bakedImage struct {
	digest     string
	containers []bakedContainer
}

// bakedContainer is what a manifest says one container runs: an explicit
// command, or the image's entrypoint, with its args and the mount rule each of
// its volume mounts needs; the variables it sets; and whether it also imports
// some (envFrom) or receives the namespace's Service variables (service links
// not disabled), whose names this cannot resolve.
type bakedContainer struct {
	name         string
	command      []string
	args         []string
	mounts       []pkgallowlist.MountRule
	env          []bakedVariable
	envFrom      bool
	serviceLinks bool
}

// bakedVariable is one variable a manifest sets. literal is false for a value
// taken from a reference (fieldRef, secretKeyRef, ...), unknown here;
// optional marks a key reference the kubelet skips when the key is missing.
type bakedVariable struct {
	name, value       string
	literal, optional bool
}

func (k bakedContainer) argv() []string {
	return slices.Concat(k.command, k.args)
}

// admitsBaked reports whether a seed container admits a baked one. A
// container without a command runs the image's ENTRYPOINT and, without args,
// its CMD, neither of which the manifest shows: only a seed leaving command
// and args any admits it. The mount check compares the rules the manifest implies; whether
// the storage behind a volume is memory or encrypted is the node's to see.
// image is the image config's environment, nil when unknown (seedEnvAdmits).
func admitsBaked(c pkgallowlist.Container, digest string, k bakedContainer, image map[string]string) bool {
	switch c.Env.Policy {
	case "", pkgallowlist.PolicyAny:
	case pkgallowlist.PolicyMatch:
		if !seedEnvAdmits(c.Env, k, image) {
			return false
		}
	default:
		return false
	}
	argv := k.argv()
	if len(k.command) == 0 && (c.Command.Policy != pkgallowlist.PolicyAny || c.Args.Policy != pkgallowlist.PolicyAny) {
		return false
	}
	one := pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{"c": {Containers: []pkgallowlist.Container{c}}}}
	if !one.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
		return false
	}
	switch c.Mounts.Policy {
	case pkgallowlist.PolicyAny:
		return true
	case pkgallowlist.PolicyExact:
		byDestination := func(a, b pkgallowlist.MountRule) int { return strings.Compare(a.Destination, b.Destination) }
		return slices.Equal(slices.SortedFunc(slices.Values(c.Mounts.Rules), byDestination), slices.SortedFunc(slices.Values(k.mounts), byDestination))
	default:
		return len(k.mounts) == 0
	}
}

// seedEnvAdmits reports whether a match env policy admits k's launch
// environment (launchEnvironment): every variable is listed, every exact pin
// agrees with a value known here, and every listed variable is set. With the
// image's environment unknown, a variable the seed pins exact and the launch
// environment leaves to the image is taken to be the image's; check-images
// confirms it against the preloaded image.
func seedEnvAdmits(seed pkgallowlist.EnvPolicy, k bakedContainer, image map[string]string) bool {
	env, ok := launchEnvironment(k, image)
	if !ok {
		return false
	}
	exact := seed.ExactValues()
	for name, v := range env {
		if _, listed := seed.Variables[name]; !listed {
			return false
		}
		want, pinned := exact[name]
		if pinned && (v.source == sourceDynamic || v.source == sourceKnown && v.value != want) {
			return false
		}
	}
	for name := range seed.Variables {
		if _, set := env[name]; set {
			continue
		}
		if _, pinned := exact[name]; !pinned || image != nil {
			return false
		}
	}
	return true
}

// launchValue is one variable of a launch environment and where its value
// comes from.
type launchValue struct {
	value  string
	source valueSource
}

type valueSource int

const (
	// sourceKnown is a value fixed before the container starts.
	sourceKnown valueSource = iota
	// sourceDynamic is a value set per pod or node, which no exact pin can
	// be checked against.
	sourceDynamic
	// sourceImage is the image's value, or the runtime's when the image sets
	// none, unknown until check-images reads the image.
	sourceImage
)

// launchEnvironment is the environment k starts with, applied in the
// runtime's order, each source overriding the one before: containerd's
// HOSTNAME, the image's variables (containerd's default PATH when it sets
// none), the kubelet's API-server variables, then the manifest's. It is not
// ok when the manifest imports variables (envFrom), sets one through an
// optional key reference, or leaves service links on: which variables are
// set is then unknown.
func launchEnvironment(k bakedContainer, image map[string]string) (map[string]launchValue, bool) {
	if k.envFrom || k.serviceLinks {
		return nil, false
	}
	env := map[string]launchValue{"HOSTNAME": {source: sourceDynamic}}
	if image == nil {
		env["HOSTNAME"] = launchValue{source: sourceImage}
		env["PATH"] = launchValue{source: sourceImage}
	} else {
		env["PATH"] = launchValue{value: containerdDefaultPath}
		for name, value := range image {
			env[name] = launchValue{value: value}
		}
	}
	for name, value := range kubeletVariables {
		if value == "" {
			env[name] = launchValue{source: sourceDynamic}
		} else {
			env[name] = launchValue{value: value}
		}
	}
	for _, v := range k.env {
		if v.optional {
			return nil, false
		}
		if v.literal && !kubeletExpands(v.value) {
			env[v.name] = launchValue{value: v.value}
		} else {
			env[v.name] = launchValue{source: sourceDynamic}
		}
	}
	return env, true
}

func optionalReference(source *corev1.EnvVarSource) bool {
	if source == nil {
		return false
	}
	if ref := source.SecretKeyRef; ref != nil && ref.Optional != nil && *ref.Optional {
		return true
	}
	ref := source.ConfigMapKeyRef
	return ref != nil && ref.Optional != nil && *ref.Optional
}

// kubeletExpands reports whether the kubelet rewrites value before the
// container sees it: $(VAR) references and $$ escapes.
func kubeletExpands(value string) bool {
	return strings.Contains(value, "$(") || strings.Contains(value, "$$")
}

// kubeletVariables are the variables the kubelet sets in every container
// with service links off: those of the default namespace's kubernetes
// Service, whose port kube-apiserver fixes at 443. An empty value differs
// per cluster. Keep in step with c8s.runtimeEnv in the chart.
var kubeletVariables = map[string]string{
	"KUBERNETES_SERVICE_HOST":       "",
	"KUBERNETES_SERVICE_PORT":       "443",
	"KUBERNETES_SERVICE_PORT_HTTPS": "443",
	"KUBERNETES_PORT":               "",
	"KUBERNETES_PORT_443_TCP":       "",
	"KUBERNETES_PORT_443_TCP_ADDR":  "",
	"KUBERNETES_PORT_443_TCP_PORT":  "443",
	"KUBERNETES_PORT_443_TCP_PROTO": "tcp",
}

// containerdDefaultPath is the PATH containerd sets when the image sets none
// (oci.WithDefaultPathEnv).
const containerdDefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// mountRule is the rule a pod-spec volume mount needs: a host rule naming the
// hostPath and the access mode, an emptyDir rule, or a data rule for
// operator-supplied content. A subpath of any volume, and a reserved volumed
// placeholder emptyDir, is data, as the node classifies them. It fails on a
// source no rule describes.
func mountRule(m corev1.VolumeMount, volumes map[string]corev1.Volume) (pkgallowlist.MountRule, error) {
	v, ok := volumes[m.Name]
	if !ok {
		return pkgallowlist.MountRule{}, fmt.Errorf("mount %q names no volume", m.Name)
	}
	rule := pkgallowlist.MountRule{Destination: m.MountPath}
	switch {
	case m.SubPath != "" || m.SubPathExpr != "", v.EmptyDir != nil && strings.HasPrefix(v.Name, volume.KubeVolumePrefix):
		rule.Kind = pkgallowlist.MountData
	case v.HostPath != nil:
		rule.Kind, rule.Source, rule.ReadOnly = pkgallowlist.MountHost, v.HostPath.Path, m.ReadOnly
	case v.EmptyDir != nil:
		rule.Kind = pkgallowlist.MountEmptyDir
	case v.ConfigMap != nil, v.Secret != nil, v.Projected != nil, v.DownwardAPI != nil, v.PersistentVolumeClaim != nil:
		rule.Kind = pkgallowlist.MountData
	default:
		return pkgallowlist.MountRule{}, fmt.Errorf("mount %q has a volume source no mount rule describes", m.Name)
	}
	return rule, nil
}
func namespacedNodeImageKind(kind string) bool {
	return slices.Contains([]string{
		"Deployment", "DaemonSet", "ConfigMap", "ServiceAccount", "Role", "RoleBinding",
		"Service", "PersistentVolumeClaim", "PodDisruptionBudget", "NetworkPolicy",
	}, kind)
}

// routerWorkloadKey is the workload whose front-door container the measured
// base pins (node-guest-image/c8s/image-policy.yaml.in).
const routerWorkloadKey = "Deployment/c8s-router"

// frontDoorImage is the image the router's nginx container runs. The node
// image measures that digest for the router role, and the chart is the only
// place it is pinned (values.yaml router.nginx.image).
func frontDoorImage(object unstructured.Unstructured) (string, error) {
	containers, found, err := unstructured.NestedSlice(object.Object, "spec", "template", "spec", "containers")
	if err != nil {
		return "", fmt.Errorf("node-image workload %s containers: %w", routerWorkloadKey, err)
	}
	if !found {
		return "", fmt.Errorf("node-image workload %s declares no containers", routerWorkloadKey)
	}
	for _, entry := range containers {
		container, isMap := entry.(map[string]any)
		if !isMap {
			return "", fmt.Errorf("node-image workload %s declares a container that is not an object", routerWorkloadKey)
		}
		if name, _ := container["name"].(string); name != frontDoorContainerName {
			continue
		}
		image, _ := container["image"].(string)
		if image == "" {
			return "", fmt.Errorf("node-image workload %s container %q runs no pinned image", routerWorkloadKey, frontDoorContainerName)
		}
		return image, nil
	}
	return "", fmt.Errorf("node-image workload %s runs no %q container", routerWorkloadKey, frontDoorContainerName)
}

// frontDoorContainerName is the router container that answers external
// traffic, as the chart names it (templates/router-deployment.yaml).
const frontDoorContainerName = "nginx"

// collectWorkloadImages records every container image a baked workload runs,
// keyed by reference. The rootfs preloads exactly these, so an unpinned or
// tag-only image would leave the node pulling at boot: reject it here.
func collectWorkloadImages(object unstructured.Unstructured, key string, images map[string]*bakedImage) error {
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
	volumes := make(map[string]corev1.Volume, len(spec.Volumes))
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		baked, err := recordPinnedImage(c.Image, key, c.Name, images)
		if err != nil {
			return err
		}
		if err := collectInjectedImages(c, key, images); err != nil {
			return err
		}
		command, err := pkgallowlist.KubeletArgv(c.Command)
		if err != nil {
			return fmt.Errorf("node-image workload %s container %q command: %w", key, c.Name, err)
		}
		args, err := pkgallowlist.KubeletArgv(c.Args)
		if err != nil {
			return fmt.Errorf("node-image workload %s container %q args: %w", key, c.Name, err)
		}
		k := bakedContainer{name: c.Name, command: command, args: args, envFrom: len(c.EnvFrom) > 0, serviceLinks: spec.EnableServiceLinks == nil || *spec.EnableServiceLinks}
		for _, e := range c.Env {
			k.env = append(k.env, bakedVariable{name: e.Name, value: e.Value, literal: e.ValueFrom == nil, optional: optionalReference(e.ValueFrom)})
		}
		for _, m := range c.VolumeMounts {
			rule, err := mountRule(m, volumes)
			if err != nil {
				return fmt.Errorf("node-image workload %s container %q: %w", key, c.Name, err)
			}
			k.mounts = append(k.mounts, rule)
		}
		baked.containers = append(baked.containers, k)
	}
	return nil
}

// collectInjectedImages records what a workload injects rather than runs: the
// operator names the mesh endpoint's image, which every pod on this node will
// run, so the rootfs must preload it too. A container naming no mesh image
// injects nothing; one that names it must name an image, or the first tenant
// pod would pull at runtime.
func collectInjectedImages(c corev1.Container, key string, images map[string]*bakedImage) error {
	image, named := meshImageArg(append(c.Command, c.Args...))
	if !named {
		return nil
	}
	if image == "" {
		return fmt.Errorf("node-image workload %s container %q names %s without an image", key, c.Name, meshImageFlag)
	}
	_, err := recordPinnedImage(image, key, c.Name+" "+meshImageFlag, images)
	return err
}

// meshImageArg is the image the mesh-image flag names in one argument vector,
// and whether the vector names it at all. The operator's arguments are
// chart-rendered, so --mesh-image=<image> is the form that reaches here.
func meshImageArg(args []string) (string, bool) {
	for _, arg := range args {
		if image, named := strings.CutPrefix(arg, meshImageFlag+"="); named {
			return image, true
		}
	}
	return "", false
}

// meshImageFlag is the operator argument naming the image every covered pod
// runs (internal/webhook).
const meshImageFlag = "--mesh-image"

// recordPinnedImage records one pinned image and returns its entry, so the
// caller can append the containers the chart runs under it.
func recordPinnedImage(image, key, name string, images map[string]*bakedImage) (*bakedImage, error) {
	ref, err := reference.ParseDockerRef(image)
	if err != nil {
		return nil, fmt.Errorf("node-image workload %s container %q image: %w", key, name, err)
	}
	pinned, ok := ref.(reference.Canonical)
	if !ok || !nodeImageDigestPattern.MatchString(pinned.Digest().String()) {
		return nil, fmt.Errorf("node-image workload %s container %q image must be pinned by sha256 digest", key, name)
	}
	baked := images[ref.String()]
	if baked == nil {
		baked = &bakedImage{digest: pinned.Digest().String()}
		images[ref.String()] = baked
	}
	return baked, nil
}

// collectConfigMapArtifact lifts the two ConfigMaps the build consumes as
// files: the CDS bootstrap seed, which is written beside the manifests, and
// the router's nginx configuration (routerNginxFiles).
func collectConfigMapArtifact(object unstructured.Unstructured, key, name string, artifacts *nodeImageArtifacts) error {
	if key != "ConfigMap/c8s-cds-allowlist-seed" && key != "ConfigMap/c8s-router-nginx" {
		return nil
	}
	var cm corev1.ConfigMap
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &cm); err != nil {
		return fmt.Errorf("decode chart ConfigMap %q: %w", name, err)
	}
	if name == "c8s-cds-allowlist-seed" {
		// Baked and published in canonical bytes, so the release asset of
		// each variant (docs/releases.md) is byte for byte the measured file.
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			return fmt.Errorf("decode node-image bootstrap seed: %w", err)
		}
		if artifacts.seed, err = seed.Canonical(); err != nil {
			return fmt.Errorf("encode node-image bootstrap seed: %w", err)
		}
		return unstructured.SetNestedField(object.Object, string(artifacts.seed), "data", "allowlist-seed.json")
	}
	if len(cm.Data) != len(routerNginxFiles) {
		return fmt.Errorf("rendered nginx ConfigMap has keys %v, want %v", slices.Sorted(maps.Keys(cm.Data)), routerNginxFiles)
	}
	for _, file := range routerNginxFiles {
		if cm.Data[file] == "" {
			return fmt.Errorf("rendered nginx ConfigMap has no %s", file)
		}
	}
	artifacts.routerNginx = cm.Data
	return nil
}
