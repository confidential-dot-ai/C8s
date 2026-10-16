//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
		// Both CDS Deployments are baked; the signed launch document selects
		// which one runs (cds-role nodes, or the singleton on the server).
		"--set", "cds.ha.enabled=true",
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
		{"cds-floor.json", artifacts.cdsFloor},
		{"c8s-cds-singleton.yaml", artifacts.cdsSingleton},
		{"c8s-cds-ha.yaml", artifacts.cdsHA},
	} {
		if len(artifact.body) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(cfg.outputDir, artifact.name), artifact.body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", artifact.name, err)
		}
	}
	return nil
}

type nodeImageArtifacts struct {
	integration []byte
	// cdsSingleton and cdsHA hold the objects only one CDS flavour needs; the
	// server's node-services skips the file the launch document did not pick.
	cdsSingleton []byte
	cdsHA        []byte
	seed         []byte
	images       []string
	// cdsFloor is the NRI floor a cds-role node admits instead of the seed:
	// the HA CDS container pinned exactly, plus the DaemonSets every node runs.
	// Empty when the chart renders no HA CDS.
	cdsFloor []byte
}

// cdsFloorContainer is a container that may run on a cds-role node.
type cdsFloorContainer struct {
	key       string // workload, for the entry name
	container corev1.Container
	digest    string
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
		"Deployment/c8s-operator":   false,
		"Deployment/c8s-cds":        false,
		"Deployment/c8s-router":     false,
		"DaemonSet/c8s-armtls-mesh": false,
		"CustomResourceDefinition/confidentialworkloads.confidential.ai": false,
		"ConfigMap/c8s-router-nginx":                                     false,
		"ConfigMap/c8s-cds-allowlist-seed":                               false,
	}
	// Workloads the chart may render without being required by every render.
	optional := map[string]bool{"DaemonSet/c8s-cds-ha": true}
	seen := make(map[string]bool)
	images := make(map[string]*bakedImage)
	var cdsNode []cdsFloorContainer // containers a cds-role node runs
	var singleton, ha bytes.Buffer
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
			if _, expected := required[key]; !expected && !optional[key] {
				return nil, fmt.Errorf("unexpected node-image workload %s", key)
			}
			if err := collectWorkloadImages(object, key, images); err != nil {
				return nil, err
			}
			if kind == "DaemonSet" {
				containers, err := podContainers(object, key)
				if err != nil {
					return nil, err
				}
				cdsNode = append(cdsNode, containers...)
			}
		case "ConfigMap":
			if err := collectConfigMapArtifact(object, key, name, &artifacts); err != nil {
				return nil, err
			}
		case "Namespace":
			// The chart's own namespace is added by the collector; others
			// (the HA CDS decree namespace) are kept as rendered.
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
		out := &manifests
		switch flavour := cdsFlavour(object); flavour {
		case "singleton":
			out = &singleton
		case "ha":
			out = &ha
		}
		out.WriteString("---\n")
		out.Write(doc)
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
	// A baked component must start before CDS serves policy, with the
	// arguments, environment and mounts its manifest gives it: the seed must
	// leave those to the pod and pin at most the executable, and a pin must
	// admit every invocation the manifests spell out.
	seedDigests := make(map[string]bool)
	for _, workload := range seed.Workloads {
		for _, c := range append(workload.InitContainers, workload.Containers...) {
			if c.PinsAtMostCommand() {
				seedDigests[c.Digest.String()] = true
			}
		}
	}
	index := seed.BuildIndex()
	for image, baked := range images {
		if !seedDigests[baked.digest] {
			return nil, fmt.Errorf("node-image image %s lacks a bootstrap seed entry that leaves its args, env and mounts unconstrained", image)
		}
		for _, argv := range baked.argvs {
			if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: baked.digest, Argv: argv}) {
				return nil, fmt.Errorf("node-image image %s: the bootstrap seed does not admit the baked command %q", image, argv)
			}
		}
		artifacts.images = append(artifacts.images, image)
	}
	slices.Sort(artifacts.images)
	artifacts.integration = manifests.Bytes()
	artifacts.cdsSingleton, artifacts.cdsHA = singleton.Bytes(), ha.Bytes()
	if seen["DaemonSet/c8s-cds-ha"] {
		floor, err := buildCDSFloor(seed, cdsNode)
		if err != nil {
			return nil, err
		}
		artifacts.cdsFloor = floor
	}
	return &artifacts, nil
}

// cdsFlavour assigns the objects only one CDS flavour uses: the singleton
// Deployment, and everything the HA chart template renders (labelled
// c8s.confidential.ai/cds-ha, or named after it). Shared objects return "".
func cdsFlavour(object unstructured.Unstructured) string {
	key := object.GetKind() + "/" + object.GetName()
	switch {
	case key == "Deployment/c8s-cds":
		return "singleton"
	case key == "DaemonSet/c8s-cds-ha", key == "Service/c8s-cds-peers", key == "NetworkPolicy/c8s-cds-ha-peers",
		key == "Role/c8s-cds-ha", key == "RoleBinding/c8s-cds-ha", key == "Role/c8s-cds-decrees",
		key == "RoleBinding/c8s-cds-decrees", key == "Namespace/"+nodeImageDecreeNamespace:
		return "ha"
	}
	return ""
}

// podContainers lists a workload's containers with their pinned digests.
func podContainers(object unstructured.Unstructured, key string) ([]cdsFloorContainer, error) {
	pod, _, err := unstructured.NestedMap(object.Object, "spec", "template", "spec")
	if err != nil {
		return nil, fmt.Errorf("node-image workload %s: %w", key, err)
	}
	var spec corev1.PodSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(pod, &spec); err != nil {
		return nil, fmt.Errorf("decode node-image workload %s: %w", key, err)
	}
	var out []cdsFloorContainer
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		ref, err := reference.ParseDockerRef(c.Image)
		if err != nil {
			return nil, err
		}
		pinned, ok := ref.(reference.Canonical)
		if !ok {
			return nil, fmt.Errorf("node-image workload %s container %q is not digest-pinned", key, c.Name)
		}
		out = append(out, cdsFloorContainer{key: key, container: c, digest: pinned.Digest().String()})
	}
	return out, nil
}

// buildCDSFloor derives the cds-role NRI floor from the seed. DaemonSet
// containers keep their seed entries (their entrypoint stays pinned, so the
// c8s binary inside cannot be started as `cds`). The HA CDS container is
// pinned to its exact argv: on a cds node any other invocation of the CDS
// image, or of the operator image, is refused, so nothing but the replica
// can ask the node's attester for a cds-anchored quote.
func buildCDSFloor(seed *pkgallowlist.Allowlist, containers []cdsFloorContainer) ([]byte, error) {
	floor := pkgallowlist.Allowlist{Schema: seed.Schema, Workloads: map[string]pkgallowlist.Workload{}}
	for _, fc := range containers {
		entry, name, ok := seedEntryFor(seed, fc.digest)
		if !ok {
			return nil, fmt.Errorf("cds floor: %s container %q has no seed entry", fc.key, fc.container.Name)
		}
		if fc.key == "DaemonSet/c8s-cds-ha" {
			command := fc.container.Command
			args := fc.container.Args
			if len(command) == 0 {
				// The image entrypoint, as the seed pins it.
				command = entry.Command.Argv
			}
			if entry.Command.Policy != pkgallowlist.PolicyExact || !slices.Equal(command, entry.Command.Argv) {
				return nil, fmt.Errorf("cds floor: HA CDS command %q does not match the seed's pinned entrypoint", command)
			}
			entry.Args = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: slices.Clone(args)}
			name = "cds-ha-replica"
		}
		w := floor.Workloads[name]
		w.Label = name
		if !slices.ContainsFunc(w.Containers, func(c pkgallowlist.Container) bool { return reflect.DeepEqual(c, entry) }) {
			w.Containers = append(w.Containers, entry)
		}
		floor.Workloads[name] = w
	}
	if _, ok := floor.Workloads["cds-ha-replica"]; !ok {
		return nil, errors.New("cds floor: no HA CDS container")
	}
	return json.MarshalIndent(floor, "", "  ")
}

// seedEntryFor returns the seed's container entry for digest and its workload name.
func seedEntryFor(seed *pkgallowlist.Allowlist, digest string) (pkgallowlist.Container, string, bool) {
	for name, w := range seed.Workloads {
		for _, c := range append(w.InitContainers, w.Containers...) {
			if c.Digest.String() == digest {
				return c, name, true
			}
		}
	}
	return pkgallowlist.Container{}, "", false
}

// setNodeImageNamespace pins a namespaced resource to the node-image namespace
// and rejects one the chart placed elsewhere. Cluster-scoped kinds must carry
// no namespace at all, so a namespaced rendering of them is an error.
// nodeImageDecreeNamespace is the chart's cds.ha.decreeNamespace default:
// the HA CDS reads operator decrees there through a Role of its own.
const nodeImageDecreeNamespace = "c8s-cds-decrees"

func setNodeImageNamespace(object *unstructured.Unstructured) error {
	kind, name := object.GetKind(), object.GetName()
	if (kind == "Role" || kind == "RoleBinding") && object.GetNamespace() == nodeImageDecreeNamespace {
		return nil
	}
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

// bakedImage is one container image a baked workload runs: its digest, and
// every argv a manifest spells out for it with an explicit command. A container
// that runs the image's entrypoint records no argv; its executable is the
// image's own.
type bakedImage struct {
	digest string
	argvs  [][]string
}

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
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		ref, err := reference.ParseDockerRef(c.Image)
		if err != nil {
			return fmt.Errorf("node-image workload %s container %q image: %w", key, c.Name, err)
		}
		pinned, ok := ref.(reference.Canonical)
		if !ok || !nodeImageDigestPattern.MatchString(pinned.Digest().String()) {
			return fmt.Errorf("node-image workload %s container %q image must be pinned by sha256 digest", key, c.Name)
		}
		baked := images[ref.String()]
		if baked == nil {
			baked = &bakedImage{digest: pinned.Digest().String()}
			images[ref.String()] = baked
		}
		if len(c.Command) > 0 {
			baked.argvs = append(baked.argvs, slices.Concat(c.Command, c.Args))
		}
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
