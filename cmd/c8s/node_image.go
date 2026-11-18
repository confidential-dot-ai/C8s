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
	"strings"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	k8sversion "k8s.io/apimachinery/pkg/util/version"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/worker"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/helmchart"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/version"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

const nodeImageNamespace = "c8s-system"

// allowlistSeedName is the ConfigMap the worker chart's seed template renders.
const allowlistSeedName = "c8s-allowlist-seed"

// nodeImageRenderConfig contains build inputs only. The role, endpoint and
// attested measurement policy are supplied by authenticated boot staging.
type nodeImageRenderConfig struct {
	platform                  string
	kubeVersion               string
	imageDigest               string
	imageRepository           string
	armtlsMeshImageDigest     string
	armtlsMeshImageRepository string
	floorTemplate             string
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
		Short: "Render the worker image's files from the c8s-worker chart at image build time",
		Long:  "Render the c8s-worker chart's allowlist seed and this release's component set, and copy its static pods and the router's nginx files, for the measured worker image. Requires Helm at build time; no Helm is installed or run in the guest. Authenticated launch settings are mounted read-only from /run/c8s-node at boot.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return renderNodeImage(cmd.Context(), cfg, cmd.ErrOrStderr())
		},
	}
	f := render.Flags()
	f.StringVar(&cfg.platform, "hardware-platform", "", "CPU TEE: tdx or sev-snp (required)")
	f.StringVar(&cfg.kubeVersion, "kube-version", "", "Kubernetes semantic version of the baked kubelet, e.g. v1.36.6 (required)")
	f.StringVar(&cfg.imageDigest, "image-digest", "", "digest of the operator/get-cert container image (sha256:..., required)")
	f.StringVar(&cfg.imageRepository, "image-repository", "", "operator/get-cert container repository; empty uses the chart default")
	f.StringVar(&cfg.armtlsMeshImageDigest, "armtls-mesh-image-digest", "", "digest of the armTLS mesh container image (sha256:..., required)")
	f.StringVar(&cfg.armtlsMeshImageRepository, "armtls-mesh-image-repository", "", "armTLS mesh container repository; empty uses the chart default")
	f.StringVar(&cfg.floorTemplate, "floor-template", "", "the worker image's NRI floor template, placeholders unfilled (required)")
	f.StringVar(&cfg.chartDir, "chart-dir", "", "c8s-worker chart directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for allowlist-seed.json, component-set.json, router-image.txt, router-nginx/ and static-pods/ (required)")
	cmd.AddCommand(render)
	return cmd
}

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (cfg nodeImageRenderConfig) validate() error {
	if err := validateHardwarePlatform(cfg.platform); err != nil {
		return err
	}
	if _, err := k8sversion.ParseSemantic(cfg.kubeVersion); err != nil {
		return fmt.Errorf("--kube-version must specify the baked Kubernetes semantic version: %w", err)
	}
	for _, input := range cfg.images() {
		if (input.required || input.digest != "") && !imageDigestPattern.MatchString(input.digest) {
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

// nodeImageInput ties one image build flag to the chart value it pins and to
// the floor template's placeholders for that image.
type nodeImageInput struct {
	flag        string // build flag prefix, e.g. "armtls-mesh-image"
	valuePath   string // chart value the repository and digest are set under
	placeholder string // floor template placeholder prefix, e.g. "MESH"
	repository  string
	digest      string
	required    bool // the image must be pinned for the render to succeed
}

// images maps the chart's image values to the build flags that pin them.
func (cfg nodeImageRenderConfig) images() []nodeImageInput {
	return []nodeImageInput{
		{flag: "image", valuePath: "image", placeholder: "OPERATOR", repository: cfg.imageRepository, digest: cfg.imageDigest, required: true},
		{flag: "armtls-mesh-image", valuePath: "armtlsMesh.image", placeholder: "MESH", repository: cfg.armtlsMeshImageRepository, digest: cfg.armtlsMeshImageDigest, required: true},
	}
}

func renderNodeImage(ctx context.Context, cfg nodeImageRenderConfig, log io.Writer) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.floorTemplate == "" {
		return fmt.Errorf("--floor-template is required")
	}
	cfg, cleanup, err := cfg.resolveWorkerChart()
	if err != nil {
		return err
	}
	defer cleanup()
	seed, err := renderImageSeed(ctx, cfg)
	if err != nil {
		return err
	}
	routerImage, err := routerNginxImage(cfg.chartDir)
	if err != nil {
		return err
	}
	if err := writeNodeImageFiles(cfg.outputDir, cfg.chartDir, seed, routerImage); err != nil {
		return err
	}
	version, err := componentSetVersion()
	if err != nil {
		fmt.Fprintf(log, "no component-set.json: %v\n", err)
		return nil
	}
	template, err := cfg.fillFloorTemplate(ctx, routerImage)
	if err != nil {
		return err
	}
	set, err := worker.ComponentSetFile(template, seed, version)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cfg.outputDir, "component-set.json"), set, 0o644)
}

// componentSetVersion is the set version this build publishes under: its
// release tag without the v, which a set is keyed by.
func componentSetVersion() (string, error) {
	tag := version.Version
	if !semver.IsValid(tag) || semver.Canonical(tag) != tag {
		return "", fmt.Errorf("this build's version %q is no release tag (vMAJOR.MINOR.PATCH, optionally with a pre-release), and a component set is keyed by the release that built it", tag)
	}
	return strings.TrimPrefix(tag, "v"), nil
}

// fillFloorTemplate is the worker image's floor template with the image
// placeholders of this render substituted, as the image build substitutes them
// before `c8s worker floor` reads it.
func (cfg nodeImageRenderConfig) fillFloorTemplate(ctx context.Context, routerImage string) ([]byte, error) {
	body, err := os.ReadFile(cfg.floorTemplate)
	if err != nil {
		return nil, fmt.Errorf("--floor-template: %w", err)
	}
	values, err := chartValues(ctx, cfg.chartDir)
	if err != nil {
		return nil, err
	}
	routerRepository, routerDigest, _ := strings.Cut(routerImage, "@")
	filled := []string{"@ROUTER_REPO@", routerRepository, "@ROUTER_DIGEST@", routerDigest}
	for _, input := range cfg.images() {
		repository := input.repository
		if repository == "" {
			repository, err = stringAtPath(values, input.valuePath+".repository")
			if err != nil {
				return nil, fmt.Errorf("--%s-repository: %w", input.flag, err)
			}
		}
		filled = append(filled,
			"@"+input.placeholder+"_REPO@", repository,
			"@"+input.placeholder+"_DIGEST@", input.digest,
		)
	}
	return []byte(strings.NewReplacer(filled...).Replace(string(body))), nil
}

// resolveWorkerChart is cfg with chartDir naming a chart directory on disk:
// the one --chart-dir gave, or the bundled worker chart extracted to a
// temporary directory, with the cleanup that removes it.
func (cfg nodeImageRenderConfig) resolveWorkerChart() (nodeImageRenderConfig, func(), error) {
	if cfg.chartDir != "" {
		return cfg, func() {}, nil
	}
	tmp, err := helmchart.ExtractTemp()
	if err != nil {
		return cfg, func() {}, fmt.Errorf("extract the worker chart: %w", err)
	}
	cfg.chartDir = filepath.Join(tmp, helmchart.WorkerChart)
	return cfg, func() { os.RemoveAll(tmp) }, nil
}

// renderImageSeed is the worker chart's allowlist seed in canonical bytes.
func renderImageSeed(ctx context.Context, cfg nodeImageRenderConfig) ([]byte, error) {
	rendered, err := templateWorkerChart(ctx, cfg, "--show-only", helmchart.WorkerSeedTemplate)
	if err != nil {
		return nil, err
	}
	var configMap corev1.ConfigMap
	if err := yaml.UnmarshalStrict(rendered, &configMap); err != nil {
		return nil, fmt.Errorf("decode %s: %w", helmchart.WorkerSeedTemplate, err)
	}
	if configMap.Kind != "ConfigMap" || configMap.Name != allowlistSeedName {
		return nil, fmt.Errorf("%s rendered %s/%s, want the ConfigMap %s", helmchart.WorkerSeedTemplate, configMap.Kind, configMap.Name, allowlistSeedName)
	}
	seed, err := pkgallowlist.ParseJSON([]byte(configMap.Data["allowlist-seed.json"]))
	if err != nil {
		return nil, fmt.Errorf("decode the worker chart's allowlist seed: %w", err)
	}
	return seed.Canonical()
}

// routerNginxImage is the router's nginx image as c8s-lib pins it, the front
// door the measured base pins for the router role.
func routerNginxImage(chartDir string) (string, error) {
	file, err := chartComponentsFile(chartDir)
	if err != nil {
		return "", err
	}
	pin := file.RouterNginx.Image
	if pin.Repository == "" || pin.Digest == "" {
		return "", fmt.Errorf("the chart pins the router's nginx as %q@%q", pin.Repository, pin.Digest)
	}
	return pin.Repository + "@" + pin.Digest, nil
}

// templateWorkerChart runs helm template on the worker chart with the stock
// file of cfg's CPU TEE and cfg's images, then args.
func templateWorkerChart(ctx context.Context, cfg nodeImageRenderConfig, args ...string) ([]byte, error) {
	stockFile, err := workerStockFile(cfg.chartDir, cfg.platform)
	if err != nil {
		return nil, err
	}
	helmArgs := []string{
		"template", "c8s", cfg.chartDir,
		"--namespace", nodeImageNamespace,
		"--kube-version", cfg.kubeVersion,
		"-f", stockFile,
	}
	for _, input := range cfg.images() {
		helmArgs = append(helmArgs, "--set-string", input.valuePath+".digest="+input.digest)
		if input.repository != "" {
			helmArgs = append(helmArgs, "--set-string", input.valuePath+".repository="+input.repository)
		}
	}
	return runHelm(ctx, append(helmArgs, args...)...)
}

// workerStockFile is the worker chart's stock file for platform, the values
// its CPU TEE pins.
func workerStockFile(chartDir, platform string) (string, error) {
	path := filepath.Join(chartDir, "values-"+platform+".yaml")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("the worker chart holds no stock file for %s: %w", platform, err)
	}
	return path, nil
}

// runHelm runs helm with args and returns its standard output.
func runHelm(ctx context.Context, args ...string) ([]byte, error) {
	helm := exec.CommandContext(ctx, "helm", args...)
	var stderr bytes.Buffer
	helm.Stderr = &stderr
	out, err := helm.Output()
	if err != nil {
		return nil, fmt.Errorf("helm %s: %w: %s", args[0], err, stderr.String())
	}
	return out, nil
}

// writeNodeImageFiles writes what mkosi.sync installs or reads: the seed, the
// router's nginx image, and the chart's router nginx files and static pods.
func writeNodeImageFiles(
	outputDir string,
	chartDir string,
	seed []byte,
	routerImage string,
) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	if err := copyChartFiles(filepath.Join(chartDir, helmchart.RouterNginxDir), filepath.Join(outputDir, "router-nginx")); err != nil {
		return err
	}
	if err := copyChartFiles(filepath.Join(chartDir, helmchart.StaticPodsDir), filepath.Join(outputDir, "static-pods")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "allowlist-seed.json"), seed, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "router-image.txt"), []byte(routerImage+"\n"), 0o644)
}

// copyChartFiles copies the regular files of the chart directory src into dst.
func copyChartFiles(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("read the chart's %s: %w", src, err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	copied := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, entry.Name()), body, 0o644); err != nil {
			return err
		}
		copied++
	}
	if copied == 0 {
		return fmt.Errorf("the chart's %s holds no files", src)
	}
	return nil
}
