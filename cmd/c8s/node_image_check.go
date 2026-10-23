//go:build !c8s_node

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// nodeImageArchitecture is the platform the measured node image runs.
const nodeImageArchitecture = "amd64"

func newNodeImageCheckImagesCmd() *cobra.Command {
	var outputDir, layoutDir string
	cmd := &cobra.Command{
		Use:   "check-images",
		Short: "Check that the preloaded core images start under the bootstrap seed",
		Long:  "Read the config of every image node-image render listed from its preloaded OCI layout, and check that the bootstrap seed admits each baked container's complete launch environment, the image's variables included. Run it after airgap-images.sh, before the image is sealed.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return checkNodeImages(outputDir, layoutDir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&outputDir, "output-dir", "", "directory node-image render wrote (required)")
	f.StringVar(&layoutDir, "layouts", "", "directory holding each image's OCI layout as oci-<sha256 hex> (required)")
	for _, name := range []string{"output-dir", "layouts"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
	return cmd
}

// checkNodeImages checks the render in outputDir against the image configs
// in layoutDir: render alone knows only the image env the chart declares.
func checkNodeImages(outputDir, layoutDir string) error {
	rendered, err := os.ReadFile(filepath.Join(outputDir, "c8s-integration.yaml"))
	if err != nil {
		return err
	}
	names, err := os.ReadFile(filepath.Join(outputDir, "local-names.txt"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if rendered, err = resolveLocalNames(rendered, names); err != nil {
		return err
	}
	rawSeed, err := os.ReadFile(filepath.Join(outputDir, "allowlist-seed.json"))
	if err != nil {
		return err
	}
	// The seed pins the operator's argv with the injected images' node-local
	// names; compare it with the render mapped back to digests.
	if rawSeed, err = resolveLocalNames(rawSeed, names); err != nil {
		return err
	}
	seed, err := pkgallowlist.ParseJSON(rawSeed)
	if err != nil {
		return fmt.Errorf("decode node-image bootstrap seed: %w", err)
	}
	images := make(map[string]*bakedImage)
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("decode node integration: %w", err)
		}
		if len(raw.Raw) == 0 || bytes.Equal(raw.Raw, []byte("null")) {
			continue
		}
		var object unstructured.Unstructured
		if err := object.UnmarshalJSON(raw.Raw); err != nil {
			return fmt.Errorf("decode node integration resource: %w", err)
		}
		if kind := object.GetKind(); kind == "Deployment" || kind == "DaemonSet" {
			if _, err := collectWorkloadImages(object, kind+"/"+object.GetName(), images); err != nil {
				return err
			}
		}
	}
	if len(images) == 0 {
		return fmt.Errorf("node integration in %s runs no images", outputDir)
	}
	seeded := seedContainers(seed)
	for _, image := range slices.Sorted(maps.Keys(images)) {
		baked := images[image]
		config, err := layoutImageConfig(filepath.Join(layoutDir, "oci-"+strings.TrimPrefix(baked.digest, "sha256:")), baked.digest)
		if err != nil {
			return fmt.Errorf("node-image image %s: %w", image, err)
		}
		env := make(map[string]string, len(config.Config.Env))
		for _, entry := range config.Config.Env {
			name, value, _ := strings.Cut(entry, "=")
			env[name] = value
		}
		for _, k := range baked.containers {
			if !slices.ContainsFunc(seeded[baked.digest], func(c pkgallowlist.Container) bool { return admitsBaked(c, baked.digest, k, env) }) {
				return fmt.Errorf("node-image image %s: the bootstrap seed does not admit container %s under the variables its image sets %q", image, k.name, config.Config.Env)
			}
		}
	}
	return nil
}

// layoutImageConfig reads the config of the image digest names from the OCI
// layout at dir: the first linux/amd64 image at or below it, through nested
// indexes. Every blob is checked against its digest.
func layoutImageConfig(dir, digest string) (*platformConfig, error) {
	var layout ocispec.Index
	if err := readJSON(filepath.Join(dir, "index.json"), &layout); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(layout.Manifests, func(d ocispec.Descriptor) bool { return d.Digest.String() == digest }) {
		return nil, fmt.Errorf("OCI layout %s does not hold %s", dir, digest)
	}
	config, err := findImageConfig(dir, digest, maxIndexDepth)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", digest, err)
	}
	if config == nil {
		return nil, fmt.Errorf("image %s has no linux/%s image", digest, nodeImageArchitecture)
	}
	return config, nil
}

// maxIndexDepth bounds the indexes findImageConfig descends through, so a
// cyclic layout fails instead of recursing forever.
const maxIndexDepth = 8

// platformConfig is the part of an image config check-images reads.
type platformConfig struct {
	Config struct {
		Env []string `json:"Env"`
	} `json:"config"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// findImageConfig returns the config of the first linux/amd64 image at or
// below digest, nil when there is none, descending at most depth indexes. The
// platform is read from each image's config, since a single manifest carries
// none and an index entry may omit it.
func findImageConfig(dir, digest string, depth int) (*platformConfig, error) {
	if depth == 0 {
		return nil, fmt.Errorf("indexes nest deeper than %d levels", maxIndexDepth)
	}
	var blob struct {
		ocispec.Manifest
		Manifests []ocispec.Descriptor `json:"manifests"`
	}
	if err := readBlob(dir, digest, &blob); err != nil {
		return nil, err
	}
	if blob.Manifests == nil && !isIndexMediaType(blob.MediaType) {
		if blob.Config.Digest == "" {
			return nil, fmt.Errorf("manifest %s has no config", digest)
		}
		var config platformConfig
		if err := readBlob(dir, blob.Config.Digest.String(), &config); err != nil {
			return nil, err
		}
		if config.OS != "linux" || config.Architecture != nodeImageArchitecture {
			return nil, nil
		}
		return &config, nil
	}
	for _, d := range blob.Manifests {
		if d.Platform != nil && (d.Platform.OS != "linux" || d.Platform.Architecture != nodeImageArchitecture) {
			continue
		}
		config, err := findImageConfig(dir, d.Digest.String(), depth-1)
		if config != nil || err != nil {
			return config, err
		}
	}
	return nil, nil
}

func isIndexMediaType(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

// readBlob decodes the layout blob digest names into v, refusing content
// whose sha256 differs.
func readBlob(dir, digest string, v any) error {
	hexDigest, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return fmt.Errorf("blob digest %s is not sha256", digest)
	}
	data, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", hexDigest))
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != hexDigest {
		return fmt.Errorf("blob %s in %s does not match its digest", digest, dir)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode blob %s: %w", digest, err)
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// resolveLocalNames maps node-local image names back to the digest-pinned
// references they stand for (render's local-names.txt), so the checks see
// the image every node actually runs.
func resolveLocalNames(rendered, names []byte) ([]byte, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(names)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("local-names.txt: bad line %q", line)
		}
		rendered = bytes.ReplaceAll(rendered, []byte("image: "+f[1]+"\n"), []byte("image: "+f[0]+"\n"))
		// The operator's injected-image flags (--mesh-image=<name>).
		for _, flag := range injectedImageFlags {
			rendered = bytes.ReplaceAll(rendered, []byte(flag+f[1]), []byte(flag+f[0]))
		}
	}
	return rendered, nil
}
