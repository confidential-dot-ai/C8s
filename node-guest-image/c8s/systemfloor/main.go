// Command systemfloor checks the RKE2 system images in image-policy.yaml.in:
// every container of the allowlist.base workloads between the BEGIN/END
// markers must name, for its image, the digest the node's containerd stores.
//
// The digests are the ones containerd computes when it IMPORTS the airgap
// bundles at rke2 boot, not the registry's: the bundles are docker-archive
// tarballs and the import rebuilds each manifest, so the digest only exists
// in the store. This tool runs the same code the daemon's import does
// (images/archive.ImportIndex, vendored with the c8s module) against a
// scratch content store, so the check matches what the plugin resolves at
// runtime. Images the baked manifests pull keep their pinned registry digest.
//
//	systemfloor -bundle rke2-images-core.linux-amd64.tar.zst \
//	    -bundle rke2-images-cilium.linux-amd64.tar.zst \
//	    -manifest .../server/manifests/nvidia-device-plugin.yaml \
//	    node-guest-image/c8s/image-policy.yaml.in
//
// exits non-zero naming each container whose digest is stale, with the digest
// its image has in the inputs.
package main

import (
	"context"
	_ "crypto/sha256" // go-digest's canonical algorithm
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	localcontent "github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// entry is one image a node stores: its digest under its image reference.
type entry struct {
	digest string
	ref    string
}

// bundleEntries imports a docker-archive airgap bundle the way containerd's
// import does and returns one entry per named image: the rebuilt manifest
// digest under its normalized repo:tag name.
func bundleEntries(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("zstd decoder: %w", err)
	}
	defer zr.Close()

	entries, err := importEntries(zr)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", filepath.Base(path), err)
	}
	return entries, nil
}

// importEntries runs containerd's docker-archive import over a tar stream
// against a scratch content store and reads the resulting index.
func importEntries(r io.Reader) ([]entry, error) {
	root, err := os.MkdirTemp("", "systemfloor-content")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	store, err := localcontent.NewStore(root)
	if err != nil {
		return nil, fmt.Errorf("content store: %w", err)
	}

	idxDesc, err := archive.ImportIndex(context.Background(), store, r)
	if err != nil {
		return nil, err
	}

	idxJSON, err := content.ReadBlob(context.Background(), store, idxDesc)
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(idxJSON, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}

	var out []entry
	for _, m := range idx.Manifests {
		name := m.Annotations[images.AnnotationImageName]
		if name == "" {
			continue
		}
		out = append(out, entry{digest: m.Digest.String(), ref: name})
	}
	return out, nil
}

// imageRefRE matches an `image:` value pinned by digest.
var imageRefRE = regexp.MustCompile(`\bimage:\s*"?([^\s"]+@(sha256:[0-9a-f]{64}))"?`)

// manifestEntries scans a YAML manifest for digest-pinned image references;
// indented blocks match the same way.
func manifestEntries(path string) ([]entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, m := range imageRefRE.FindAllSubmatch(data, -1) {
		out = append(out, entry{digest: string(m[2]), ref: string(m[1])})
	}
	return out, nil
}

const (
	beginMarker = "# BEGIN rke2 system images"
	endMarker   = "# END rke2 system images"
)

// floorWorkloads decodes the base workloads between the marker lines.
func floorWorkloads(template string) (map[string]allowlist.Workload, error) {
	lines := strings.Split(template, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		if strings.Contains(l, beginMarker) {
			begin = i
		}
		if strings.Contains(l, endMarker) {
			end = i
		}
	}
	if begin < 0 {
		return nil, fmt.Errorf("no %q marker in template", beginMarker)
	}
	if end < 0 || end <= begin {
		return nil, fmt.Errorf("no %q marker after the begin marker", endMarker)
	}
	var doc struct {
		Workloads map[string]allowlist.Workload `yaml:"workloads"`
	}
	block := "workloads:\n" + strings.Join(lines[begin+1:end], "\n")
	if err := yaml.Unmarshal([]byte(block), &doc); err != nil {
		return nil, fmt.Errorf("decode the system images: %w", err)
	}
	return doc.Workloads, nil
}

// storedDigests maps each image reference in the inputs to its digest on the
// node.
func storedDigests(bundles, manifests []string) (map[string]string, error) {
	var entries []entry
	for _, b := range bundles {
		e, err := bundleEntries(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e...)
	}
	for _, m := range manifests {
		e, err := manifestEntries(m)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e...)
	}
	stored := make(map[string]string, len(entries))
	for _, e := range entries {
		if digest, seen := stored[e.ref]; seen && digest != e.digest {
			return nil, fmt.Errorf("%s is both %s and %s in the inputs", e.ref, digest, e.digest)
		}
		stored[e.ref] = e.digest
	}
	return stored, nil
}

// staleDigests names each floor container whose digest is not the one stored
// for its image, or whose image no input carries.
func staleDigests(floor map[string]allowlist.Workload, stored map[string]string) error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(floor)) {
		w := floor[name]
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			want, carried := stored[c.Image]
			if !carried {
				errs = append(errs, fmt.Errorf("%s: %s is in none of the pinned bundles and baked manifests", name, c.Image))
				continue
			}
			if c.Digest.String() != want {
				errs = append(errs, fmt.Errorf("%s: %s is %s on the node, not %s", name, c.Image, want, c.Digest))
			}
		}
	}
	return errors.Join(errs...)
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ", ") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "systemfloor:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("systemfloor", flag.ContinueOnError)
	var bundles, manifests stringList
	fs.Var(&bundles, "bundle", "RKE2 airgap image bundle (*.tar.zst); repeatable")
	fs.Var(&manifests, "manifest", "baked YAML manifest to scan for digest-pinned image refs; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: systemfloor [-bundle FILE]... [-manifest FILE]... image-policy.yaml.in")
	}
	templatePath := fs.Arg(0)
	if len(bundles) == 0 && len(manifests) == 0 {
		return fmt.Errorf("no inputs: pass -bundle and/or -manifest")
	}
	stored, err := storedDigests(bundles, manifests)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	floor, err := floorWorkloads(string(data))
	if err != nil {
		return err
	}
	if err := staleDigests(floor, stored); err != nil {
		return fmt.Errorf("%s: system images are stale:\n%w", templatePath, err)
	}
	return nil
}
