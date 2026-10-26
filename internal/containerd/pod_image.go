package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	podImageTimeout         = 5 * time.Second
	podImageDocumentLimit   = 1 << 20
	podImageTotalLimit      = 8 << 20
	podImageObjectLimit     = 64
	podImageDepthLimit      = 8
	podImageDescriptorLimit = 256
	criMetadataExtension    = "io.cri-containerd.container.metadata"
	criMetadataType         = "github.com/containerd/cri/pkg/store/container/Metadata"
)

var errPodImageLimit = errors.New("pod image verification limit exceeded")

// VerifyContainerImage binds a pinned image to the saved CRI configuration and
// the container's actual rootfs. Image names and mutable image-store entries
// are not evidence of either selection.
func (r *Resolver) VerifyContainerImage(ctx context.Context, containerID, sandboxID, pin string) error {
	if !canonicalImageDigest(pin) || containerID == "" || sandboxID == "" {
		return errors.New("pod image verification requires a container, sandbox and canonical image digest")
	}
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(ctx, r.namespace), podImageTimeout)
	defer cancel()
	info, err := r.client.ContainerService().Get(ctx, containerID)
	if err != nil {
		return fmt.Errorf("read selected container image: %w", err)
	}
	if info.ID != containerID || info.Snapshotter == "" || info.SnapshotKey == "" {
		return errors.New("selected container has no matching identity or rootfs snapshot")
	}
	selected, err := selectedConfigDigest(info.Extensions[criMetadataExtension], containerID, sandboxID)
	if err != nil {
		return err
	}
	proof := podImageProof{store: r.client.ContentStore(), selected: selected}
	config, err := proof.imageConfig(ctx, ocispec.Descriptor{Digest: digest.Digest(pin)}, 0)
	if err != nil {
		return fmt.Errorf("bind selected configuration to pinned image: %w", err)
	}
	snapshot, err := r.client.SnapshotService(info.Snapshotter).Stat(ctx, info.SnapshotKey)
	if err != nil {
		return fmt.Errorf("read selected container snapshot: %w", err)
	}
	if snapshot.Name != info.SnapshotKey || snapshot.Kind != snapshots.KindActive || snapshot.Parent != identity.ChainID(config.RootFS.DiffIDs).String() {
		return errors.New("selected container rootfs does not match the pinned image")
	}
	return ctx.Err()
}

// The shipped CRI versions store these immutable fields outside Config in
// both metadata encodings. Config itself changes encoding between v1 and v2.
func selectedConfigDigest(extension typeurl.Any, containerID, sandboxID string) (string, error) {
	if extension == nil || extension.GetTypeUrl() != criMetadataType || len(extension.GetValue()) > podImageDocumentLimit {
		return "", errors.New("missing, unsupported or oversized CRI container metadata")
	}
	var saved struct {
		Version  string
		Metadata struct {
			ID        string
			SandboxID string
			ImageRef  string
		}
	}
	if err := json.Unmarshal(extension.GetValue(), &saved); err != nil {
		return "", fmt.Errorf("decode CRI container metadata: %w", err)
	}
	if saved.Version != "v1" && saved.Version != "v2" {
		return "", errors.New("unsupported CRI container metadata version")
	}
	if saved.Metadata.ID != containerID || saved.Metadata.SandboxID != sandboxID || !canonicalImageDigest(saved.Metadata.ImageRef) {
		return "", errors.New("CRI container metadata does not bind this container, sandbox and image configuration")
	}
	return saved.Metadata.ImageRef, nil
}

func canonicalImageDigest(value string) bool {
	d, err := types.ParseDigest(value)
	return err == nil && d.String() == value
}

type podImageProof struct {
	store    content.Provider
	selected string
	objects  int
	bytes    int64
}

func (p *podImageProof) read(ctx context.Context, desc ocispec.Descriptor) ([]byte, error) {
	if !canonicalImageDigest(desc.Digest.String()) || desc.Size < 0 || desc.Size > podImageDocumentLimit {
		return nil, errors.New("invalid pinned image content descriptor")
	}
	if p.objects >= podImageObjectLimit {
		return nil, errPodImageLimit
	}
	p.objects++
	reader, err := p.store.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	size := reader.Size()
	if size <= 0 || size > podImageDocumentLimit || (desc.Size != 0 && desc.Size != size) {
		return nil, errors.New("pinned image content size does not match its bounded descriptor")
	}
	if p.bytes+size > podImageTotalLimit {
		return nil, errPodImageLimit
	}
	p.bytes += size
	data := make([]byte, size)
	n, err := reader.ReadAt(data, 0)
	if n != len(data) || (err != nil && !errors.Is(err, io.EOF)) {
		return nil, fmt.Errorf("read pinned image content: %w", errors.Join(err, io.ErrUnexpectedEOF))
	}
	if digest.FromBytes(data) != desc.Digest {
		return nil, errors.New("pinned image content digest mismatch")
	}
	return data, nil
}

type podImageDocument struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Config        *ocispec.Descriptor  `json:"config"`
	Layers        []ocispec.Descriptor `json:"layers"`
	Manifests     []ocispec.Descriptor `json:"manifests"`
}

func (p *podImageProof) imageConfig(ctx context.Context, desc ocispec.Descriptor, depth int) (*ocispec.Image, error) {
	if depth > podImageDepthLimit {
		return nil, errPodImageLimit
	}
	data, err := p.read(ctx, desc)
	if err != nil {
		return nil, err
	}
	var doc podImageDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode pinned image document: %w", err)
	}
	if err := doc.validate(desc.MediaType); err != nil {
		return nil, err
	}
	if doc.Config != nil {
		return p.manifestConfig(ctx, doc)
	}
	var lastErr error
	for _, child := range doc.Manifests {
		config, err := p.imageConfig(ctx, child, depth+1)
		if err == nil {
			return config, nil
		}
		if ctx.Err() != nil || errors.Is(err, errPodImageLimit) {
			return nil, err
		}
		// An index can include platforms not pulled into this guest. Only
		// a complete path to the actual selected configuration is evidence.
		lastErr = err
	}
	return nil, fmt.Errorf("selected image configuration is not reachable from the pinned index: %w", lastErr)
}

func (d *podImageDocument) validate(expectedType string) error {
	if d.SchemaVersion != 2 || (d.MediaType != "" && expectedType != "" && d.MediaType != expectedType) {
		return errors.New("unsupported pinned image schema or media type mismatch")
	}
	mediaType := d.MediaType
	if mediaType == "" {
		mediaType = expectedType
	}
	if d.Config != nil && d.Manifests == nil {
		if mediaType != "" && !images.IsManifestType(mediaType) {
			return errors.New("pinned image document is not a supported manifest")
		}
		if len(d.Layers) > podImageDescriptorLimit {
			return errPodImageLimit
		}
		return nil
	}
	if d.Config == nil && d.Layers == nil && len(d.Manifests) > 0 {
		if mediaType != "" && !images.IsIndexType(mediaType) {
			return errors.New("pinned image document is not a supported index")
		}
		if len(d.Manifests) > podImageDescriptorLimit {
			return errPodImageLimit
		}
		for _, child := range d.Manifests {
			if !canonicalImageDigest(child.Digest.String()) || child.Size <= 0 || child.Size > podImageDocumentLimit || (!images.IsManifestType(child.MediaType) && !images.IsIndexType(child.MediaType)) {
				return errors.New("invalid pinned image index descriptor")
			}
		}
		return nil
	}
	return errors.New("pinned image document is neither a manifest nor an index")
}

func (p *podImageProof) manifestConfig(ctx context.Context, manifest podImageDocument) (*ocispec.Image, error) {
	configDesc := *manifest.Config
	if configDesc.Digest.String() != p.selected {
		return nil, errors.New("selected image configuration differs from the pinned manifest")
	}
	if configDesc.Size <= 0 || (configDesc.MediaType != ocispec.MediaTypeImageConfig && configDesc.MediaType != images.MediaTypeDockerSchema2Config) {
		return nil, errors.New("invalid pinned image configuration descriptor")
	}
	data, err := p.read(ctx, configDesc)
	if err != nil {
		return nil, err
	}
	var config ocispec.Image
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode selected image configuration: %w", err)
	}
	if config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return nil, errors.New("pinned image configuration does not describe the manifest's layers")
	}
	for i, diffID := range config.RootFS.DiffIDs {
		layer := manifest.Layers[i]
		if !canonicalImageDigest(diffID.String()) || !canonicalImageDigest(layer.Digest.String()) || layer.Size < 0 || !images.IsLayerType(layer.MediaType) {
			return nil, errors.New("invalid pinned image rootfs descriptor")
		}
	}
	return &config, nil
}
