package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	contentapi "github.com/containerd/containerd/api/services/content/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const selectedContainerID = "selected-container"
const selectedSandboxID = "selected-sandbox"

type selectedImageFixture struct {
	t                *testing.T
	mu               sync.Mutex
	blobs            map[string][]byte
	container        *containersapi.Container
	snapshot         *snapshotsapi.Info
	config           ocispec.Image
	manifest         ocispec.Manifest
	pin              ocispec.Descriptor
	metadataVersion  string
	metadataID       string
	metadataSandbox  string
	metadataConfig   string
	metadataType     string
	metadataOverride []byte
	containerError   error
	snapshotError    error
	stall            string
}

func newSelectedImageFixture(t *testing.T) *selectedImageFixture {
	t.Helper()
	f := &selectedImageFixture{
		t: t, blobs: map[string][]byte{}, metadataVersion: "v1",
		metadataID: selectedContainerID, metadataSandbox: selectedSandboxID,
		metadataType: criContainerMetadataType,
		container:    &containersapi.Container{ID: selectedContainerID, Image: "registry/app:latest", Snapshotter: "overlayfs", SnapshotKey: selectedContainerID},
		config:       ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"}, Config: ocispec.ImageConfig{Entrypoint: []string{"/app"}}, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromString("unpacked base"), digest.FromString("unpacked app")}}},
	}
	config := f.addJSON(f.config, ocispec.MediaTypeImageConfig)
	f.metadataConfig = config.Digest.String()
	f.manifest = ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: []ocispec.Descriptor{
		{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("compressed base"), Size: 42},
		{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("compressed app"), Size: 43},
	}}
	f.pin = f.addJSON(f.manifest, f.manifest.MediaType)
	f.snapshot = &snapshotsapi.Info{Name: selectedContainerID, Kind: snapshotsapi.Kind_ACTIVE, Parent: identity.ChainID(f.config.RootFS.DiffIDs).String()}
	return f
}

func (f *selectedImageFixture) addJSON(value any, mediaType string) ocispec.Descriptor {
	f.t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	d := digest.FromBytes(data)
	f.blobs[d.String()] = data
	return ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
}

func (f *selectedImageFixture) setManifest() {
	f.pin = f.addJSON(f.manifest, f.manifest.MediaType)
}

func (f *selectedImageFixture) checkRPC(ctx context.Context, stage string) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if got := md.Get(namespaces.GRPCHeader); len(got) != 1 || got[0] != testNamespace {
		return status.Errorf(codes.InvalidArgument, "wrong namespace: %v", got)
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > podImageTimeout+time.Second {
		return status.Error(codes.InvalidArgument, "unbounded image verification RPC")
	}
	if f.stall == stage {
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	}
	return nil
}

type selectedContainerServer struct {
	containersapi.UnimplementedContainersServer
	f *selectedImageFixture
}

func (s selectedContainerServer) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	if err := s.f.checkRPC(ctx, "container"); err != nil {
		return nil, err
	}
	f := s.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.containerError != nil {
		return nil, f.containerError
	}
	if req.ID != selectedContainerID {
		return nil, status.Error(codes.NotFound, "unknown container")
	}
	data := f.metadataOverride
	if data == nil {
		var err error
		data, err = json.Marshal(map[string]any{"Version": f.metadataVersion, "Metadata": map[string]any{"ID": f.metadataID, "SandboxID": f.metadataSandbox, "ImageRef": f.metadataConfig, "Config": "a v2 config is encoded separately"}})
		if err != nil {
			return nil, err
		}
	}
	container := proto.Clone(f.container).(*containersapi.Container)
	container.Extensions = map[string]*anypb.Any{criContainerMetadataExtension: {TypeUrl: f.metadataType, Value: data}}
	return &containersapi.GetContainerResponse{Container: container}, nil
}

type selectedContentServer struct {
	contentapi.UnimplementedContentServer
	f *selectedImageFixture
}

func (s selectedContentServer) Info(ctx context.Context, req *contentapi.InfoRequest) (*contentapi.InfoResponse, error) {
	if err := s.f.checkRPC(ctx, "content"); err != nil {
		return nil, err
	}
	f := s.f
	f.mu.Lock()
	defer f.mu.Unlock()
	data, exists := f.blobs[req.Digest]
	if !exists {
		return nil, status.Error(codes.NotFound, "content is not pulled")
	}
	return &contentapi.InfoResponse{Info: &contentapi.Info{Digest: req.Digest, Size: int64(len(data))}}, nil
}

func (s selectedContentServer) Read(req *contentapi.ReadContentRequest, stream contentapi.Content_ReadServer) error {
	if err := s.f.checkRPC(stream.Context(), "read"); err != nil {
		return err
	}
	f := s.f
	f.mu.Lock()
	data, exists := f.blobs[req.Digest]
	f.mu.Unlock()
	if !exists {
		return status.Error(codes.NotFound, "content is not pulled")
	}
	if req.Offset < 0 || req.Offset > int64(len(data)) || req.Size <= 0 || req.Size > podImageDocumentLimit {
		return status.Error(codes.InvalidArgument, "unbounded or invalid content read")
	}
	end := min(int64(len(data)), req.Offset+req.Size)
	return stream.Send(&contentapi.ReadContentResponse{Offset: req.Offset, Data: data[req.Offset:end]})
}

type selectedSnapshotServer struct {
	snapshotsapi.UnimplementedSnapshotsServer
	f *selectedImageFixture
}

func (s selectedSnapshotServer) Stat(ctx context.Context, req *snapshotsapi.StatSnapshotRequest) (*snapshotsapi.StatSnapshotResponse, error) {
	if err := s.f.checkRPC(ctx, "snapshot"); err != nil {
		return nil, err
	}
	f := s.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapshotError != nil {
		return nil, f.snapshotError
	}
	if req.Key != selectedContainerID || req.Snapshotter != "overlayfs" {
		return nil, status.Error(codes.NotFound, "unknown rootfs snapshot")
	}
	return &snapshotsapi.StatSnapshotResponse{Info: proto.Clone(f.snapshot).(*snapshotsapi.Info)}, nil
}

func (f *selectedImageFixture) resolver() *Resolver {
	f.t.Helper()
	socket := tempSocketPath(f.t)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		f.t.Fatal(err)
	}
	srv := grpc.NewServer()
	containersapi.RegisterContainersServer(srv, selectedContainerServer{f: f})
	contentapi.RegisterContentServer(srv, selectedContentServer{f: f})
	snapshotsapi.RegisterSnapshotsServer(srv, selectedSnapshotServer{f: f})
	// A tag now points elsewhere. No image service request is necessary or
	// permitted when proving the image selected for an existing container.
	currentImages := &fakeImages{knownName: "registry/app:latest"}
	imagesapi.RegisterImagesServer(srv, currentImages)
	go func() { _ = srv.Serve(lis) }()
	f.t.Cleanup(srv.Stop)
	f.t.Cleanup(func() {
		currentImages.mu.Lock()
		defer currentImages.mu.Unlock()
		if len(currentImages.requested) != 0 {
			f.t.Errorf("verification looked up mutable image-store entries: %v", currentImages.requested)
		}
	})
	return newTestResolver(f.t, socket)
}

// The executed image is proved from the pinned digest, the saved
// CRI configuration and the rootfs; the moved tag is never looked up.
func TestVerifyContainerImage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*selectedImageFixture)
	}{
		{"OCI manifest after tag moved", func(*selectedImageFixture) {}},
		{"CRI metadata v2", func(f *selectedImageFixture) { f.metadataVersion = "v2" }},
		{"Docker schema2", func(f *selectedImageFixture) {
			f.manifest.MediaType = images.MediaTypeDockerSchema2Manifest
			f.manifest.Config.MediaType = images.MediaTypeDockerSchema2Config
			for i := range f.manifest.Layers {
				f.manifest.Layers[i].MediaType = images.MediaTypeDockerSchema2LayerGzip
			}
			f.setManifest()
		}},
		{"index with unpulled other platform first", func(f *selectedImageFixture) {
			other := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("unpulled arm64 manifest"), Size: 100, Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64"}}
			selected := f.pin
			selected.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{other, selected}}, ocispec.MediaTypeImageIndex)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelectedImageFixture(t)
			tc.prepare(f)
			if err := f.resolver().VerifyContainerImage(t.Context(), selectedContainerID, selectedSandboxID, f.pin.Digest.String()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// One refusal per verification branch, and the traversal bounds that
// keep an attacker-shaped image document from exhausting the verifier.
func TestVerifyContainerImageRefusals(t *testing.T) {
	limit := errPodImageLimit.Error()
	for _, tc := range []struct {
		name    string
		prepare func(*selectedImageFixture)
		want    string
	}{
		{"selected configuration differs even with same filesystem", func(f *selectedImageFixture) {
			other := f.config
			other.Config.Entrypoint = []string{"/different-command"}
			f.metadataConfig = f.addJSON(other, ocispec.MediaTypeImageConfig).Digest.String()
		}, "selected image configuration differs"},
		{"selected snapshot differs despite matching configuration", func(f *selectedImageFixture) { f.snapshot.Parent = digest.FromString("other rootfs").String() }, "rootfs does not match"},
		{"snapshot missing", func(f *selectedImageFixture) { f.snapshotError = status.Error(codes.NotFound, "gone") }, "read selected container snapshot"},
		{"container missing", func(f *selectedImageFixture) { f.containerError = status.Error(codes.NotFound, "gone") }, "read selected container image"},
		{"container response for another ID", func(f *selectedImageFixture) { f.container.ID = "different" }, "no matching identity"},
		{"metadata sandbox mismatch", func(f *selectedImageFixture) { f.metadataSandbox = "other" }, "metadata does not bind"},
		{"metadata config is not canonical", func(f *selectedImageFixture) { f.metadataConfig = strings.ToUpper(f.metadataConfig) }, "metadata does not bind"},
		{"metadata schema unknown", func(f *selectedImageFixture) { f.metadataVersion = "v3" }, "metadata version"},
		{"metadata malformed", func(f *selectedImageFixture) { f.metadataOverride = []byte("{") }, "decode CRI"},
		{"metadata too large", func(f *selectedImageFixture) {
			f.metadataOverride = []byte(strings.Repeat(" ", podImageDocumentLimit+1))
		}, "unsupported or oversized"},
		{"pinned root absent", func(f *selectedImageFixture) { delete(f.blobs, f.pin.Digest.String()) }, "content is not pulled"},
		{"root malformed", func(f *selectedImageFixture) {
			data := []byte("{")
			f.pin.Digest = digest.FromBytes(data)
			f.blobs[f.pin.Digest.String()] = data
		}, "decode pinned image document"},
		{"root digest mismatch", func(f *selectedImageFixture) { f.blobs[f.pin.Digest.String()] = []byte(`{"schemaVersion":2}`) }, "content digest mismatch"},
		{"config size mismatch", func(f *selectedImageFixture) { f.manifest.Config.Size++; f.setManifest() }, "content size"},
		{"config media type invalid", func(f *selectedImageFixture) {
			f.manifest.Config.MediaType = "application/octet-stream"
			f.setManifest()
		}, "configuration descriptor"},
		{"root schema unsupported", func(f *selectedImageFixture) { f.manifest.SchemaVersion = 1; f.setManifest() }, "unsupported pinned image schema"},
		{"manifest has wrong media type", func(f *selectedImageFixture) { f.manifest.MediaType = ocispec.MediaTypeImageIndex; f.setManifest() }, "not a supported manifest"},
		{"layer count differs", func(f *selectedImageFixture) { f.manifest.Layers = f.manifest.Layers[:1]; f.setManifest() }, "does not describe"},
		{"layer digest invalid", func(f *selectedImageFixture) { f.manifest.Layers[0].Digest = "not-a-digest"; f.setManifest() }, "rootfs descriptor"},
		{"index child size missing", func(f *selectedImageFixture) {
			child := f.pin
			child.Size = 0
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{child}}, ocispec.MediaTypeImageIndex)
		}, "index descriptor"},
		{"index does not reach selected config", func(f *selectedImageFixture) {
			f.metadataConfig = digest.FromString("different platform config").String()
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{f.pin}}, ocispec.MediaTypeImageIndex)
		}, "not reachable"},
		{"index depth", func(f *selectedImageFixture) {
			for range podImageDepthLimit + 2 {
				f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{f.pin}}, ocispec.MediaTypeImageIndex)
			}
		}, limit},
		{"object count", func(f *selectedImageFixture) {
			children := make([]ocispec.Descriptor, podImageObjectLimit)
			for i := range children {
				children[i] = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString(fmt.Sprintf("missing platform %d", i)), Size: 100}
			}
			children = append(children, f.pin)
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: children}, ocispec.MediaTypeImageIndex)
		}, limit},
		{"descriptor count", func(f *selectedImageFixture) {
			children := make([]ocispec.Descriptor, podImageDescriptorLimit+1)
			for i := range children {
				children[i] = f.pin
			}
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: children}, ocispec.MediaTypeImageIndex)
		}, limit},
		{"total content bytes", func(f *selectedImageFixture) {
			var children []ocispec.Descriptor
			for i := range 10 {
				manifest := f.manifest
				manifest.Config.Digest = digest.FromString(fmt.Sprintf("other platform %d", i))
				manifest.Annotations = map[string]string{"padding": strings.Repeat("x", 900_000)}
				children = append(children, f.addJSON(manifest, ocispec.MediaTypeImageManifest))
			}
			children = append(children, f.pin)
			f.pin = f.addJSON(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: children}, ocispec.MediaTypeImageIndex)
		}, limit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelectedImageFixture(t)
			tc.prepare(f)
			err := f.resolver().VerifyContainerImage(t.Context(), selectedContainerID, selectedSandboxID, f.pin.Digest.String())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want %q", err, tc.want)
			}
		})
	}
}

// A stalled runtime fails the start within the caller's deadline.
func TestVerifyContainerImageDeadline(t *testing.T) {
	f := newSelectedImageFixture(t)
	f.stall = "content"
	r := f.resolver()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := r.VerifyContainerImage(ctx, selectedContainerID, selectedSandboxID, f.pin.Digest.String())
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("deadline not respected: %v after %s", err, time.Since(started))
	}
}

// Every start, including a restart, is verified afresh.
func TestVerifyContainerImageChecksEveryStart(t *testing.T) {
	f := newSelectedImageFixture(t)
	r := f.resolver()
	if err := r.VerifyContainerImage(t.Context(), selectedContainerID, selectedSandboxID, f.pin.Digest.String()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.snapshot.Parent = digest.FromString("changed snapshot").String()
	f.mu.Unlock()
	if err := r.VerifyContainerImage(t.Context(), selectedContainerID, selectedSandboxID, f.pin.Digest.String()); err == nil {
		t.Fatal("reused a previous container/image verification")
	}
}

// A tag or non-canonical digest is never accepted as the pin.
func TestVerifyContainerImageRejectsInvalidInputsBeforeRPC(t *testing.T) {
	r := &Resolver{}
	for _, input := range []struct{ container, sandbox, pin string }{
		{"", selectedSandboxID, testDigest},
		{selectedContainerID, "", testDigest},
		{selectedContainerID, selectedSandboxID, "registry/app:latest"},
		{selectedContainerID, selectedSandboxID, strings.ToUpper(testDigest)},
	} {
		if err := r.VerifyContainerImage(t.Context(), input.container, input.sandbox, input.pin); err == nil {
			t.Fatalf("accepted invalid input: %+v", input)
		}
	}
}
