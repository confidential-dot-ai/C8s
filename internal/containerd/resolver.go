// Package containerd talks to a node's containerd: image digests, a container's
// stored OCI spec, a sandbox's recorded network, and stopping a container.
package containerd

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/distribution/reference"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minReconnectInterval throttles reconnect attempts so a sustained containerd
// outage cannot turn every image lookup into a re-dial storm.
const minReconnectInterval = time.Second

// Resolver resolves image tags to digests using containerd's image store.
type Resolver struct {
	client    *containerdclient.Client
	namespace string

	reconnectMu   sync.Mutex
	lastReconnect time.Time
}

// NewResolver creates a resolver connected to the containerd socket.
func NewResolver(socket, namespace string) (*Resolver, error) {
	c, err := containerdclient.New(socket)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd at %s: %w", socket, err)
	}

	return &Resolver{
		client:    c,
		namespace: namespace,
	}, nil
}

// Resolve looks up the digest for an image reference (e.g. "docker.io/grafana/grafana:12.3.1")
// by querying containerd's image store. The image must already be pulled.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (string, error) {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)

	// containerd stores images under their fully-qualified names
	// (e.g. docker.io/library/nginx:1.27); kubelet may pass short
	// forms (nginx:1.27, rancher/local-path-provisioner:v0.0.30).
	// Normalize before looking up.
	normalized := imageRef
	if named, err := reference.ParseDockerRef(imageRef); err == nil {
		normalized = named.String()
	}

	var img containerdclient.Image
	if err := r.withReconnect(func() error {
		var err error
		img, err = r.client.GetImage(nsCtx, normalized)
		return err
	}); err != nil {
		return "", fmt.Errorf("image not found in containerd store: %s: %w", normalized, err)
	}

	return img.Target().Digest.String(), nil
}

// ContainerSpec is the OCI spec containerd stored for a container.
func (r *Resolver) ContainerSpec(ctx context.Context, containerID string) (*specs.Spec, error) {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)
	var spec *specs.Spec
	if err := r.withReconnect(func() error {
		container, err := r.client.LoadContainer(nsCtx, containerID)
		if err != nil {
			return err
		}
		spec, err = container.Spec(nsCtx)
		return err
	}); err != nil {
		return nil, fmt.Errorf("read the OCI spec of container %s: %w", containerID, err)
	}
	return spec, nil
}

// StopContainer kills a container by its containerd ID.
func (r *Resolver) StopContainer(ctx context.Context, containerID string) error {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)

	var container containerdclient.Container
	if err := r.withReconnect(func() error {
		var err error
		container, err = r.client.LoadContainer(nsCtx, containerID)
		return err
	}); err != nil {
		return fmt.Errorf("load container %s: %w", containerID, err)
	}

	task, err := container.Task(nsCtx, nil)
	if err != nil {
		return fmt.Errorf("get task for %s: %w", containerID, err)
	}

	if err := task.Kill(nsCtx, syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill task for %s: %w", containerID, err)
	}

	return nil
}

// withReconnect runs op; if it fails because the containerd connection is
// unavailable (e.g. containerd was restarted), it re-dials once and retries.
// Non-connection failures (a genuinely absent image, a missing container) are
// returned as-is without a reconnect. Reconnects are throttled so a sustained
// outage does not spin.
func (r *Resolver) withReconnect(op func() error) error {
	return withReconnect(op, r.reconnect, isConnectionError)
}

// withReconnect is the transport-agnostic retry policy, split out so it can be
// tested without a live containerd.
func withReconnect(op func() error, reconnect func() error, isConnErr func(error) bool) error {
	err := op()
	if err == nil || !isConnErr(err) {
		return err
	}
	if reconnectErr := reconnect(); reconnectErr != nil {
		// Surface the original operation error; the reconnect failure is
		// secondary and would mask the reason the caller cares about.
		return err
	}
	return op()
}

// reconnect re-dials the containerd connection at most once per
// minReconnectInterval; concurrent callers that lose the throttle race skip the
// re-dial and rely on the one that won having refreshed the shared connection.
func (r *Resolver) reconnect() error {
	r.reconnectMu.Lock()
	defer r.reconnectMu.Unlock()
	if time.Since(r.lastReconnect) < minReconnectInterval {
		return nil
	}
	r.lastReconnect = time.Now()
	return r.client.Reconnect()
}

// isConnectionError reports whether err indicates the containerd connection is
// unavailable, as opposed to a NotFound / InvalidArgument the retry can't fix.
// containerd surfaces a downed connection either as a raw gRPC Unavailable
// status or as an errdefs.ErrUnavailable, depending on the call path.
func isConnectionError(err error) bool {
	return status.Code(err) == codes.Unavailable || errdefs.IsUnavailable(err)
}

// Close closes the containerd client connection.
func (r *Resolver) Close() error {
	return r.client.Close()
}
