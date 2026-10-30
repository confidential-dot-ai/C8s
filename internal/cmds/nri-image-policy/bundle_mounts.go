package nriimagepolicy

import (
	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ClassifyBundleMount classifies one mount of a container's OCI bundle as
// admission does, for the runtime wrapper, which sees the bundle but not the
// NRI view. The pod and container come from the bundle's CRI annotations; a
// source that does not match them is classified as a host mount. ok is false
// for a mount that carries no host bytes, such as a kernel filesystem.
func ClassifyBundleMount(podUID, sandboxID, containerName string, m *api.Mount) (class allowlist.MountClass, ok bool) {
	if !carriesHostBytes(m) {
		return "", false
	}
	ctx := MountContext{
		PodUID:    podUID,
		SandboxID: sandboxID,
		Pod:       &api.PodSandbox{Id: sandboxID, Uid: podUID},
		Container: &api.Container{Name: containerName, PodSandboxId: sandboxID},
		Storage:   noStorage{},
	}
	return newMountObserver(ctx.Storage, nodeMounts{}).observeMount(ctx, m).Class, true
}

// noStorage answers no storage evidence: classification does not need it.
type noStorage struct{}

func (noStorage) Inspect(string) allowlist.MountStorage { return allowlist.MountUnknown }
