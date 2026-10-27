package nriimagepolicy

import (
	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ObserveRecordedMounts classifies the mounts of a container recorded on a
// node (its OCI mounts, name, pod UID and sandbox ID) as admission classifies
// them, so a build-time tool can derive the exact mount rules of a node
// component from a booted node (node-guest-image/c8s/systemfloor).
func ObserveRecordedMounts(podUID, sandboxID, container string, mounts []*api.Mount) []allowlist.ObservedMount {
	pod := &api.PodSandbox{Id: sandboxID, Uid: podUID}
	ctr := &api.Container{PodSandboxId: sandboxID, Name: container, Mounts: mounts}
	return newMountObserver(nil, nodeMounts{}).Observe(pod, ctr)
}
