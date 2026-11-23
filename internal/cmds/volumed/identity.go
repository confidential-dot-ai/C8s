package volumed

import (
	"fmt"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

// PeerIdentity resolves a caller to the pod the kernel says it is in.
//
// The pod decides where the volume mounts, so it is taken from the caller's
// cgroup via kernel peer credentials and never from the request.
type PeerIdentity struct {
	ProcRoot string
}

// Resolve returns the pod the calling process belongs to.
func (p PeerIdentity) Resolve(peer workloadclaims.Peer) (PodCgroup, error) {
	pods, err := PodCandidatesForPID(p.procRoot(), peer.PID())
	if err != nil {
		return PodCgroup{}, err
	}
	// Rechecked after the /proc read so a caller that exited mid-resolution
	// cannot have its PID reused by another pod's container.
	if !peer.IsAlive() {
		return PodCgroup{}, fmt.Errorf("volumed: caller exited during resolution")
	}
	return pods[0], nil
}

func (p PeerIdentity) procRoot() string {
	if p.ProcRoot != "" {
		return p.ProcRoot
	}
	return "/proc"
}
