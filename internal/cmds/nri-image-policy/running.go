package nriimagepolicy

import (
	"sync"

	"github.com/containerd/nri/pkg/api"
)

// runningContainers is every container on this node that has started and not
// since stopped, as the runtime described it at its start or at registration.
type runningContainers struct {
	mu   sync.Mutex
	byID map[string]runningContainer
}

type runningContainer struct {
	pod *api.PodSandbox
	ctr *api.Container
}

func (r *runningContainers) add(pod *api.PodSandbox, ctr *api.Container) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = map[string]runningContainer{}
	}
	r.byID[ctr.GetId()] = runningContainer{pod: pod, ctr: ctr}
}

func (r *runningContainers) remove(containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, containerID)
}

// list returns a copy, so callers check and kill without holding the lock.
func (r *runningContainers) list() []runningContainer {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]runningContainer, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c)
	}
	return out
}
