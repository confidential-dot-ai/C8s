package nriimagepolicy

import (
	"errors"
	"os"

	"github.com/containerd/nri/pkg/api"
)

// emptyGenericAssignment is the sole exception to the Pod restart refusal.
// The reconciled journal, runtime inventory and immutable manifest must all
// prove that this generic boot has never published or started its assigned Pod.
func (p *plugin) emptyGenericAssignment(pods []*api.PodSandbox, ctrs []*api.Container, manifest string) bool {
	if p.cfg.Pod == nil || !p.cfg.Pod.Generic || p.cfg.Pod.Waiting || p.cfg.Pod.UID == "" || p.measurer == nil || len(p.measurer.Digests()) != 0 || len(pods) != 0 || len(ctrs) != 0 {
		return false
	}
	_, err := os.Lstat(manifest)
	return errors.Is(err, os.ErrNotExist)
}
