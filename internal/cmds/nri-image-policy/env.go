package nriimagepolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ValidateContainerAdjustment runs after all create-time plugins. Unlike a
// StartContainer notification, a failed/disconnected validator rejects creation.
// Together with containerd's required_plugins configuration this prevents a
// plugin disconnect between creation and start from bypassing launch admission.
func (p *plugin) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
	if req.GetContainer() == nil || req.GetPod() == nil {
		return fmt.Errorf("missing container or sandbox in NRI validation")
	}
	ctr, env := adjustedLaunchContainer(req)
	verdict, reason := p.checkContainerObserved(ctx, p.cfg, req.GetPod(), ctr, ctr.GetAnnotations()[annotationImageName], launchFinal, env, adjustedMounts(req, ctr))
	if verdict == verdictDeny && p.cfg.Policy.Mode != ModeAudit {
		return fmt.Errorf("%s", reason)
	}
	// No inventory record here: later validators can still reject creation, and
	// CDI transformations under an any policy have not happened yet.
	return nil
}

// adjustedLaunchContainer applies the env/argv part of cumulative NRI edits.
// For valid unique input names this is equivalent to NRI's AdjustEnv: the last
// edit per name wins; marked names are removed. Order is irrelevant to policy.
// Invalid input or deferred CDI injection yields unknown env evidence, so only
// unrestricted env policies can admit it at this stage. Never guess an empty env.
func adjustedLaunchContainer(req *api.ValidateContainerAdjustmentRequest) (*api.Container, *allowlist.EnvObservation) {
	ctr := proto.Clone(req.GetContainer()).(*api.Container)
	adjust := req.GetAdjust()
	if len(adjust.GetArgs()) > 0 {
		ctr.Args = slices.Clone(adjust.GetArgs())
	}
	if len(adjust.GetCDIDevices()) > 0 {
		return ctr, nil
	}
	if len(adjust.GetEnv()) == 0 {
		return ctr, containerEnv(ctr)
	}
	if _, err := observeEnv(ctr); err != nil {
		return ctr, nil
	}
	values := map[string]string{}
	for _, entry := range ctr.Env {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	for _, edit := range adjust.GetEnv() {
		if edit == nil {
			return ctr, nil
		}
		name, remove := edit.IsMarkedForRemoval()
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return ctr, nil
		}
		if remove {
			delete(values, name)
		} else {
			values[name] = edit.Value
		}
	}
	ctr.Env = nil
	for name, value := range values {
		ctr.Env = append(ctr.Env, name+"="+value)
	}
	return ctr, containerEnv(ctr)
}

// adjustedMounts observes cumulative edits; deferred CDI leaves evidence unavailable.
func adjustedMounts(req *api.ValidateContainerAdjustmentRequest, ctr *api.Container) []allowlist.ObservedMount {
	if len(req.GetAdjust().GetCDIDevices()) > 0 {
		return nil
	}
	for _, edit := range req.GetAdjust().GetMounts() {
		if edit == nil {
			return nil
		}
		destination, remove := edit.IsMarkedForRemoval()
		ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
			return m.GetDestination() == destination
		})
		if !remove {
			ctr.Mounts = append(ctr.Mounts, proto.Clone(edit).(*api.Mount))
		}
	}
	return newMountObserver(nil).Observe(req.GetPod(), ctr)
}
