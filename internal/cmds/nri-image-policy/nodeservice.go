package nriimagepolicy

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

// A node service is a pod of one container serving the whole node: a component
// set entry marked nodeService, which pins its digest, command, args,
// environment and mounts. Admission excuses its container the host-privilege
// rules exactly as the measured base excuses a static pod it pins
// (nodetcb.go), host ports aside, and records the grant for the runtime
// wrapper's floor (nodeservicegrants.go). The control plane writes the pod, so
// two rules hold it to what the entry leaves: the container runs alone in its
// pod, and one pod of that entry runs on the node. See
// docs/allowlist-and-capabilities.md.

// nodeServiceRule names the rule in a refusal's log and audit record.
const nodeServiceRule = "node_service"

// nodeServiceOf is the node-service entry a component set in force binds to
// this container's launch, and the refusal when the pod it runs in is not that
// node service's pod.
//
// The digest is resolved only where the applied document declares a node
// service, so an ordinary container costs no containerd round-trip.
func (p *plugin) nodeServiceOf(ctx context.Context, snap *policySnapshot, observed observedContainer) (allowlist.NodeServiceRef, error) {
	if !p.policy.declaresNodeService(snap) {
		return allowlist.NodeServiceRef{}, nil
	}
	service, _ := p.policy.nodeServiceOf(snap, p.observedLaunch(ctx, observed))
	if err := p.nodeServiceRefusal(snap, observed, service); err != nil {
		return allowlist.NodeServiceRef{}, err
	}
	return service, nil
}

// nodeServiceRefusal is why this container may not run in this sandbox, nil
// when it may. The rules read the containers the inventory records for each
// sandbox, so judging one container again — at its start, at a recheck or
// after this enforcer restarted — judges it the same, and a kubelet that
// starts the entry's container again takes its predecessor's place.
func (p *plugin) nodeServiceRefusal(snap *policySnapshot, observed observedContainer, service allowlist.NodeServiceRef) error {
	sandboxID := observed.pod.GetId()
	recorded := p.recordedBySandbox()
	if service.Entry == "" {
		if held := p.nodeServiceIn(snap, recorded[sandboxID]); held != "" {
			return fmt.Errorf("a node service runs alone in its pod: the pod runs node service %q", held)
		}
		return nil
	}
	for _, c := range recorded[sandboxID] {
		if held, _ := p.policy.nodeServiceOf(snap, c.Running()); held.Entry != service.Entry {
			return fmt.Errorf("a node service runs alone in its pod: node service %q runs beside the container admitted as %s", service.Entry, c.Digest)
		}
	}
	if holder := p.sandboxHolding(snap, recorded, sandboxID, service.Entry); holder != "" {
		return fmt.Errorf("a node service runs in one pod on the node: node service %q runs in sandbox %s", service.Entry, holder)
	}
	// Two containers of one launch share a record, so the live containers tell
	// a second copy of the node service from the container being judged.
	if beside := p.liveContainerBeside(sandboxID, observed.ctr.GetId()); beside != "" {
		return fmt.Errorf("a node service runs alone in its pod: node service %q runs beside container %q", service.Entry, beside)
	}
	return nil
}

// nodeServiceIn is the node-service entry one of these recorded containers was
// admitted by, "" when none was.
func (p *plugin) nodeServiceIn(snap *policySnapshot, containers []workloadclaims.SandboxContainer) string {
	for _, c := range containers {
		if service, held := p.policy.nodeServiceOf(snap, c.Running()); held {
			return service.Entry
		}
	}
	return ""
}

// sandboxHolding is the sandbox other than this one whose recorded containers
// hold entry, "" when none does.
func (p *plugin) sandboxHolding(snap *policySnapshot, recorded map[string][]workloadclaims.SandboxContainer, sandboxID, entry string) string {
	for id, containers := range recorded {
		if id == sandboxID {
			continue
		}
		for _, c := range containers {
			if service, held := p.policy.nodeServiceOf(snap, c.Running()); held && service.Entry == entry {
				return id
			}
		}
	}
	return ""
}

// noteNodeService records a node service's grant for the runtime wrapper's
// privilege floor, and refuses a container of a pod the node-service rules do
// not admit. The record belongs to the validation hook, as the capability
// grant does: the wrapper reads it at the create.
func (p *plugin) noteNodeService(ctx context.Context, snap *policySnapshot, observed observedContainer) error {
	service, err := p.nodeServiceOf(ctx, snap, observed)
	if err != nil {
		return err
	}
	var granted [][]string
	if service.Entry != "" {
		granted = [][]string{{service.Entry}}
		p.logger.Info("admitting a node service past the host-privilege rules",
			"namespace", observed.pod.GetNamespace(), "pod", observed.pod.GetName(),
			"container", observed.ctr.GetName(), "entry", service.Entry, "set", service.Set.Version)
	}
	if err := p.nodeServiceGrants.note(observed.ctr.GetId(), granted); err != nil {
		p.logger.Error("cannot record the container's node-service grant; the runtime wrapper holds it to the privilege floor",
			"container", observed.ctr.GetId(), "error", err)
	}
	return nil
}
