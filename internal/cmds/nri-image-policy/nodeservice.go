package nriimagepolicy

import (
	"context"
	"fmt"
	"sync"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

// nodeServices is the node's node-service count: which sandbox holds each
// entry, and the container names admission cleared in each sandbox. It is
// memory alone; a restart rebuilds it from the containers the runtime reports
// (recountNodeServices).
type nodeServices struct {
	mu        sync.Mutex
	bySandbox map[string]*nodeServiceSandbox
	byEntry   map[string]string
}

// nodeServiceSandbox is one sandbox's part of the count: the container names
// admission cleared in it, and the node-service entry one of them holds.
type nodeServiceSandbox struct {
	containers map[string]bool
	entry      string
	container  string
}

// hold records a container admission cleared in a sandbox and, where a
// node-service entry admits its launch, the node's one instance of that entry.
// It reports why that sandbox may not run the container.
func (n *nodeServices) hold(sandboxID, container, entry string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bySandbox == nil {
		n.bySandbox, n.byEntry = map[string]*nodeServiceSandbox{}, map[string]string{}
	}
	sandbox := n.bySandbox[sandboxID]
	if sandbox == nil {
		sandbox = &nodeServiceSandbox{containers: map[string]bool{}}
		n.bySandbox[sandboxID] = sandbox
	}
	if entry == "" {
		if sandbox.entry != "" && sandbox.container != container {
			return fmt.Errorf("a node service runs alone in its pod: the pod runs node service %q", sandbox.entry)
		}
		sandbox.containers[container] = true
		return nil
	}
	if beside := sandbox.besides(container); beside != "" {
		return fmt.Errorf("a node service runs alone in its pod: node service %q runs beside container %q", entry, beside)
	}
	if holder, held := n.byEntry[entry]; held && holder != sandboxID {
		return fmt.Errorf("a node service runs in one pod on the node: node service %q runs in sandbox %s", entry, holder)
	}
	sandbox.containers[container] = true
	sandbox.entry, sandbox.container = entry, container
	n.byEntry[entry] = sandboxID
	return nil
}

func (s *nodeServiceSandbox) besides(container string) string {
	for name := range s.containers {
		if name != container {
			return name
		}
	}
	return ""
}

func (n *nodeServices) forget(sandboxID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	sandbox := n.bySandbox[sandboxID]
	if sandbox == nil {
		return
	}
	if sandbox.entry != "" && n.byEntry[sandbox.entry] == sandboxID {
		delete(n.byEntry, sandbox.entry)
	}
	delete(n.bySandbox, sandboxID)
}

// nodeServiceOf is the node-service entry a component set in force binds to
// this container's launch, and the refusal when the pod it runs in is not that
// node service's pod. The container joins its sandbox's record here, so the
// rules read what admission cleared.
//
// The digest is resolved only where the applied document declares a node
// service, so an ordinary container costs no containerd round-trip.
func (p *plugin) nodeServiceOf(ctx context.Context, observed observedContainer) (allowlist.NodeServiceRef, error) {
	var service allowlist.NodeServiceRef
	if p.policy.declaresNodeService() {
		service, _ = p.policy.nodeServiceOf(p.observedLaunch(ctx, observed))
	}
	if err := p.nodeServices.hold(observed.pod.GetId(), observed.ctr.GetName(), service.Entry); err != nil {
		return allowlist.NodeServiceRef{}, err
	}
	return service, nil
}

// noteNodeService records a node service's grant for the runtime wrapper's
// privilege floor, and refuses a container of a pod the node-service rules do
// not admit. The record belongs to the validation hook, as the capability
// grant does: the wrapper reads it at the create.
func (p *plugin) noteNodeService(ctx context.Context, observed observedContainer) error {
	service, err := p.nodeServiceOf(ctx, observed)
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

// recountNodeServices rebuilds the node-service count from the containers the
// runtime reported at registration.
func (p *plugin) recountNodeServices(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) {
	podByID := podsByID(pods)
	for _, ctr := range ctrs {
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil || ctr.GetState() == api.ContainerState_CONTAINER_STOPPED {
			continue
		}
		observed := p.observeContainer(pod, ctr, ctr.GetAnnotations()[annotationImageName])
		if _, err := p.nodeServiceOf(ctx, observed); err != nil {
			p.logger.Warn("a container running before this enforcer connected breaks a node-service rule; its next start is refused",
				"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "error", err)
		}
	}
}
