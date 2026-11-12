package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// containerMounts bind-mounts what the node hands a credential client,
// read-only: the inventory's socket directory at
// workloadclaims.SidecarSocketDir into the socket consumers
// (workloadclaims.IsSocketConsumer) of an injected pod, the node's CDS
// attestation policy at workloadclaims.CDSPinsPath, and the CDS endpoint it
// dials at workloadclaims.CDSAddressPath. All are OCI-level replacements for a
// pod-spec hostPath volume, which PodSecurity baseline and restricted would
// reject. nil for every other container, and whenever the inventory is
// disabled.
//
// The two policy mounts are what make the CDS a client reaches trusted: it
// reads compiled paths, so a pod cannot name another source and the control
// plane cannot pass one as an argument. A container running as the credentials
// identity that this node's measured base grants no such role is refused.
func (c nodeCVM) containerMounts(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error) {
	p := c.p
	if fetchesRouteManifest(pod, ctr) {
		if err := p.refusedUntilFirstDecree(); err != nil {
			return nil, err
		}
		return p.routerCDSMount(), nil
	}
	injected := injectedCredentialSidecar(pod, ctr)
	if !holdsCredentialsIdentity(ctr) && !injected {
		return nil, nil
	}
	if holdsCredentialsIdentity(ctr) && p.measuredRole(ctx, pod, ctr) != CredentialRole {
		return nil, fmt.Errorf("container %q runs as the credentials identity (uid %d) but this node's measured base grants it no %s role, so it would reach CDS unpinned",
			ctr.GetName(), workloadclaims.CredentialsUID, CredentialRole)
	}
	socketDir := ""
	if servesInventory := p.inventory != nil; servesInventory {
		socketDir = p.cfg.WorkloadClaims.SocketDir
	}
	var mounts []*api.Mount
	for _, bind := range []struct{ source, destination string }{
		{socketDir, workloadclaims.SidecarSocketDir},
		{p.cdsPins, workloadclaims.CDSPinsPath},
		{p.cdsAddress, workloadclaims.CDSAddressPath},
	} {
		if bind.source != "" && takesNodeMount(pod, ctr, bind.destination) {
			mounts = append(mounts, readOnlyBind(bind.source, bind.destination))
		}
	}
	if len(mounts) == 0 {
		return nil, nil
	}
	if err := p.refusedUntilFirstDecree(); err != nil {
		return nil, err
	}
	return &api.ContainerAdjustment{Mounts: mounts}, nil
}

// A Pod CVM's one guest bind is the client document.
func (c podCVM) containerMounts(_ context.Context, _ *api.PodSandbox, _ *api.Container) (*api.ContainerAdjustment, error) {
	if c.p.clientDocument == "" {
		return nil, nil
	}
	return &api.ContainerAdjustment{Mounts: []*api.Mount{readOnlyBind(c.p.clientDocument, workloadclaims.ClientDocumentPath)}}, nil
}

// refusedUntilFirstDecree refuses immediately rather than waiting: the look
// can outlast containerd's NRI request timeout, and the kubelet retries the
// creation.
func (p *plugin) refusedUntilFirstDecree() error {
	if p.awaitingDecree.Load() {
		return errors.New("the node is still taking its first CDS pin decree; retry once it has")
	}
	return nil
}

// holdsCredentialsIdentity reports whether this container runs as the identity
// the pod ruleset admits the node's CDS for. The grant itself is the measured
// role.
func holdsCredentialsIdentity(ctr *api.Container) bool {
	return ctr.GetUser().GetUid() == workloadclaims.CredentialsUID
}

// fetchesRouteManifest reports whether this container is the one the router's
// route manifest comes through: its attest sidecar, on the upstream identity
// that pod's ruleset admits the node's CDS for (meshgate_linux.go). The pod is
// the chart's own in a namespace the enforcer compiles in, and the measured
// base binds every container of it to a role, so the name holds no privilege
// of its own.
func fetchesRouteManifest(pod *api.PodSandbox, ctr *api.Container) bool {
	return pod.GetNamespace() == routerNamespace &&
		ctr.GetName() == workloadclaims.AttestContainerName &&
		ctr.GetUser().GetUid() == workloadclaims.UpstreamUID
}

// routerCDSMount is the CDS endpoint and the node's CDS pins: without the
// followed pins the router loses its routes the moment an image roll retires
// its launch-time set. The pins land at a path of their own, so the router is
// not handed a credential client's trust root.
func (p *plugin) routerCDSMount() *api.ContainerAdjustment {
	var mounts []*api.Mount
	if p.cdsAddress != "" {
		mounts = append(mounts, readOnlyBind(p.cdsAddress, workloadclaims.CDSAddressPath))
	}
	if p.cdsPins != "" {
		mounts = append(mounts, readOnlyBind(p.cdsPins, workloadclaims.RouterCDSPinsPath))
	}
	if len(mounts) == 0 {
		return nil
	}
	return &api.ContainerAdjustment{Mounts: mounts}
}

// injectedCredentialSidecar reports the webhook's own shape: a reserved
// sidecar name on a pod the injector annotated. Both are tenant-forgeable, so
// every socket in the directory stays safe against any on-node caller through
// peer-credential binding and a read-only mount.
func injectedCredentialSidecar(pod *api.PodSandbox, ctr *api.Container) bool {
	return pod.GetAnnotations()[workloadclaims.AnnotationInjected] == "true" &&
		workloadclaims.IsSocketConsumer(ctr.GetName())
}

// measuredRole is the role the node's measured base grants this launch, from
// the evidence the runtime reports at CreateContainer: digest, argv,
// environment and the mounts requested so far, classified as the final check
// classifies them, so a declaration that pins a mount set is matched here too.
// StartContainer re-reads the same fields from the final spec.
func (p *plugin) measuredRole(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) string {
	imageRef, err := p.cvm().imageOf(pod, ctr)
	if err != nil {
		return ""
	}
	return p.roleOf(p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), p.observedMounts(pod, ctr)))
}

func readOnlyBind(source, destination string) *api.Mount {
	return &api.Mount{
		Destination: destination,
		Type:        "bind",
		Source:      source,
		Options:     []string{"rbind", "ro", "rprivate", "nosuid", "nodev", "noexec"},
	}
}
