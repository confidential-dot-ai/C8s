package nriimagepolicy

import (
	"context"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
)

// The pod-role config test lives in nriimagepolicy_test because it runs
// nodeservices.Prepare, and nodeservices imports this package.
var (
	LoadConfig            = loadConfig
	RenderNodeImagePolicy = renderNodeImagePolicy
	AssertPodBootstrap    = assertPodBootstrap
)

func SandboxModeOf(c *config) sandboxMode { return c.sandboxMode() }

// AdmitsCreation runs the creation validator of a plugin built from cfg for
// an ordinary, sandbox-compliant container of a pod in namespace, whose image
// resolves to digest. It answers whether a config admits a plain workload.
func AdmitsCreation(cfg *config, namespace, image, digest string) error {
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     discardLogger(),
		containerd: &fakeContainerd{resolve: func(context.Context, string) (string, error) { return digest, nil }},
		mesh:       newMeshGate(cfg.Mesh, discardLogger()),
	}
	p.inventory = newAdmissionInventory("/proc")
	pod := sandboxedPod()
	pod.Namespace = namespace
	// A pod CVM's static pod carries no service account token, and a
	// workload entry without a mounts policy admits platform mounts only.
	ctr := sandboxedContainer()
	ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
		return strings.HasSuffix(m.Destination, "/serviceaccount")
	})
	ctr.PodSandboxId = pod.Id
	ctr.Annotations = map[string]string{annotationImageName: image}
	return p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr})
}
