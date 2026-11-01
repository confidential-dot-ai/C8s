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

// MeshImageDigest is the mesh endpoint image the rendered fixture bakes.
const MeshImageDigest = meshImageDigest

const PodBootstrapServedDigest = pushDigestB

func SandboxModeOf(c *config) sandboxMode { return c.sandboxMode() }

// AdmitsCreation runs the creation hook of a plugin built from cfg for an
// ordinary, sandbox-compliant container of a pod in namespace, whose image
// resolves to digest. It answers whether a config's allowlist admits a plain
// workload. The mesh gate is not in this answer: it decides at adjustment
// validation over a protected sandbox, which only the namespace test holds
// (assertPodBootstrap).
func AdmitsCreation(cfg *config, namespace, image, digest string) error {
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     discardLogger(),
		containerd: &fakeContainerd{resolve: func(context.Context, string) (string, error) { return digest, nil }},
		mesh:       newMeshGate(*cfg.Mesh, discardLogger()),
	}
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()
	pod := sandboxedPod()
	pod.Namespace = namespace
	if cfg.Pod != nil {
		pod.Name = cfg.Pod.Name
	}
	// A pod CVM's static pod carries no service account token, and a
	// workload entry without a mounts policy admits platform mounts only.
	ctr := sandboxedContainer()
	ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
		return strings.HasSuffix(m.Destination, "/serviceaccount")
	})
	ctr.PodSandboxId = pod.Id
	ctr.Annotations = map[string]string{annotationImageName: image}
	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	return err
}
