package nriimagepolicy

// The pod-role config test lives in nriimagepolicy_test because it runs
// nodeservices.Prepare, and nodeservices imports this package.
var (
	LoadConfig            = loadConfig
	RenderNodeImagePolicy = renderImagePolicyTemplate
	AssertPodBootstrap    = assertPodBootstrap
)

// MeshImageDigest is the mesh endpoint image the rendered fixture bakes.
const MeshImageDigest = meshImageDigest

const PodBootstrapServedDigest = pushDigestB

func SandboxModeOf(c *config) sandboxMode { return c.sandboxMode() }
