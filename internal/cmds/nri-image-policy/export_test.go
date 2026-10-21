package nriimagepolicy

// The pod-role config test lives in nriimagepolicy_test because it runs
// nodeservices.Prepare, and nodeservices imports this package.
var (
	LoadConfig            = loadConfig
	RenderNodeImagePolicy = renderNodeImagePolicy
)

func SandboxModeOf(c *config) sandboxMode { return c.sandboxMode() }
