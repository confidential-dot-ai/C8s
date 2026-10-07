package workflows

import "testing"

// The SNP lane's build step is the TDX lifecycle's staged mode: the commit
// under test selects the node image, so an image revision to pair against is
// no longer an input.
func TestSNPBuildUsesSelectedSource(t *testing.T) {
	doc := readWorkflow(t, "snp-metal-e2e.yml")
	testBuildUsesSelectedSource(t, doc.Jobs["e2e"].Steps, false, []string{
		"assert measured services and Kubernetes integration converged",
		"assert the image floor denies, then opens to a signed write",
		"assert a confidential workload runs with an injected cert"})
}
