package podprovider

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// storedDocument parses the launch document a record froze. The provider wrote
// and signed it, so the record is trusted as written and the signature is not
// verified again on every read.
func storedDocument(trust trustSpec) (*launchconfig.Document, error) {
	return launchconfig.Parse(trust.InitData.Document)
}

// genericLaunch signs a generic-boot document: no pod section, no allowlist
// entries and a node name chosen at random, reachable only on the status port.
func (c *Config) genericLaunch(name string) (createRequest, error) {
	return c.signedRequest(c.document(name), nil)
}
