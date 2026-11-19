package cds

import (
	"fmt"
	"sync/atomic"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// nodeSet is the node images this CDS certifies: the launch file's, until a
// replica set's chain names others (a nodes entry). /attest, the
// sandbox-digests client and /measurements all read the one set in force.
type nodeSet struct {
	current atomic.Pointer[nodeImages]
}

type nodeImages struct {
	values refvalues.ReferenceValues
	// document is the set as /measurements serves it.
	document []byte
}

func newNodeSet(values refvalues.ReferenceValues) (*nodeSet, error) {
	n := &nodeSet{}
	return n, n.set(values)
}

// set replaces the set in force from the next request on.
func (n *nodeSet) set(values refvalues.ReferenceValues) error {
	document, err := refvalues.Render(values)
	if err != nil {
		return fmt.Errorf("render /measurements document: %w", err)
	}
	n.current.Store(&nodeImages{values: values, document: document})
	return nil
}

func (n *nodeSet) images() []remote.ImagePin { return n.current.Load().values.Images }

func (n *nodeSet) pins() armtls.Pins { return armtls.Pins{Images: n.images()} }

func (n *nodeSet) document() []byte { return n.current.Load().document }
