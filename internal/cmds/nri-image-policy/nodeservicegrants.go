package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
)

// NodeServiceGrantDir holds one file per container admitted as a node service
// (nodeservice.go), named by container ID and naming the component set entry
// that admitted it. Only this plugin writes it; the runtime wrapper reads it at
// the low-level runtime's create (internal/cmds/c8srunc).
//
// INVARIANT: not under workload_claims.socket_dir, which pods mount, and no
// declaration binds it.
const NodeServiceGrantDir = "/run/nri-image-policy-node-services"

func newNodeServiceGrantRecords(dir string) *grantRecords {
	return &grantRecords{dir: dir, jsonKey: "nodeService"}
}

// NodeServiceGrant is the node-service entry admission granted a container.
// The zero value is no grant.
type NodeServiceGrant struct {
	Entry string
}

func (g NodeServiceGrant) Granted() bool {
	return g.Entry != ""
}

// ReadNodeServiceGrant returns the node-service entry admission granted a
// container. A container with no record, and an id that can name none, hold no
// grant. An error reports a record that is not one this plugin wrote: a
// regular file in a directory, both owned by the reader (root on a node) and
// writable by nobody else.
func ReadNodeServiceGrant(dir, containerID string) (NodeServiceGrant, error) {
	if !validContainerID(containerID) {
		return NodeServiceGrant{}, nil
	}
	granted, err := newNodeServiceGrantRecords(dir).read(containerID)
	switch {
	case os.IsNotExist(err):
		return NodeServiceGrant{}, nil
	case err != nil:
		return NodeServiceGrant{}, err
	case len(granted) != 1 || len(granted[0]) != 1:
		return NodeServiceGrant{}, fmt.Errorf("%s names no node-service entry", filepath.Join(dir, containerID))
	}
	return NodeServiceGrant{Entry: granted[0][0]}, nil
}
