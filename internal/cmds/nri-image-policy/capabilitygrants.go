package nriimagepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// CapabilityGrantDir holds one file per container admission cleared whose
// launch an allowlist entry declares capabilities for
// (allowlist.Container.Capabilities), named by container ID and listing what
// each of those entries declares. Only this plugin writes it; the runtime
// wrapper reads it at the low-level runtime's create, so the start check the
// runtime skips when this plugin does not answer is not the only capability
// bound (internal/cmds/c8srunc).
//
// INVARIANT: not under workload_claims.socket_dir, which pods mount, and no
// declaration binds it.
const CapabilityGrantDir = "/run/nri-image-policy-caps"

// capabilityGrant is one record's content: the capability sets the entries
// admitting the container's launch declare for it.
type capabilityGrant struct {
	Capabilities [][]string `json:"capabilities"`
}

// capabilityGrants writes and removes those records.
type capabilityGrants struct {
	dir string
}

// note records what the entries admitting a container's launch declare for
// it, and removes any stale record when they declare nothing, so a record
// exists exactly while admission last granted that container capabilities.
func (g *capabilityGrants) note(containerID string, caps [][]string) error {
	if g == nil {
		return nil
	}
	if len(caps) == 0 {
		g.remove(containerID)
		return nil
	}
	if !validContainerID(containerID) {
		return fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	data, err := json.Marshal(capabilityGrant{Capabilities: caps})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(g.dir, containerID), data, 0o600)
}

func (g *capabilityGrants) remove(containerID string) {
	if g == nil || !validContainerID(containerID) {
		return
	}
	_ = os.Remove(filepath.Join(g.dir, containerID))
}

// ReadCapabilityGrant returns the capability sets admission granted a
// container, spelled with no CAP_ prefix. A container with no record holds
// none. An error reports a record that is not one this plugin wrote: a regular
// file in a directory, both owned by the reader (root on a node) and writable
// by nobody else.
func ReadCapabilityGrant(dir, containerID string) ([][]string, error) {
	if !validContainerID(containerID) {
		return nil, fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	if err := requireOwnerOnly(dir, true); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	path := filepath.Join(dir, containerID)
	if err := requireOwnerOnly(path, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var grant capabilityGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return grant.Capabilities, nil
}
