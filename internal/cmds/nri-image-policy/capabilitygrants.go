package nriimagepolicy

import "os"

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

func newCapabilityGrantRecords(dir string) *grantRecords {
	return &grantRecords{dir: dir, jsonKey: "capabilities"}
}

// ReadCapabilityGrant returns the capability sets admission granted a
// container, spelled with no CAP_ prefix. A container with no record holds
// none. An error reports a record that is not one this plugin wrote: a regular
// file in a directory, both owned by the reader (root on a node) and writable
// by nobody else.
func ReadCapabilityGrant(dir, containerID string) ([][]string, error) {
	caps, err := newCapabilityGrantRecords(dir).read(containerID)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return caps, err
}
