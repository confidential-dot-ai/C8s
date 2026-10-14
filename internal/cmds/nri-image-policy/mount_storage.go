package nriimagepolicy

import "github.com/confidential-dot-ai/c8s/pkg/allowlist"

// mountStorageInspector proves a storage property from the mounted source and
// every mount the node holds below it, since a recursive bind carries those
// too. Implementations return Unknown whenever the complete proof is
// unavailable.
type mountStorageInspector interface {
	Inspect(source string) allowlist.MountStorage
}
