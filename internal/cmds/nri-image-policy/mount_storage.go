package nriimagepolicy

import "github.com/confidential-dot-ai/c8s/pkg/allowlist"

// mountStorageInspector proves a storage property from the mounted source.
// Implementations return Unknown whenever the complete proof is unavailable.
type mountStorageInspector interface {
	Inspect(source string) allowlist.MountStorage
	// NoMountsBelow reports whether the node's mount table holds no mount
	// strictly below source, so a recursive bind of it carries no nested
	// mount with access flags of its own. False whenever unproven.
	NoMountsBelow(source string) bool
}
