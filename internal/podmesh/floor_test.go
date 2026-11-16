package podmesh

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A default drop of a declarable capability would take it from a container the node admits.
func TestFloorDroppedCapabilitiesAreUndeclarable(t *testing.T) {
	for _, name := range floorDroppedCapabilities {
		if !pkgallowlist.UndeclarableCapability(string(name)) {
			t.Errorf("capability %s may be declared by an entry, so the floor must not drop it by default", name)
		}
	}
}
