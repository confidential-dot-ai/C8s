package workloadclaims

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Key identifies a (digest, argv, env, mounts) admission in the
// cumulative inventory. Host source commitments and access modes are included in identity.
// The framing must be injective: a collision erases historical evidence and can
// allow a sandbox to match a workload it did not actually run.
func (c SandboxContainer) Key() string {
	var key strings.Builder
	fmt.Fprintf(&key, "digest=%q argv=%q env=", c.Digest, c.Argv)
	if c.Env == nil {
		key.WriteString("nil")
	} else {
		encoded, _ := json.Marshal(c.Env)
		key.Write(encoded)
	}
	key.WriteString(" mounts=")
	if c.Mounts == nil {
		key.WriteString("nil")
	} else {
		key.WriteByte('[')
		for _, m := range c.Mounts {
			fmt.Fprintf(&key, "{%q %q %q %q %t}", m.Destination, m.Class, m.Storage, m.HostSourceDigest, m.ReadOnly)
		}
		key.WriteByte(']')
	}
	return key.String()
}

// Compare orders containers by digest, argv, then the full admission key.
// The digests endpoint uses this stable order so identical sandboxes report
// identical inventories.
func (c SandboxContainer) Compare(o SandboxContainer) int {
	return cmp.Or(strings.Compare(c.Digest, o.Digest), slices.Compare(c.Argv, o.Argv), strings.Compare(c.Key(), o.Key()))
}
