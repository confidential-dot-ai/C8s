// Package policymeasure records in TDX RTMR[3] every allowlist policy a node
// enforces, so a verifier can check the node's whole policy history since
// boot, and lets the node's other measured consumers account for those
// extends. See docs/allowlist-and-capabilities.md, "Measured policy history".
// The journal paths live in armtls so the public package carries no internal
// import.
package policymeasure

import (
	"errors"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// JournalName is the journal file in the NRI plugin's runtime directory, a
// tmpfs that lives exactly as long as the register.
const JournalName = armtls.MeasuredPoliciesJournal

// Where readers beside the measurer find the journal. They assume the default
// runtime directory (nriImagePolicy.hostPaths.runtimeDir).
const (
	// NodeJournal is the path on the node, and in pods that mount the runtime
	// directory at its host path.
	NodeJournal = armtls.NodeJournal
	// SidecarJournal is the path in sidecars the NRI plugin mounts the runtime
	// directory into (workloadclaims.SidecarSocketDir).
	SidecarJournal = armtls.SidecarJournal
)

// Open returns the journal that measures policies into this node's RTMR[3],
// whose launch seeded it from anchor. It returns nil, nil on a platform
// without a runtime register.
func Open(dir string, platform teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
	reg, err := runtimemeasure.Open(platform)
	if errors.Is(err, runtimemeasure.ErrNoRegister) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return runtimemeasure.OpenJournalSeeded(filepath.Join(dir, JournalName), reg, runtimemeasure.Seed(anchor))
}
