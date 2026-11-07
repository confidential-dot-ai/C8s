//go:build !c8s_dev

package cds

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// haTimingOverride is empty, so a replica runs on cdsha's own timers.
var haTimingOverride cdsha.Timing

// bindAttestationAPIFlag adds no flag: a release verifies every replica
// in-process, against the hardware roots.
func bindAttestationAPIFlag(
	*cobra.Command,
	*cdsconn.PinVerifier,
) {
}
