//go:build !c8s_dev

package ta

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cdsha"

// haTimingOverride is empty, so a replica runs on cdsha's own timers.
var haTimingOverride cdsha.Timing
