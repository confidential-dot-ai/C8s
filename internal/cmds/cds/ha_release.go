//go:build !c8s_dev

package cds

import "github.com/confidential-dot-ai/c8s/internal/cdsha"

// haTimingOverride is empty, so a replica runs on cdsha's own timers.
var haTimingOverride cdsha.Timing
