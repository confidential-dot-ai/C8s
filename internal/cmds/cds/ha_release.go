//go:build !c8s_dev

package cds

import "github.com/confidential-dot-ai/c8s/internal/cdsha"

// A release serves a cluster's CDS as the singleton; a replica of a replica
// set needs a c8s_dev build.
const servesReplicas = false

// haTiming is empty, so a replica runs on cdsha's own timers.
var haTiming cdsha.Timing
