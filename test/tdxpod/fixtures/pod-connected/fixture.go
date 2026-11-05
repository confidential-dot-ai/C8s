// Package podfixture shares the measured connected acceptance workload: the
// image the pod document pins, the argv of each of its modes and the timing
// the workload, its in-pod checker and the outside judges agree on. The
// program itself is netcheck/, built into Image by the Dockerfile beside it.
package podfixture

import (
	"strconv"
	"time"
)

// Image is the published workload image: conformance-images.yml run
// 41619128412 built it from the Dockerfile in this directory at the source
// of this fixture.
const Image = "ghcr.io/confidential-dot-ai/c8s-conformance-pod-netcheck@sha256:1c35bf20bccce071ed340f1e8611058321113df370d8f813f6a4d4de157094e4"

// Command is the workload's executable; the allowlist pins it exactly.
func Command() []string { return []string{"/usr/local/bin/pod-netcheck"} }

// The modes, each the first argument of its argv.
const (
	ModeServe    = "serve"     // the application: probes and the HTTP report
	ModeCheck    = "check"     // the in-pod checker reading the application's report
	ModeCDSProbe = "cds-probe" // the guest probe of an owned CDS endpoint
	ModeHello    = "hello"     // an independently ready application, no probes
)

// ServeArgs is the application's argv; config is the compact JSON the
// netcheck config type reads.
func ServeArgs(config string) []string { return []string{ModeServe, config} }

// CheckArgs is the checker's argv, with the application's config.
func CheckArgs(config string) []string { return []string{ModeCheck, config} }

// CDSProbeArgs is the guest probe's argv. A zero hold selects restart mode,
// which exits once after ProbeRestartHold of continuous unreachability;
// otherwise renewal mode withdraws readiness after hold, which the probe
// accepts only when it equals ProbeRenewalHold.
func CDSProbeArgs(host string, hold time.Duration) []string {
	args := []string{ModeCDSProbe, host}
	if hold > 0 {
		args = append(args, strconv.Itoa(int(hold.Seconds())))
	}
	return args
}

// HelloArgs is the argv of the independently ready application.
func HelloArgs() []string { return []string{ModeHello} }

// Timing of the application and its checker; the readiness cycle the outside
// judges expect follows from ReadyAfter, DipStart and DipEnd.
const (
	Period             = 15 * time.Second   // between probe rounds
	Freshness          = 90 * time.Second   // a report older than this is stale
	ReadyAfter         = 120 * time.Second  // readiness after the first full pass
	DipStart           = 300 * time.Second  // readiness withdrawn from here
	DipEnd             = 480 * time.Second  // and restored from here
	TransitionDeadline = 700 * time.Second  // the checker has seen all three states by here
	Soak               = 3900 * time.Second // the checker exits 0 after this much healthy time
	InitialDeadline    = 1200 * time.Second // the first full pass must come by here
	CheckerDeadline    = 5400 * time.Second // the checker gives up here
	CheckerPeriod      = 10 * time.Second   // between checker reads
)

// Timing of the CDS guest probe.
const (
	ProbeRestartHold    = 120 * time.Second  // continuous outage before the one exit
	ProbeRenewalHold    = 3900 * time.Second // the only accepted renewal hold
	ProbeReachableBy    = 60 * time.Second   // the CDS must answer once by here
	ProbeRestartBudget  = 600 * time.Second  // restart mode's whole observation
	ProbeRenewalGrace   = 900 * time.Second  // renewal mode observes for hold plus this
	ProbeConnectTimeout = 2 * time.Second
)

// Exit statuses, read through authenticated pod status.
const (
	ExitInitialTimeout  = 10 // no full pass by InitialDeadline
	ExitTransitions     = 11 // a readiness state missing by TransitionDeadline
	ExitSoakTimeout     = 12 // CheckerDeadline passed
	ExitProbeUnwritable = 42 // the restart directory is not writable
	ExitProbeTransport  = 43 // a failure that is not a transport failure
	ExitProbeMarker     = 44 // the restart marker could not be created
	ExitProbeUnreached  = 45 // the CDS never answered by ProbeReachableBy
	ExitProbeNoOutage   = 46 // the observation ended without a confirmed outage
	ExitProbeHold       = 47 // a renewal hold other than ProbeRenewalHold
)
