//go:build !c8s_node

// Package helmchart bundles the C8s Helm chart into the Go binary
// so `c8s install` is a single-file install tool — no side chart download.
//
// The chart lives under c8s/ in this package. Develop it with the
// `helm` CLI directly (helm lint internal/helmchart/c8s,
// helm template test internal/helmchart/c8s).
//
// Build tag: dropped from `-tags c8s_node` builds along with the
// `c8s install` subcommand that consumes it.
package helmchart

import (
	"embed"
	"strings"
)

// ChartFS contains the full chart tree including dotfiles and underscored
// template partials (_helpers.tpl).
//
//go:embed all:c8s
var ChartFS embed.FS

// ChartRoot is the path prefix inside ChartFS that a helm action expects as
// a chart directory.
const ChartRoot = "c8s"

// HostSweepScript is the uninstall host sweep script, normalized the way the
// chart's argv pin renders it (trailing newlines collapsed to one).
func HostSweepScript() string {
	b, err := ChartFS.ReadFile(ChartRoot + "/files/scripts/host-sweep.sh")
	if err != nil {
		panic(err)
	}
	return strings.TrimRight(string(b), "\n") + "\n"
}
