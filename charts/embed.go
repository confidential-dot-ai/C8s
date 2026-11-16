// Package charts embeds the C8s Helm charts into the Go binary.
package charts

import "embed"

// FS contains the full chart trees including dotfiles and underscored template
// partials (_helpers.tpl). The charts/ dependency links are symlinks that
// embedding skips; helmchart.Extract recreates them.
//
//go:embed all:cloud all:control-plane all:lib all:worker
var FS embed.FS
