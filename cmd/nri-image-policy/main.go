// Command nri-image-policy is a thin wrapper around the
// `c8s nri-image-policy` cobra subcommand.
package main

import (
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	nriimagepolicy "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/nri-image-policy"
)

func main() { cmdsutil.RunMain(nriimagepolicy.Run) }
