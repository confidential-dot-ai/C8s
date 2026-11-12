// Command get-cert is a thin wrapper around the `c8s get-cert` cobra
// subcommand for `go build ./cmd/get-cert` users and the historical image
// entrypoint.
package main

import (
	"os"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
)

func main() {
	ctx, stop := cmdsutil.SignalContext()
	defer stop()
	if err := getcert.NewCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
