//go:build linux

package armtlsmesh

import (
	"context"
	"os/signal"
	"syscall"
)

// Run dispatches armtls-mesh CLI args via cobra. Signal handling is wired
// here, so RunE reads cmd.Context() instead of reinstalling its own
// NotifyContext.
func Run(args []string) error {
	cmd := newArmtlsMeshCommand()
	cmd.SetArgs(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return cmd.ExecuteContext(ctx)
}
