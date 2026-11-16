//go:build linux

package armtlsmesh

import "context"

// Run dispatches armtls-mesh CLI args via cobra under ctx.
func Run(ctx context.Context, args []string) error {
	cmd := newArmtlsMeshCommand()
	cmd.SetArgs(args)
	return cmd.ExecuteContext(ctx)
}
