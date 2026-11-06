// Package keys implements the `c8s keys` command group: operator EC keys.
// The private half signs allowlist, secrets, and volume writes (and
// get-kubeconfig); the public half is what CDS pins at install
// (c8s install --operator-keys).
package keys

import "github.com/spf13/cobra"

// NewCmd returns the `c8s keys` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage operator keys",
		Long: `Manage the operator EC keypair that authorizes platform writes. The private
key signs allowlist, secrets, and volume writes (and get-kubeconfig); the
public key is what CDS pins at install (c8s install --operator-keys).`,
	}
	cmd.AddCommand(newKeygenCmd())
	return cmd
}
