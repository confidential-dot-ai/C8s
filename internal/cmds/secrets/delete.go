package secrets

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taha"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

func newDeleteCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete the secret at a path of a Trust Authority replica set",
		Long: `Delete the operator secret at <path> with a secret entry: no replica of the
set releases it after the entry. A single Trust Authority deletes nothing; a restart
clears its store.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			path, err := pkgallowlist.CanonicalSecretPath(args[0])
			if err != nil {
				return err
			}
			handled, err := taha.WriteSecret(cmd.Context(), &o.Options, path, nil, false)
			if err == nil && !handled {
				err = errors.New("the Trust Authority is not a replica set: a single Trust Authority deletes no secret")
			}
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", path)
			}
			return err
		},
	}
}
