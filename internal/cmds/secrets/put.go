package secrets

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taconn"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taha"
	intsecrets "github.com/confidential-dot-ai/confidential-kubernetes/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

func newPutCmd(o *options) *cobra.Command {
	var (
		fromFile  string
		overwrite bool
		dryRun    bool
		gate      = taconn.MeshCAGate{
			What:      "secret",
			ForceNote: "Unrelated to --overwrite, which governs replacing an existing value",
		}
	)
	cmd := &cobra.Command{
		Use:   "put <path>",
		Short: "Store an operator-supplied value at a secret path",
		Long: `Store a value at <path> in the Trust Authority secret store, reading it from stdin or from
--from-file. The bytes are stored exactly as read, including any trailing
newline; the byte count is printed so you can confirm which bytes were sent.

A path that already holds a value needs --overwrite, and the value it holds is
named before it is replaced.

The write names the Trust Authority it trusts with --mesh-ca: the mesh CA Trust Authority serves must be
one you pinned, or the secret is refused. --force writes without that check.

A workload reads its secret into a file once, at startup. Replacing a value
reaches a running pod when that pod next restarts.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			path, err := pkgallowlist.CanonicalSecretPath(args[0])
			if err != nil {
				return err
			}
			value, err := readValue(cmd, fromFile)
			if err != nil {
				return err
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would write %d bytes to %s\n", len(value), path)
				return nil
			}

			c, err := o.client(cmd.Context())
			if err != nil {
				return err
			}
			if err := gate.Check(cmd.Context(), cmd.ErrOrStderr(), c.http, o.URL); err != nil {
				return err
			}

			signer, err := o.Signer()
			if err != nil {
				return err
			}

			// Ask to create first, whatever --overwrite says. A path that already
			// holds a value comes back refused with what is there, so the line
			// naming what a replacement destroys is printed before it happens —
			// the store has no versioning and no delete.
			res, err := c.put(cmd.Context(), path, value, false, signer)
			if err != nil {
				return err
			}
			if res.Sealed != "" {
				return putEntry(cmd, o, path, res.Sealed, overwrite, len(value))
			}
			if res.Created {
				fmt.Fprintf(cmd.OutOrStdout(), "+ %s (new)\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", len(value), path)
				return nil
			}
			if !overwrite {
				return fmt.Errorf("%s already holds %s; re-run with --overwrite to replace it", path, describe(res.Existing))
			}

			fmt.Fprintf(cmd.OutOrStdout(), "~ %s (replaces %s)\n", path, describe(res.Existing))
			res, err = c.put(cmd.Context(), path, value, true, signer)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", len(value), path)
			if res.Existing == intsecrets.OriginWorkload {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"note: pods already holding the workload-generated value keep it until they restart\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace a value already at the path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the intended change without calling Trust Authority")
	gate.BindFlags(cmd.Flags())
	return cmd
}

// putEntry names a value a replica set sealed in a secret entry: only then
// do replicas release it.
func putEntry(cmd *cobra.Command, o *options, path, sealed string, overwrite bool, n int) error {
	h, err := cdschain.ParseHash(sealed)
	if err != nil {
		return fmt.Errorf("the replica answered no sealed value: %w", err)
	}
	if _, err := taha.WriteSecret(cmd.Context(), &o.Options, path, &h, overwrite); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", n, path)
	return nil
}

// describe names a stored value by what put it there, for the line an operator
// reads before replacing it.
func describe(o intsecrets.Origin) string {
	switch o {
	case intsecrets.OriginWorkload:
		return "a workload-generated value"
	case intsecrets.OriginOperator:
		return "an operator-supplied value"
	default:
		return "a value"
	}
}

// readValue reads the secret from a file or stdin. The bytes are passed through
// unmodified: a PEM key ends in a newline and a token usually must not, so
// neither can be trimmed on the CLI's guess.
func readValue(cmd *cobra.Command, fromFile string) ([]byte, error) {
	var (
		value []byte
		err   error
	)
	if fromFile != "" {
		value, err = os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read --from-file: %w", err)
		}
	} else {
		value, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read value from stdin: %w", err)
		}
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("value is empty: supply it on stdin or with --from-file")
	}
	return value, nil
}
