package cdsha

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

func newSubmitPolicyCmd(o *options) *cobra.Command {
	var cluster, expected, file string
	cmd := &cobra.Command{
		Use:   "submit-policy",
		Short: "Submit a prepared signed policy entry without an operator key",
		Long: `Submit the exact native signed entry in --file after verifying the attested
policy log against independently trusted --cluster, --genesis and --expect-head.
--expect-head names the artifact's predecessor, even when retrying a held entry
after newer entries or operator-key rotation.

--image-policy-file is required; --insecure is refused. No operator key is loaded.
Only an exact HTTP 200 confirmation and a durable local record report success.
Keep the artifact unchanged after an uncertain result and retry this command;
it never re-signs, rebases, or automatically retries the entry.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := o.policyTarget("submit-policy", cluster, expected)
			if err != nil {
				return err
			}
			encoded, entry, err := readSubmittedPolicy(file, target)
			if err != nil {
				return err
			}
			w, err := o.connection(cmd.Context())
			if err != nil {
				return err
			}
			return w.submitPolicy(cmd.Context(), target, encoded, entry)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cluster, "cluster", "", "the independently trusted cluster ID")
	f.StringVar(&expected, "expect-head", "", "the independently trusted predecessor as <seq>:<hash>")
	f.StringVar(&file, "file", "", "the native signed policy entry from prepare-policy, retained unchanged")
	cmdsutil.RequireFlags(cmd, "cluster", "expect-head", "file")
	return cmd
}

func (w *writer) submitPolicy(ctx context.Context, target policyTarget, encoded []byte, entry cdschain.Entry) error {
	if err := w.o.prepareStateDir(); err != nil {
		return err
	}
	history, err := w.readPolicy(ctx, target, entry)
	if err != nil {
		return err
	}
	// Holding an entry does not establish confirmation; every retry must POST it.
	_, err = submitEncoded(ctx, w.client, w.url, encoded, history.entry)
	if err == nil {
		err = w.o.complete(target.genesis, history.entry)
	}
	if cmdsutil.ExitStatus(err) == cmdsutil.ExitNotConfirmed {
		// The shared advice assumes a next write; this command's is itself.
		return fmt.Errorf("%w; for submit-policy, keep --file unchanged and run the same command again: a rerun confirms the entry and records its head", err)
	}
	return err
}
