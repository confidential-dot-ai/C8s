package taha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/fileutil"
)

func newPreparePolicyCmd(o *options) *cobra.Command {
	var cluster, expected, file, digest, output string
	cmd := &cobra.Command{
		Use:   "prepare-policy",
		Short: "Sign a reviewed policy entry into a new file without submitting it",
		Long: `Check --cluster, --genesis and --expect-head against the attested policy
log and the local acknowledged-head floor. Require --file to contain canonical
allowlist bytes matching --policy-sha256, then sign the next policy entry with
--operator-key and write its native body and signature to a new --out file.

--image-policy-file is required; --insecure is refused. The supplied genesis
remains binding even with an existing local record. Signing authorizes the
entry at this position, but does not commit it or reserve the position.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := o.policyTarget("prepare-policy", cluster, expected)
			if err != nil {
				return err
			}
			policy, err := readPreparedPolicy(file, digest)
			if err != nil {
				return err
			}
			if err := newOutput(output); err != nil {
				return err
			}
			w, err := o.writer(cmd.Context())
			if err != nil {
				return err
			}
			return w.preparePolicy(cmd.Context(), cmd.OutOrStdout(), target, policy, output)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cluster, "cluster", "", "the intended cluster ID")
	f.StringVar(&expected, "expect-head", "", "the required predecessor as <seq>:<hash>")
	f.StringVar(&file, "file", "", "the reviewed canonical allowlist file (no trailing newline)")
	f.StringVar(&digest, "policy-sha256", "", "SHA-256 of the exact policy file, as 64 lowercase hex characters")
	f.StringVar(&output, "out", "", "new output file for the native signed entry; must not exist")
	cmdsutil.RequireFlags(cmd, "cluster", "expect-head", "file", "policy-sha256", "out")
	return cmd
}

// policyTarget is the independently trusted position the flags name.
func (o *options) policyTarget(command, cluster, expected string) (policyTarget, error) {
	if o.Insecure {
		return policyTarget{}, fmt.Errorf("%s requires attested HTTPS; --insecure is not allowed", command)
	}
	if o.MeasurementsConfig == "" {
		return policyTarget{}, fmt.Errorf("%s requires independent Trust Authority pins: pass --image-policy-file", command)
	}
	if strings.TrimSpace(cluster) == "" {
		return policyTarget{}, errors.New("--cluster must not be empty")
	}
	genesis, err := o.pinnedGenesis()
	if err != nil {
		return policyTarget{}, err
	}
	if genesis == nil {
		return policyTarget{}, errors.New("--genesis is required")
	}
	head, err := cdschain.ParsePin(expected)
	if err != nil {
		return policyTarget{}, fmt.Errorf("--expect-head: %w", err)
	}
	return policyTarget{
		cluster: cluster,
		genesis: *genesis,
		head:    head,
	}, nil
}

// newOutput refuses an --out that cannot be created, before anything is
// read from Trust Authority, recorded or signed.
func newOutput(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("--out: %s exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--out: %w", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return fmt.Errorf("--out: %w", err)
	}
	return nil
}

func (w *writer) preparePolicy(ctx context.Context, out io.Writer, target policyTarget, policy []byte, path string) error {
	state, err := w.verifiedTarget(ctx, &target)
	if err != nil {
		return err
	}
	e, err := w.sign(state, cdschain.TypePolicy, cdschain.Policy{Allowlist: policy})
	if err != nil {
		return err
	}
	encoded, err := e.Encode()
	if err != nil {
		return err
	}
	if len(encoded) > cdschain.MaxEntryBytes {
		return fmt.Errorf("prepared entry exceeds %d bytes", cdschain.MaxEntryBytes)
	}
	// The entry is signed once: it must be on disk before success is printed.
	if err := fileutil.WriteNewDurable(path, encoded, 0o600); err != nil {
		return fmt.Errorf("--out: %w", err)
	}
	_, err = fmt.Fprintf(out, "prepared head %d (%s) after %d (%s) in %s; not submitted\n", state.Head.Seq+1, e.Hash(), state.Head.Seq, state.Head.Hash, path)
	return err
}
