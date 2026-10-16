package allowlist

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/deployment"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func newAddCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "add <digest> <image>",
		Short: "Add an entry admitting an image under any command line",
		Long: `Write the entry "<image basename>-<first 12 hex of digest>": one container at
<digest> whose command and args policy are both "any". The chart's seed takes an
entry of that name in place of the one it generates for the digest. To pin a command line or grant secrets, write the entry
with 'apply' or 'derive' instead.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			digest, err := types.ParseDigest(args[0])
			if err != nil {
				return err
			}
			image, err := requireLabel(args[1], "image")
			if err != nil {
				return err
			}
			name := pkgallowlist.DigestEntryName(digest, image)
			entry := pkgallowlist.DigestEntry(digest, image)

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would add %s (%s)\n", name, digest)
				return nil
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			findings := collisionsWithLive(map[string]pkgallowlist.Workload{name: entry}, live)
			for _, f := range findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
			}
			if errs := countErrors(findings); errs > 0 {
				return fmt.Errorf("refusing to add: %d lint error(s)", errs)
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.PutWorkload(ctx(cmd), name, entry, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the intended entry without calling CDS")
	return cmd
}

func newUploadCmd(o *options) *cobra.Command {
	var (
		dryRun   bool
		force    bool
		strict   bool
		required []string
		cvmMode  string
	)
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Replace the entire allowlist with the contents of a file",
		Long: `Atomically replace the entire allowlist with the contents of <file> (the
canonical JSON 'export' writes). CDS assigns the new version.

If any required core c8s component is missing from the file's image labels (` + fmt.Sprintf("%v", defaultRequiredComponents) + `),
upload refuses unless --force, since a cluster missing them cannot pull its own
control plane. --cvm-mode bare-metal omits attestation-api from this set because
the measured node image supplies it. A baked node image also serves no
nri-image-policy entry, since its base allowlist admits the plugin, so an
allowlist exported from one re-uploads only with --force. With gke, aks, or no
mode, the full set is required. Override the required set with --require. The file is lint-checked
before upload; --strict makes lint warnings fatal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			reqComponents, err := requiredComponentsForMode(cvmMode)
			if err != nil {
				return err
			}
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}

			findings := lintOffline(desired)
			for _, f := range findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
			}
			// An error means the document cannot do what it says, so --force
			// does not reach it: that flag is about missing components.
			if errs := countErrors(findings); errs > 0 {
				return fmt.Errorf("refusing to upload: %d lint error(s)", errs)
			}
			if strict && len(findings) > 0 {
				return fmt.Errorf("refusing to upload: %d lint warning(s) with --strict", len(findings))
			}

			if len(required) > 0 {
				// An empty needle matches every ref and would silently disable the
				// guard; reject it (and a bare wildcard) outright.
				for _, r := range required {
					if _, err := requireLabel(r, "--require value"); err != nil {
						return err
					}
				}
				reqComponents = required
			}
			if missing := missingComponents(uploadImageLabels(desired), reqComponents); len(missing) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: uploaded allowlist is missing core c8s component(s): %v\n", missing)
				if !force {
					hint := "re-run with --force if this is intentional"
					if cvmMode == "bare-metal" && slices.Contains(missing, "nri-image-policy") {
						hint = "a baked node image serves no nri-image-policy entry (the plugin is admitted from its measured base allowlist), so re-run with --force when uploading to a baked node; otherwise the installer could no longer start"
					}
					return fmt.Errorf("refusing to upload an allowlist missing core components %v; %s", missing, hint)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "proceeding anyway (--force)")
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}

			// Show the operator what will change before writing.
			if live, _, err := c.List(ctx(cmd)); err == nil {
				_ = printDiff(cmd.OutOrStdout(), o.output, diffAllowlists(live, desired))
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch current allowlist for diff: %v\n", err)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would replace allowlist with %d workload(s)\n", len(desired.Workloads))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.ReplaceAll(ctx(cmd), desired, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "uploaded %d workload(s)\n", len(desired.Workloads))
			return nil
		},
	}
	cmd.Flags().StringVar(&cvmMode, "cvm-mode", "", "deployment mode: bare-metal, gke, or aks (bare-metal uses the measured host attestation service; omitted requires all core components)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without replacing the allowlist")
	cmd.Flags().BoolVar(&force, "force", false, "upload even if core c8s components are missing")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat lint warnings as fatal")
	cmd.Flags().StringSliceVar(&required, "require", nil, "component identifiers that must appear in the uploaded image refs (overrides the default set)")
	return cmd
}

func requiredComponentsForMode(mode string) ([]string, error) {
	if mode == "" {
		return slices.Clone(defaultRequiredComponents), nil
	}
	baked, err := deployment.BakedAttestationAndNRIPlugin(mode)
	if err != nil {
		return nil, err
	}
	if baked {
		return slices.DeleteFunc(slices.Clone(defaultRequiredComponents), func(component string) bool {
			return component == "attestation-api"
		}), nil
	}
	return slices.Clone(defaultRequiredComponents), nil
}

// requireLabel rejects an empty or bare-wildcard label. Image and name labels
// are informational, but "" or "*" almost always signals a mistake and a
// wildcard must never be mistaken for a policy value.
func requireLabel(val, what string) (string, error) {
	switch val {
	case "":
		return "", fmt.Errorf("%s must not be empty", what)
	case "*":
		return "", fmt.Errorf("%s must not be a bare wildcard %q", what, val)
	}
	return val, nil
}
