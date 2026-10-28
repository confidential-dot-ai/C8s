package allowlist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/deployment"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
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
canonical JSON 'export' writes). CDS assigns the new version. The replace is
conditional on the version upload read for its diff: if another write landed
since, CDS refuses it and nothing changes; run upload again to see the new diff.

If any required core c8s component is missing from the file's image labels (` + fmt.Sprintf("%v", defaultRequiredComponents) + `),
upload refuses unless --force, since a cluster missing them cannot pull its own
control plane. --cvm-mode bare-metal omits attestation-api and nri-image-policy
from this set because the measured node image supplies them. With gke, aks, or
no mode, the full set is required. Override the required set with --require. The file is lint-checked
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
					return fmt.Errorf("refusing to upload an allowlist missing core components %v; re-run with --force if this is intentional", missing)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "proceeding anyway (--force)")
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}

			// Show the operator what will change before writing. The write is
			// conditional on the version this diff was made against.
			live, version, err := c.List(ctx(cmd))
			if err == nil {
				_ = printDiff(cmd.OutOrStdout(), o.output, diffAllowlists(live, desired))
			} else if dryRun {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch current allowlist for diff: %v\n", err)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would replace allowlist with %d workload(s)\n", len(desired.Workloads))
				return nil
			}
			if err != nil {
				return fmt.Errorf("read the allowlist the upload replaces: %w", err)
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := replaceIfUnchanged(ctx(cmd), c, desired, version, signer); err != nil {
				if errors.Is(err, errAllowlistChanged) {
					return fmt.Errorf("nothing was uploaded: %w", err)
				}
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

// errAllowlistChanged is a whole-document write that did not land because
// another write landed after the read the document was built from.
var errAllowlistChanged = errors.New("the allowlist changed since it was read; run the command again to re-read it and see the new diff")

// unconfirmedError is a whole-document write no answer confirmed or refused
// (a 5xx, or no answer at all) while CDS still serves the version it was
// conditional on: it has not landed, and it still can until another write
// lands.
type unconfirmedError struct {
	cause   error
	version string
}

func (e *unconfirmedError) Error() string {
	return fmt.Sprintf("the write was not confirmed (%v): CDS still serves version %s without it, and the write "+
		"was conditional on that version, so it lands only if no other write lands first; run the command "+
		"again: the new write is conditional on the version it reads too, so the document is written at most once", e.cause, e.version)
}

func (e *unconfirmedError) Unwrap() error { return e.cause }

// replaceIfUnchanged writes doc in place of the allowlist at version, the
// version of the read doc was built from, so it never overwrites a write made
// since. CDS commits the document and its operator signature in one write.
//
// When the answer does not settle whether the write landed (a 412, which may
// refuse a resend of a write CDS committed but answered 503 for; a 5xx; no
// answer), it reads the allowlist back and reports what happened: nil if doc
// landed, errAllowlistChanged if another write landed instead, an
// *unconfirmedError if nothing landed yet. A refusal (any other 4xx) or an
// error before sending is returned as is: nothing was written.
func replaceIfUnchanged(ctx context.Context, c allowlistclient.Client, doc *pkgallowlist.Allowlist, version string, signer allowlistclient.Authorizer) error {
	if version == "" {
		// Without a version the write would be unconditional.
		return errors.New("CDS served the allowlist without a version (ETag W/\"N\"), so the write cannot be made conditional on it")
	}
	err := c.ReplaceAll(ctx, doc, version, signer)
	if err == nil {
		return nil
	}
	var se *operatorauth.StatusError
	var ue *url.Error
	refused := errors.As(err, &se) && se.Status < 500 && se.Status != http.StatusPreconditionFailed
	if refused || (se == nil && !errors.As(err, &ue)) {
		return err
	}
	landed, served, rerr := writeLanded(ctx, c, doc, version)
	switch {
	case rerr != nil:
		return fmt.Errorf("the write was not confirmed (%w), and reading the allowlist back to see whether it landed failed: %v; "+
			"check with 'c8s allowlist list' before running the command again", err, rerr)
	case landed:
		return nil
	case served != version || (se != nil && se.Status == http.StatusPreconditionFailed):
		return errAllowlistChanged
	default:
		return &unconfirmedError{cause: err, version: version}
	}
}

// writeLanded reports whether a whole-document write of doc conditional on
// version landed, and the version CDS serves now. It landed if CDS serves doc
// now, or if its history holds doc at the version right after version: the
// one write conditional on version produced it.
func writeLanded(ctx context.Context, c allowlistclient.Client, doc *pkgallowlist.Allowlist, version string) (bool, string, error) {
	want, err := doc.Canonical()
	if err != nil {
		return false, "", err
	}
	got, served, err := c.CanonicalBytes(ctx)
	if err != nil {
		return false, "", err
	}
	if bytes.Equal(want, got) {
		return true, served, nil
	}
	if served == version {
		return false, served, nil
	}
	n, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return false, "", fmt.Errorf("version %q is not a counter: %w", version, err)
	}
	history, err := c.History(ctx)
	if err != nil {
		return false, "", err
	}
	sum := sha256.Sum256(want)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	next := strconv.FormatUint(n+1, 10)
	for _, e := range history {
		if e.Version == next && e.Digest == digest {
			return true, served, nil
		}
	}
	return false, served, nil
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
			return component == "attestation-api" || component == "nri-image-policy"
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
