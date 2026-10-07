package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func newExplainCmd(o *options) *cobra.Command {
	var (
		sandboxID string
		asJSON    bool
	)
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show why a sandbox does or does not receive its secrets",
		Long: `Report the release decision for one sandbox: what its node's inventory says it
is running, which of those containers c8s injected and drops, what is left to
match, how each workload entry measures against that, and the grant that
resolves.

A refused release tells the pod only that it was refused, and the input that
decides it — the container set — is visible only to CDS, so this is where a
wedged pod is diagnosed.

The sandbox ID is on the pod's certificate; 'c8s verify' prints it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			if err := armtls.ValidateSandboxID(sandboxID); err != nil {
				return fmt.Errorf("--sandbox: %w", err)
			}
			signer, err := o.Signer()
			if err != nil {
				return err
			}
			c, err := o.client(cmd.Context())
			if err != nil {
				return err
			}
			resp, err := c.explain(cmd.Context(), sandboxID, signer)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(resp)
			}
			printExplain(cmd.OutOrStdout(), resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&sandboxID, "sandbox", "", "sandbox ID to explain (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the raw report")
	_ = cmd.MarkFlagRequired("sandbox")
	return cmd
}

// printExplain lays the report out in the order CDS decides, so the first thing
// that goes wrong is the first thing read.
func printExplain(w io.Writer, r intsecrets.ExplainResponse) {
	fmt.Fprintf(w, "sandbox    %s\n", r.SandboxID)
	if r.InventoryHost != "" {
		fmt.Fprintf(w, "inventory  %s\n", r.InventoryHost)
	}

	if len(r.Reported) > 0 {
		injected := 0
		for _, c := range r.Reported {
			if c.Injected {
				injected++
			}
		}
		fmt.Fprintf(w, "reported   %d container(s)\n", len(r.Reported))
		fmt.Fprintf(w, "dropped    %d injected by c8s\n", injected)
		fmt.Fprintf(w, "candidates %d\n", len(r.Candidates))
		for _, c := range r.Reported {
			mark := " "
			if c.Injected {
				mark = "-"
			}
			fmt.Fprintf(w, "  %s %s  %s\n", mark, c.Digest, shellArgv(c.Argv))
		}
	}

	for _, e := range r.Entries {
		fmt.Fprintln(w)
		switch {
		case e.Matches && e.HasGrant:
			fmt.Fprintf(w, "%s  MATCH\n", e.Name)
		case e.Matches:
			fmt.Fprintf(w, "%s  MATCH (no secret grant)\n", e.Name)
		default:
			fmt.Fprintf(w, "%s  NEAR MISS\n", e.Name)
		}
		for _, f := range e.Foreign {
			fmt.Fprintf(w, "  foreign  %s  %s\n", f.Digest, shellArgv(f.Argv))
			fmt.Fprintf(w, "           no container in this entry declares it\n")
		}
		for _, m := range e.MissingMains {
			label := m.Digest
			if m.Image != "" {
				label = fmt.Sprintf("%s (%s)", m.Digest, m.Image)
			}
			fmt.Fprintf(w, "  missing  %s\n", label)
			fmt.Fprintf(w, "           declared as a main container, nothing running satisfies it\n")
		}
	}

	fmt.Fprintln(w)
	if r.Grant != nil {
		fmt.Fprintf(w, "released via %q\n", r.Match)
		if len(r.Grant.Read) > 0 {
			fmt.Fprintf(w, "  read   %s\n", strings.Join(r.Grant.Read, " "))
		}
		if len(r.Grant.Write) > 0 {
			fmt.Fprintf(w, "  write  %s\n", strings.Join(r.Grant.Write, " "))
		}
		return
	}
	fmt.Fprintf(w, "nothing is released: %s\n", r.Refusal)
}

// shellArgv renders an argv for reading. Empty is explicit, since a container
// with no reported argv is never dropped as injected and that is worth seeing.
func shellArgv(argv []string) string {
	if len(argv) == 0 {
		return "(no argv reported)"
	}
	return "[" + strings.Join(argv, " ") + "]"
}
