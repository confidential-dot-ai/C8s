package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
)

func newShowCmd(o *options) *cobra.Command {
	var (
		output string
		raw    bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the stored route manifest, its revision and digest",
		Long: `Fetch the signed route manifest from CDS and print its revision, notBefore,
maxAgeSeconds, route digest (SHA-256 of the manifest bytes, the value a client
pins) and routes. --raw prints the manifest bytes, ready to edit and 'put'.
-o json prints the envelope CDS serves.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("--output must be text or json, got %q", output)
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			env, m, verified, err := o.fetch(ctx(cmd), c)
			if errors.Is(err, routesclient.ErrNotFound) {
				return fmt.Errorf("%w; write one with 'c8s routes put' or 'c8s routes add'", err)
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch {
			case raw:
				_, err = out.Write(env.Manifest)
				return err
			case output == "json":
				b, err := json.Marshal(env)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(out, "%s\n", b)
				return err
			}
			return printManifest(out, env.Manifest, m, verified)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	cmd.Flags().BoolVar(&raw, "raw", false, "print the manifest bytes only")
	return cmd
}

func printManifest(out io.Writer, manifest []byte, m *pkgroutes.Manifest, verified bool) error {
	signature := "not verified (pass --operator-keys)"
	if verified {
		signature = "verified against --operator-keys"
	}
	fmt.Fprintf(out, "revision:      %d\n", m.Revision)
	fmt.Fprintf(out, "notBefore:     %s\n", m.NotBefore.Format(time.RFC3339Nano))
	fmt.Fprintf(out, "maxAgeSeconds: %d\n", int64(m.MaxAge/time.Second))
	fmt.Fprintf(out, "digest:        %s\n", digestHex(manifest))
	fmt.Fprintf(out, "signature:     %s\n", signature)
	if len(m.Hosts) == 0 {
		_, err := fmt.Fprintln(out, "\nno hosts in the stored manifest")
		return err
	}
	fmt.Fprintln(out)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPATH\tMATCH\tADDRESS\tBACKEND")
	for _, host := range slices.Sorted(maps.Keys(m.Hosts)) {
		for _, r := range m.Hosts[host].Routes {
			backend := "workload " + r.Backend.Workload
			if r.Backend.Workload == "" {
				backend = "server name " + r.Backend.ServerName
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", host, r.Path, r.Match, r.Backend.Address, backend)
		}
	}
	return tw.Flush()
}

func newDigestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "digest <file>",
		Short: "Print the route digest of a manifest file",
		Long: `Validate a manifest file and print its route digest: the hex SHA-256 of its
exact bytes, the value a client pins.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, _, err := readManifest(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), digestHex(manifest))
			return err
		},
	}
}

func readManifest(path string) ([]byte, *pkgroutes.Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, err := pkgroutes.Parse(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, m, nil
}
