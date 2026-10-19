// Package secrets implements the `c8s secrets` operator CLI for the CDS secret
// store.
//
// Writes are authorized by an operator EC private key whose public key CDS pins
// (cds --operator-keys) — the same credential that signs an allowlist mutation,
// and the same key the `secrets` grants in that allowlist are rooted in. The
// private key never leaves the CLI: it signs a short-lived token bound to the
// method, path, and body of one request.
package secrets

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// options holds the flags shared by every subcommand.
type options struct {
	cdsconn.Options
}

// NewCmd returns the `c8s secrets` command tree.
func NewCmd() *cobra.Command {
	return newCmd(nil)
}

// newCmd is the injectable constructor behind NewCmd.
func newCmd(verifier cdsconn.PinVerifier) *cobra.Command {
	o := &options{Options: cdsconn.Options{Verifier: verifier, DirectCDS: true}}
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage the CDS secret store",
		Long: `Put operator-supplied values into the CDS secret store — an API token, a
database password, a wrapped key: anything CDS cannot generate for itself.

A value is released to a pod when the images running in that pod's sandbox match
an allowlist entry whose 'secrets' grant covers the path. Write the grant with
'c8s allowlist apply'; this command supplies the value.

Writes are signed with an operator EC private key you supply via --operator-key
(or C8S_OPERATOR_KEY), whose public half CDS pins separately via
'c8s install --operator-keys'.

Values live in the CDS process and nowhere else, so a CDS restart clears the
store and every workload holding a secret has to be rolled (see
docs/secrets.md).`,
		SilenceUsage: true,
	}

	cdsconn.BindFlags(cmd.PersistentFlags(), &o.Options)
	cmd.AddCommand(newPutCmd(o), newExplainCmd(o))
	return cmd
}

// client builds the secrets API client over the attested channel to CDS.
func (o *options) client(ctx context.Context) (client, error) {
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return client{}, err
	}
	return client{baseURL: strings.TrimRight(o.URL, "/"), http: hc}, nil
}
