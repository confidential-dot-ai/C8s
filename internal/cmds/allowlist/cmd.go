// Package allowlist implements the `c8s allowlist` operator CLI for reading and
// mutating the CDS-served image allowlist that nri-image-policy enforces on
// every node: named workload entries, each pinning an init/main container set
// with per-container argv and path policy, looked up by container digest.
//
// Reads (list, get, export, diff, lint, inspect-image) are unauthenticated.
// Writes (add, apply, edit, delete, upload) are authorized by an operator EC
// private key whose public key CDS pins (cds --operator-keys); the CLI mints a
// short-lived, body-bound token per write via pkg/operatorauth.
package allowlist

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Required image-label substrings for deployments with a chart-managed attestation API.
var defaultRequiredComponents = []string{
	"cds",
	"armtls-mesh",
	"nri-image-policy",
	"attestation-api",
	"c8s-router",
}

// options holds the flags shared by every subcommand.
type options struct {
	cdsconn.Options

	output string // "text" | "json"
}

// NewCmd returns the `c8s allowlist` command tree.
func NewCmd() *cobra.Command {
	return newCmd(nil)
}

// newCmd is the injectable constructor behind NewCmd.
func newCmd(verifier cdsconn.PinVerifier) *cobra.Command {
	o := &options{Options: cdsconn.Options{Verifier: verifier}}
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage the CDS image allowlist",
		Long: `Read and mutate the image allowlist that CDS serves and nri-image-policy
enforces on every node: named workload entries, each pinning an init/main
container set with per-container argv and path policy. An image that may run
with any command line is an entry whose command and args policy are both "any";
'add' writes one.

Reads (list, get, export, diff, lint, inspect-image) are unauthenticated. Writes
(add, apply, edit, delete, upload) are signed with an operator EC private key
you supply to THIS CLI via --operator-key
(or C8S_OPERATOR_KEY). The private key never leaves the CLI — it signs a
short-lived token that CDS verifies against the operator public keys it was
configured to pin separately (cds --operator-keys, set by 'c8s install
--operator-keys').

The default chart publishes /allowlist through router. Point --url at that
front door only when it uses CDS-issued public TLS (discovery reports
public_tls.mode=cds), and use the router launch digest with --measurements. A
WebPKI front door cannot yet bind its public certificate to the attestation
evidence, so this CLI refuses it; use a direct CDS armTLS URL instead (for
example through a port-forward) and pin the CDS launch digest. To generate an
operator key and pin its public half, see the c8s README ("Managing the image
allowlist").`,
		SilenceUsage: true,
	}

	pf := cmd.PersistentFlags()
	cdsconn.BindFlags(pf, &o.Options)
	pf.StringVarP(&o.output, "output", "o", "text", "output format: text or json")

	cmd.AddCommand(
		newListCmd(o),
		newGetCmd(o),
		newExportCmd(o),
		newDiffCmd(o),
		newAddCmd(o),
		newApplyCmd(o),
		newDeriveCmd(o),
		newEditCmd(o),
		newDeleteCmd(o),
		newUploadCmd(o),
		newLintCmd(o),
		newInspectImageCmd(o),
	)
	return cmd
}

// validate checks the flags every subcommand needs.
func (o *options) validate() error {
	if err := o.Validate(); err != nil {
		return err
	}
	if o.output != "text" && o.output != "json" {
		return fmt.Errorf("--output must be text or json, got %q", o.output)
	}
	return nil
}

// client builds the allowlist API client over the attested channel to CDS.
func (o *options) client(ctx context.Context) (allowlistclient.Client, error) {
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return allowlistclient.Client{}, err
	}
	return allowlistclient.NewClientWithHTTP(o.URL, hc), nil
}

// signer builds the operator credential. Required only for write subcommands.
func (o *options) signer() (*operatorauth.Signer, error) { return o.Signer() }

// uploadImageLabels gathers every image label an allowlist carries — workload
// labels and workload container images — the surface the upload component
// guard scans. Keys are synthetic; only the values matter.
func uploadImageLabels(al *pkgallowlist.Allowlist) map[string]string {
	labels := map[string]string{}
	n := 0
	add := func(s string) {
		if s != "" {
			labels[strconv.Itoa(n)] = s
			n++
		}
	}
	for _, w := range al.Workloads {
		add(w.Label)
		for _, c := range w.InitContainers {
			add(c.Image)
		}
		for _, c := range w.Containers {
			add(c.Image)
		}
	}
	return labels
}

// missingComponents returns the required component identifiers not present as a
// (case-insensitive) substring of any image reference in images.
func missingComponents(images map[string]string, required []string) []string {
	var missing []string
	for _, comp := range required {
		needle := strings.ToLower(comp)
		found := false
		for _, image := range images {
			if strings.Contains(strings.ToLower(image), needle) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, comp)
		}
	}
	return missing
}

// ctx returns the command context or a background context as a fallback.
func ctx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
