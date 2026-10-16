package volume

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// options holds the flags every subcommand shares.
type options struct {
	cdsconn.Options
}

// NewCmd returns the `c8s volume` command tree.
func NewCmd() *cobra.Command {
	return newCmd(nil)
}

func newCmd(verifier cdsconn.PinVerifier) *cobra.Command {
	o := &options{Options: cdsconn.Options{Verifier: verifier, DirectCDS: true}}
	cmd := &cobra.Command{
		Use:   "volume",
		Short: "Build encrypted volumes and store their keys in CDS",
		Long: `Build a volume that only an attested workload can open.

'create' packages a directory into an encrypted, integrity-protected image and
puts its key into the CDS secret store — or, with --mutable, builds a writable
volume the workload can both read and write, without integrity protection. The
image is ciphertext either way: copy it to the node by any means, including
through the untrusted host.

'attach' then presents that image to the node as a disk carrying the serial the
volume is found by, and 'detach' removes it. Both run on the node, as root, and
are only needed where the hypervisor cannot hand you a disk with a serial of
your choosing.

The key is released to a pod when the images running in that pod's sandbox match
an allowlist entry whose 'secrets' grant covers the key's path. 'create' prints
the grant and the pod annotations to apply; it does not modify any workload.

Writes are signed with an operator EC private key you supply via --operator-key
(or C8S_OPERATOR_KEY), whose public half CDS pins via 'c8s install
--operator-keys'.

Keys live in the CDS process and nowhere else, so a CDS restart makes every
volume in the cluster unopenable until its key is written again. Keep the escrow
file 'create' writes.`,
		SilenceUsage: true,
	}
	cdsconn.BindFlags(cmd.PersistentFlags(), &o.Options)
	cmd.AddCommand(newCreateCmd(o))
	// attach/detach run on the node and never speak to CDS; they inherit the
	// connection flags without requiring them.
	cmd.AddCommand(newAttachCmd(Attacher{}), newDetachCmd(Attacher{}))
	return cmd
}

// putBlob stores the key blob, and refuses a path that already holds anything.
//
// Create-only, deliberately: a volume's key and its ciphertext are one unit, so
// replacing the key of a path some volume is already using does not rotate
// anything — it strands that volume with no way back. `c8s secrets put
// --overwrite` is the deliberate way to replace a value, and this is not it.
func putBlob(ctx context.Context, hc *http.Client, baseURL, path string, blob Blob, auth authorizer) error {
	value, err := blob.Marshal()
	if err != nil {
		return err
	}
	body, err := json.Marshal(intsecrets.PutRequest{
		Value:     base64Std(value),
		Overwrite: false,
	})
	if err != nil {
		return err
	}

	req, err := operatorauth.NewRequest(ctx, http.MethodPut, baseURL+"/secrets"+path, body, auth)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch resp.StatusCode {
	case http.StatusCreated:
		return nil
	case http.StatusConflict:
		return fmt.Errorf("%s already holds a value; a volume key is not replaceable — "+
			"choose another path, or remove the volume that uses this one", path)
	default:
		return fmt.Errorf("cds returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}

// authorizer mints the operator Authorization header for one write, bound to
// its method, path, and body. Implemented by operatorauth.Signer.
type authorizer = operatorauth.Authorizer
