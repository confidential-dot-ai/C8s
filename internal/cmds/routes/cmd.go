// Package routes implements the `c8s routes` operator CLI for the signed
// route manifest that CDS stores and serves at /routes (route policy §8).
//
// show and digest only read. put, add and rm send a manifest signed with the
// operator key, through the same connection and credential flags as
// `c8s allowlist` (internal/cmds/cdsconn).
package routes

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
)

type options struct {
	cdsconn.Options

	// operatorKeys is a PEM file of trusted operator public keys. When set,
	// every fetched manifest is verified as W2 requires.
	operatorKeys string
}

// NewCmd returns the `c8s routes` command tree.
func NewCmd() *cobra.Command {
	return newCmd(nil)
}

func newCmd(verifier cdsconn.PinVerifier) *cobra.Command {
	o := &options{Options: cdsconn.Options{Verifier: verifier}}
	cmd := &cobra.Command{
		Use:   "routes",
		Short: "Manage the signed route manifest on CDS",
		Long: `Read and write the route manifest (c8s.routes/v1) that CDS stores at /routes.

CDS keeps one signed route manifest: the manifest bytes and the write token
that authorized them. A write must carry a revision greater than the stored
one. 'put' writes a file verbatim, for example after a CDS restart that lost
its database. 'add' and 'rm' fetch the stored route manifest, verify it
against --operator-keys, change one route, and write the next revision. They
set notBefore to now, or keep the stored notBefore when it is later. The next
revision is the later of the stored one plus one and the current Unix time in
seconds, or --revision. Once routers apply the manifest, a router keeps the
highest revision it accepted, applied or staged, even across a CDS reset, so
after a reset write one above it. 'add' refuses an empty store unless --new
starts the first manifest. Before signing, they print every route the new
revision carries, since the write re-authorizes them all.

To sign writes, pass the operator key with --operator-key (or
C8S_OPERATOR_KEY), as for 'c8s allowlist'. --operator-keys names the operator
public keys you trust. 'show' verifies against them when given; 'add' and
'rm' require them, since they re-sign the stored routes.

Point --url at CDS itself, with no path, because the router does not relay
/routes. A port-forward to the CDS Service works; pin the CDS launch digest
with --measurements.`,
		SilenceUsage: true,
	}
	pf := cmd.PersistentFlags()
	cdsconn.BindFlags(pf, &o.Options)
	pf.StringVar(&o.operatorKeys, "operator-keys", "", "PEM file of trusted operator public keys; verifies the write token of every fetched route manifest")

	cmd.AddCommand(
		newShowCmd(o),
		newDigestCmd(),
		newPutCmd(o),
		newAddCmd(o),
		newRmCmd(o),
	)
	return cmd
}

func (o *options) client(ctx context.Context) (routesclient.Client, error) {
	if err := o.Validate(); err != nil {
		return routesclient.Client{}, err
	}
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return routesclient.Client{}, err
	}
	return routesclient.New(o.URL, hc)
}

// fetch returns the stored manifest, verified when --operator-keys is set.
// verified reports whether it was.
func (o *options) fetch(ctx context.Context, c routesclient.Client) (env pkgroutes.Envelope, m *pkgroutes.Manifest, verified bool, err error) {
	env, err = c.Get(ctx)
	if err != nil {
		return env, nil, false, err
	}
	if o.operatorKeys == "" {
		m, err = pkgroutes.Parse(env.Manifest)
		return env, m, false, err
	}
	keys, err := o.trustedKeys()
	if err != nil {
		return env, nil, false, err
	}
	s, err := pkgroutes.VerifySigned(env, keys, nil)
	if err != nil {
		return env, nil, false, fmt.Errorf("stored route manifest fails verification against --operator-keys: %w", err)
	}
	return env, s.Manifest(), true, nil
}

func (o *options) trustedKeys() ([]*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(o.operatorKeys)
	if err != nil {
		return nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("--operator-keys %q: %w", o.operatorKeys, err)
	}
	return keys, nil
}

// put signs and writes manifest, sending ifMatch when not empty. On a 409 or
// 412 it appends rebase, the recovery step for the calling command, unless
// the 409 refuses a spent token, which a fresh signature fixes.
func put(ctx context.Context, c routesclient.Client, manifest []byte, signer operatorauth.Authorizer, ifMatch, rebase string) error {
	err := c.Put(ctx, manifest, signer, ifMatch)
	var se *operatorauth.StatusError
	if errors.As(err, &se) {
		switch {
		case SpentToken(err):
			return fmt.Errorf("%w; re-run the command to sign a new token", err)
		case se.Status == http.StatusConflict, se.Status == http.StatusPreconditionFailed:
			return fmt.Errorf("%w; %s", err, rebase)
		case se.Status == http.StatusUnauthorized:
			return fmt.Errorf("%w; check that the public key of --operator-key is in cds.operatorKeys", err)
		}
	}
	return err
}

// SpentToken reports whether err is the CDS's 409 for a write token that
// already authorized a write, which a fresh token fixes, unlike a stale
// revision's 409.
func SpentToken(err error) bool {
	var se *operatorauth.StatusError
	return errors.As(err, &se) && se.Status == http.StatusConflict && strings.Contains(se.Body, allowlist.ErrTokenReused.Error())
}

func digestHex(manifest []byte) string {
	d := pkgroutes.Digest(manifest)
	return hex.EncodeToString(d[:])
}

func ctx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
