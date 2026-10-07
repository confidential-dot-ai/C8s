// Package cdsca implements `c8s cds ca`: read the CDS mesh CA bundle over the
// attested connection.
//
// The bundle is the anchor `--mesh-ca` takes on `c8s secrets put` and
// `c8s verify`. It is read from the same `GET /ca` route that gate compares
// against, over the channel cdsconn builds — armTLS to a direct CDS URL, a
// verified discovery document at a router front door.
package cdsca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// errUnpinned refuses a read that would turn "any attested build" into an
// anchor. Every command taking --mesh-ca treats the bundle as a pin it checks
// CDS against; one read from an unpinned endpoint is whatever answered, and
// pinning it later proves only that the same thing answered twice.
var errUnpinned = errors.New(
	"refusing to read a mesh CA from an unpinned CDS: no endpoint image is pinned, so any attested build would be accepted " +
		"and its CA would become the anchor you pin. Pass --image-policy-file <policy.json>, --measurements <endpoint build ID>, or --measurements-file")

// errPlaintext refuses a plaintext endpoint. The bundle distinguishes one CDS
// from another and nothing over http attests to being either.
var errPlaintext = errors.New(
	"--url must be https: the mesh CA bundle is read over the attested connection, and a plaintext CDS " +
		"needs no bundle — the --mesh-ca gate exempts http endpoints")

// NewCmd returns the `ca` subcommand.
func NewCmd() *cobra.Command { return newCmd(nil) }

// newCmd is the injectable constructor behind NewCmd.
func newCmd(verifier cdsconn.PinVerifier) *cobra.Command {
	o := &cdsconn.Options{Verifier: verifier}
	var out string
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Read the CDS mesh CA bundle over the attested connection",
		Long: `Read the mesh CA bundle CDS serves at GET /ca and write it as PEM to --out,
or to stdout. This is the anchor 'c8s secrets put --mesh-ca' and
'c8s verify --mesh-ca' take.

The read travels the attested connection those commands use and requires endpoint
pins: use --image-policy-file for a complete image policy, or --measurements
(or --measurements-file) for launch digests. Pin CDS for a direct URL, or the
router for a front door. A launch measurement identifies the image, not the
instance, so the SHA-256 of each certificate is printed on stderr — record it,
and compare it on a later read or against a copy obtained another way.

CDS generates its mesh CA in process, so a restart replaces it and the bundle
has to be read again. The bundle carries the CAs CDS still signs against, newest
first.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			u, err := url.Parse(o.URL)
			if err != nil {
				return fmt.Errorf("parse --url %q: %w", o.URL, err)
			}
			if u.Scheme != "https" {
				return errPlaintext
			}
			pinned, err := o.Pinned()
			if err != nil {
				return err
			}
			if !pinned {
				return errUnpinned
			}
			hc, err := o.HTTPClient(cmd.Context())
			if err != nil {
				return err
			}
			raw, err := attestclient.NewClientWithHTTP(o.URL, hc).MeshCA(cmd.Context())
			if err != nil {
				return fmt.Errorf("read the mesh CA from %s: %w", o.URL, err)
			}
			certs, err := certutil.ParsePEMCertificates(raw)
			if err != nil {
				return fmt.Errorf("parse the mesh CA from %s: %w", o.URL, err)
			}
			report(cmd.ErrOrStderr(), certs)

			bundle := encode(certs)
			if out == "" {
				_, err = cmd.OutOrStdout().Write(bundle)
				return err
			}
			if err := os.WriteFile(out, bundle, 0o644); err != nil {
				return fmt.Errorf("write %q: %w", out, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d certificate(s) to %s\n", len(certs), out)
			return nil
		},
	}
	cdsconn.BindFlags(cmd.Flags(), o)
	cmd.Flags().StringVar(&out, "out", "", "write the bundle here instead of stdout")
	return cmd
}

// encode re-emits the parsed certificates. The bundle holds the DER the
// --mesh-ca gate compares and nothing else, so a byte CDS served outside a
// CERTIFICATE block never reaches the anchor.
func encode(certs []*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, c := range certs {
		// pem.Encode fails only on a writer error; bytes.Buffer has none.
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return out.Bytes()
}

// report names each certificate: the digest to record and compare on a later
// read, and the validity window, which moves when CDS regenerates the CA.
func report(w io.Writer, certs []*x509.Certificate) {
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		fmt.Fprintf(w, "mesh CA  sha256=%s  subject=%q  not-before=%s  not-after=%s\n",
			hex.EncodeToString(sum[:]), c.Subject.CommonName,
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
}
