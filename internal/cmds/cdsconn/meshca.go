package cdsconn

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// MeshCAGate is the --mesh-ca / --force pair every command that writes a value
// into the CDS secret store carries. armTLS proves the peer is a TEE running a
// pinned build; a launch measurement does not distinguish instances running the
// same node image. The mesh CA key is generated per CDS and is the anchor that
// `c8s verify --mesh-ca` and every workload already hold.
type MeshCAGate struct {
	// What names the value being written ("secret", "volume key") in the
	// refusal and the --force warning.
	What string
	// ForceNote, if set, is appended to the --force help.
	ForceNote string

	Bundle string
	Force  bool
}

// ErrMeshCAMismatch marks a refusal because CDS served a mesh CA outside the
// pinned bundle, as opposed to one where the CA could not be read or checked.
var ErrMeshCAMismatch = errors.New("the CDS serves a mesh CA that is not in --mesh-ca")

// BindFlags registers --mesh-ca and --force on a write subcommand.
func (g *MeshCAGate) BindFlags(f *pflag.FlagSet) {
	force := "write the " + g.what() + " without checking the CDS mesh CA against --mesh-ca"
	if g.ForceNote != "" {
		force += ". " + g.ForceNote
	}
	f.StringVar(&g.Bundle, "mesh-ca", "", "PEM bundle of the mesh CA this CDS must serve; the same anchor 'c8s verify --mesh-ca' takes. Required unless --force")
	f.BoolVar(&g.Force, "force", false, force)
}

// Precheck runs the part of the gate that needs no CDS: the flags name a bundle
// (or --force), and the bundle holds certificates. A command with expensive work
// before its write runs this first, so a missing flag costs nothing.
func (g *MeshCAGate) Precheck(rawURL string) error {
	if exempt(rawURL) || g.Force {
		return nil
	}
	_, err := g.pinned()
	return err
}

// Check refuses a write whose CDS is not pinned to an operator-held mesh CA.
// A plaintext endpoint is exempt for the same reason it is exempt from the
// measurement pin: --insecure has already announced that nothing about the peer
// is authenticated, and /ca fetched over it would be the host's answer anyway.
//
// INVARIANT: hc is the client from Options.HTTPClient that then carries the
// write. Every request on it reaches one peer (see the package doc), so the CA
// compared is the CA of the CDS that receives the value, not of whatever
// answered an earlier connection.
func (g *MeshCAGate) Check(ctx context.Context, stderr io.Writer, hc *http.Client, rawURL string) error {
	if exempt(rawURL) {
		return nil
	}
	if g.Force {
		fmt.Fprintf(stderr,
			"warning: --force: writing this %s without checking the CDS mesh CA. An attested peer at this address that is not your CDS receives the value.\n", g.what())
		return nil
	}
	pinned, err := g.pinned()
	if err != nil {
		return err
	}
	served, err := fetchCA(ctx, hc, rawURL)
	if err != nil {
		return err
	}
	if len(served) == 0 {
		return fmt.Errorf("cds served no certificate at /ca, so its mesh CA cannot be checked against --mesh-ca")
	}
	for _, der := range served {
		if !pinned[string(der)] {
			return fmt.Errorf(
				"%w: the CDS at %s is not the CDS that issued your workloads' certificates (--mesh-ca %s), "+
					"and a %s written here would be released to whatever it admits", ErrMeshCAMismatch, rawURL, g.Bundle, g.what())
		}
	}
	return nil
}

func (g *MeshCAGate) pinned() (map[string]bool, error) {
	if g.Bundle == "" {
		return nil, fmt.Errorf(
			"refusing to write a %s to a CDS whose mesh CA is not pinned: --measurements proves the peer is an attested build, "+
				"but nodes can boot that same build, so it does not prove the peer is your CDS. "+
				"Pass --mesh-ca <bundle.pem> (the anchor you pass to 'c8s verify --mesh-ca'), or --force to write without it", g.what())
	}
	return pinnedCerts(g.Bundle)
}

func (g *MeshCAGate) what() string {
	if g.What == "" {
		return "value"
	}
	return g.What
}

func exempt(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Scheme == "http"
}

// pinnedCerts reads the operator's bundle into a set keyed by raw DER. Identity
// is compared on the encoded certificate, not on a parsed field, so nothing in
// the comparison depends on how a certificate is interpreted.
func pinnedCerts(path string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --mesh-ca: %w", err)
	}
	certs, err := parseCertsPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("--mesh-ca %s: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("--mesh-ca %s contains no PEM certificates", path)
	}
	out := make(map[string]bool, len(certs))
	for _, der := range certs {
		out[string(der)] = true
	}
	return out, nil
}

// fetchCA reads CDS's mesh CA chain over hc with the client `c8s cds ca` uses,
// so the two read /ca alike.
func fetchCA(ctx context.Context, hc *http.Client, baseURL string) ([][]byte, error) {
	raw, err := attestclient.NewClientWithHTTP(baseURL, hc).MeshCA(ctx)
	var status *attestclient.StatusError
	switch {
	case errors.As(err, &status):
		return nil, fmt.Errorf("cds returned %d for /ca, so its mesh CA cannot be checked against --mesh-ca", status.Status)
	case err != nil:
		return nil, fmt.Errorf("fetch the CDS mesh CA: %w", err)
	}
	certs, err := parseCertsPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("cds /ca: %w", err)
	}
	return certs, nil
}

// parseCertsPEM decodes every CERTIFICATE block in raw, returning their DER.
// A block that does not parse as a certificate is an error rather than a skip:
// a bundle half of which was understood is not a bundle an operator pinned.
func parseCertsPEM(raw []byte) ([][]byte, error) {
	var out [][]byte
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("PEM CERTIFICATE block does not parse: %w", err)
		}
		out = append(out, block.Bytes)
	}
	return out, nil
}
