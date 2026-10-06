package secrets

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

// errMeshCARequired is the refusal an operator gets for a write that names no
// mesh CA. ARmTLS proves the peer is a TEE running a pinned build; a launch
// measurement does not distinguish instances running the same node image.
// The mesh CA key is generated per CDS and is the anchor that
// `c8s verify --mesh-ca` and every workload already hold.
var errMeshCARequired = fmt.Errorf(
	"refusing to write a secret to a CDS whose mesh CA is not pinned: --measurements proves the peer is an attested build, " +
		"but every confidential pod boots that same build, so it does not prove the peer is your CDS. " +
		"Pass --mesh-ca <bundle.pem> (the anchor you pass to 'c8s verify --mesh-ca'), or --force to write without it")

// verifyMeshCA fails unless every certificate CDS serves at GET /ca is present
// in the operator's pinned bundle.
//
// INVARIANT: the fetch travels the attested channel the write itself uses, so
// the bytes compared are the ones that CDS — not the host — served.
func (c client) verifyMeshCA(ctx context.Context, bundlePath string) error {
	pinned, err := pinnedCerts(bundlePath)
	if err != nil {
		return err
	}
	served, err := c.fetchCA(ctx)
	if err != nil {
		return err
	}
	if len(served) == 0 {
		return fmt.Errorf("cds served no certificate at /ca, so its mesh CA cannot be checked against --mesh-ca")
	}
	for _, der := range served {
		if !pinned[string(der)] {
			return fmt.Errorf(
				"the CDS at %s serves a mesh CA that is not in --mesh-ca %s: this is not the CDS that issued your workloads' certificates, "+
					"and a secret written here would be released to whatever it admits", c.baseURL, bundlePath)
		}
	}
	return nil
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

// fetchCA reads CDS's mesh CA chain over the attested channel.
func (c client) fetchCA(ctx context.Context) ([][]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ca", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch the CDS mesh CA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cds returned %d for /ca, so its mesh CA cannot be checked against --mesh-ca", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read the CDS mesh CA: %w", err)
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
