package cdspins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// pinDecreePath answers 404 while the cluster has applied no decree.
const pinDecreePath = "/ha/pins"

// maxDecree bounds one answer, the largest of which lists an image roll.
const maxDecree = 1 << 20

// AttestedHTTPFetch reads the decree from a CDS that passes pins, over armTLS
// verified by the attestation-api at attestationAPIURL.
func AttestedHTTPFetch(cdsURL, attestationAPIURL string) AttestedFetcher {
	return func(ctx context.Context, pins refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
		client, err := armtls.NewVerifyingHTTPClient(armtls.Pins(pins.Policy()), attestationAPIURL)
		if err != nil {
			return nil, err
		}
		defer client.CloseIdleConnections()
		return getDecree(ctx, client, cdsURL)
	}
}

// HTTPFetch reads the decree without verifying the TLS peer: a client fetches
// this way because it recognises no CDS any more.
func HTTPFetch(cdsURL string) Fetcher {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the decree is signature-verified
		},
	}
	return func(ctx context.Context) (*cdsdecree.Signed, error) {
		return getDecree(ctx, client, cdsURL)
	}
}

// getDecree reads the decree a replica serves, and nil where it serves none.
// It verifies nothing: the Source decides what the bytes are worth.
func getDecree(ctx context.Context, client *http.Client, cdsURL string) (*cdsdecree.Signed, error) {
	route, err := url.JoinPath(cdsURL, pinDecreePath)
	if err != nil {
		return nil, fmt.Errorf("cdspins: the CDS endpoint %q: %w", cdsURL, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("cdspins: GET %s: %s", pinDecreePath, response.Status)
	}
	body, err := readutil.ReadAll(response.Body, maxDecree)
	if err != nil {
		return nil, fmt.Errorf("cdspins: GET %s: %w", pinDecreePath, err)
	}
	served, err := cdsdecree.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("cdspins: GET %s: %w", pinDecreePath, err)
	}
	return &served, nil
}
