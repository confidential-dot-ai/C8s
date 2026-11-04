package cdsrecovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Target is authority-owned policy. Images must pin the exact measured launch
// file, including the recovery authority. AttestationURL must name the
// authority's own trusted local verifier, never one supplied by the operator.
type Target struct {
	Origin         string
	Images         []remote.ImagePin
	AttestationURL string
}

// Release fetches a fresh recipient over pinned armTLS and returns ciphertext
// that an untrusted provisioning relay can deliver. The caller must protect
// the signing key and WAL key, and durably authorize cluster initialization.
// This helper is not itself a key custodian or an HA service.
func Release(ctx context.Context, expected Identity, target Target, m Material, signer ed25519.PrivateKey) (*Grant, error) {
	q, err := fetchRecipient(ctx, expected, target)
	if err != nil {
		return nil, err
	}
	return seal(q, m, signer)
}

func checkTarget(expected Identity, target Target) error {
	if err := expected.check(); err != nil {
		return err
	}
	u, err := url.Parse(target.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("recovery: recipient must be an HTTPS origin")
	}
	local, err := url.Parse(target.AttestationURL)
	if err != nil {
		return errors.New("recovery: invalid local verifier")
	}
	ip, _ := netip.ParseAddr(local.Hostname())
	unix := local.Scheme == "unix" && local.Host == "" && local.Path != ""
	loopback := (local.Scheme == "http" || local.Scheme == "https") && ip.IsLoopback() && (local.Path == "" || local.Path == "/")
	if (!unix && !loopback) || local.User != nil || local.RawQuery != "" || local.Fragment != "" {
		return errors.New("recovery: verifier must be local to the trusted authority")
	}
	if len(target.Images) == 0 {
		return errors.New("recovery: launch-bound image pins required")
	}
	for _, image := range target.Images {
		hash := sha256.Sum256(image.LaunchFile)
		if len(image.Digest) == 0 || len(image.LaunchFile) == 0 || hex.EncodeToString(hash[:]) != expected.ConfigSHA256 || image.Anchor != nil {
			return errors.New("recovery: image pins must bind the expected launch file")
		}
	}
	return nil
}

func fetchRecipient(ctx context.Context, expected Identity, target Target) (Request, error) {
	if err := checkTarget(expected, target); err != nil {
		return Request{}, err
	}
	client, err := armtls.NewVerifyingHTTPClient(armtls.Pins{Images: target.Images}, target.AttestationURL)
	if err != nil {
		return Request{}, err
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	u, _ := url.Parse(target.Origin) // checkTarget validated it.
	u.Path = RequestPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Request{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Request{}, errors.New("recovery: attested recipient request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Request{}, errors.New("recovery: recipient request refused")
	}
	body, err := readutil.ReadAll(resp.Body, 8<<10)
	if err != nil {
		return Request{}, errors.New("recovery: invalid recipient response")
	}
	var q Request
	if err := decode(body, &q); err != nil || q.Identity != expected {
		return Request{}, errors.New("recovery: recipient identity mismatch")
	}
	if err := q.check(); err != nil {
		return Request{}, err
	}
	return q, nil
}
