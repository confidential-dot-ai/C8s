//go:build linux

package armtlsmesh

import (
	"bytes"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// requirePeerWorkload runs only after the peer's mesh chain and ALPN were
// verified. A workload name alone cannot detect its redefinition in another policy.
func requirePeerWorkload(local, peer *x509.Certificate, allowed []string) error {
	ours, err := armtls.MatchedWorkloadFromCert(local)
	if err != nil {
		return err
	}
	theirs, err := armtls.MatchedWorkloadFromCert(peer)
	if err != nil {
		return err
	}
	if ours == nil || theirs == nil {
		return errors.New("outbound workload policy requires both matched-workload stamps")
	}
	if !slices.Contains(allowed, theirs.Name) {
		return errors.New("peer workload is not permitted")
	}
	if !bytes.Equal(ours.AllowlistDigest, theirs.AllowlistDigest) {
		return errors.New("peer workload was matched under another allowlist digest")
	}
	return nil
}
