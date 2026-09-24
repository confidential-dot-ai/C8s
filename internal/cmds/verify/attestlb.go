package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// gatherFromAttestLB fetches attest-lb evidence over one TLS connection and
// binds it to the serving leaf that connection presented, so the verdict
// speaks for the connection a native client rides afterwards.
func gatherFromAttestLB(ctx context.Context, base, serverName string, timeout time.Duration) (*evidence, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = "/.well-known/c8s/attest-lb"
	u.RawQuery = "nonce=" + base64.RawURLEncoding.EncodeToString(nonce)

	var servingLeaf []byte
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec // the transcript binds the observed leaf
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if peers := conn.(*tls.Conn).ConnectionState().PeerCertificates; len(peers) > 0 {
				servingLeaf = peers[0].Raw
			}
			return conn, nil
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("GET %s: %w", u, err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("read response: %w", err)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &connectError{err: fmt.Errorf("GET %s returned %d: %s", u, resp.StatusCode, strings.TrimSpace(string(data)))}
	}
	if servingLeaf == nil {
		return nil, fmt.Errorf("attest-lb needs a TLS target: no serving certificate was observed")
	}
	return evidenceFromAttestLBJSON(data, nonce, servingLeaf, fmt.Sprintf("attest-lb endpoint %s", u.Redacted()))
}

// evidenceFromAttestLBJSON verifies an attest-lb bundle against the nonce
// sent and the serving leaf observed on the same connection.
func evidenceFromAttestLBJSON(data, nonce, servingLeaf []byte, source string) (*evidence, error) {
	var r attestationResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse attestation response: %w", err)
	}
	if r.Version != types.BindingAttestLB {
		return nil, fmt.Errorf("attestation response version %q is not the attest-lb binding %q", r.Version, types.BindingAttestLB)
	}
	if len(r.Evidence) == 0 {
		return nil, fmt.Errorf("attestation response carries no evidence")
	}
	echoed, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.Nonce, "="))
	if err != nil || !bytes.Equal(echoed, nonce) {
		return nil, &securityError{err: fmt.Errorf("response nonce does not echo the challenge (possible replay or MITM)")}
	}
	leaf, ca, err := committedMeshChain(r.CDSCertPEM, r.IdentityProof)
	if err != nil {
		return nil, err
	}
	erd, err := overenc.LBTranscriptHash(r.FrontDoorMode, nonce, servingLeaf, leaf.Raw, ca.Raw)
	if err != nil {
		return nil, fmt.Errorf("compute attest-lb transcript: %w", err)
	}
	if err := verifyIdentityProof(r.IdentityProof, leaf, erd); err != nil {
		return nil, &securityError{err: err}
	}
	if err := verifyCommittedChain(leaf, ca); err != nil {
		return nil, &securityError{err: err}
	}

	sandboxID, sandboxErr := ratls.SandboxIDFromCert(leaf)
	workload, workloadErr := ratls.MatchedWorkloadFromCert(leaf)
	var rollout *types.RolloutState
	var rolloutErr error
	if r.CDSState != nil {
		rollout, rolloutErr = verifyRolloutState(r.CDSState, ca, nonce)
	}
	return &evidence{
		platform:         platformOrDefault(r.Platform),
		rawEvidence:      r.Evidence,
		erd:              erd,
		fresh:            true,
		source:           source,
		bindingNote:      "REPORTDATA binds the attest-lb transcript: front-door mode + nonce + the serving leaf this connection presented + the exact mesh leaf and its transcript-committed issuing CA (leaf proof of possession verified)",
		leaf:             leaf,
		leafChainDerived: true,
		frontDoor:        frontDoorNone,
		sandboxID:        sandboxID,
		sandboxErr:       sandboxErr,
		workload:         workload,
		workloadErr:      workloadErr,
		rollout:          rollout,
		rolloutErr:       rolloutErr,
	}, nil
}
