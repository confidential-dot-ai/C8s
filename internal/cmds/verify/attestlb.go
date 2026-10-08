package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
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
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		// The evidence must come from the connection it binds.
		return http.ErrUseLastResponse
	}, Transport: &http.Transport{
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
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &connectError{err: fmt.Errorf("GET %s returned %d: %s", u, resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("read response: %w", err)}
	}
	if servingLeaf == nil {
		return nil, fmt.Errorf("attest-lb needs a TLS target: no serving certificate was observed")
	}
	ev, err := evidenceFromAttestLBJSON(data, nonce, servingLeaf, fmt.Sprintf("attest-lb endpoint %s", u.Redacted()))
	if err != nil {
		return nil, err
	}
	ev.servingLeafSHA256 = servingLeafDigest(servingLeaf)
	return ev, nil
}

// gatherFromAttestLBFile verifies a saved attest-lb receipt against the
// challenge the client sent and the serving leaf it observed on the same
// connection. The verdict is not fresh: it proves what the connection was,
// not what the front door serves now.
func gatherFromAttestLBFile(data []byte, nonceB64, certPath, source string) (*evidence, error) {
	nonce, err := parseAttestationNonce(nonceB64)
	if err != nil {
		return nil, err
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("--observed-serving-cert: %w", err)
	}
	servingLeaf, err := parseObservedServingCert(certData)
	if err != nil {
		return nil, fmt.Errorf("--observed-serving-cert: %w", err)
	}
	ev, err := evidenceFromAttestLBJSON(data, nonce, servingLeaf, source)
	if err != nil {
		return nil, err
	}
	ev.fresh = false
	ev.servingLeafSHA256 = servingLeafDigest(servingLeaf)
	return ev, nil
}

// parseAttestationNonce decodes the canonical unpadded base64url form of the
// 32-byte challenge, the form the attest-lb query and response carry it in.
func parseAttestationNonce(value string) ([]byte, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("--attestation-nonce must be unpadded base64url: %w", err)
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("--attestation-nonce must decode to %d bytes, got %d", nonceSize, len(nonce))
	}
	if base64.RawURLEncoding.EncodeToString(nonce) != value {
		return nil, fmt.Errorf("--attestation-nonce must be canonical unpadded base64url")
	}
	return nonce, nil
}

// parseObservedServingCert accepts one certificate as PEM or DER and returns
// its DER, the form the transcript binds.
func parseObservedServingCert(data []byte) ([]byte, error) {
	der := data
	if block, rest := pem.Decode(bytes.TrimSpace(data)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block is %q, want CERTIFICATE", block.Type)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("file must hold exactly one certificate")
		}
		der = block.Bytes
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return der, nil
}

func servingLeafDigest(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
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

	sandboxID, sandboxErr := armtls.SandboxIDFromCert(leaf)
	workload, workloadErr := armtls.MatchedWorkloadFromCert(leaf)
	return &evidence{
		platform:         platformOrDefault(r.Platform),
		rawEvidence:      r.Evidence,
		erd:              erd,
		fresh:            true,
		source:           source,
		bindingNote:      "REPORTDATA binds the attest-lb transcript: front-door mode + nonce + the serving leaf this connection presented + the exact mesh leaf and its transcript-committed issuing CA (leaf proof of possession verified)",
		leaf:             leaf,
		leafChainDerived: true,
		frontDoor:        frontDoorAttested,
		sandboxID:        sandboxID,
		sandboxErr:       sandboxErr,
		workload:         workload,
		workloadErr:      workloadErr,
	}, nil
}
