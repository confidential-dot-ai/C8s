package attestclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// maxErrorBodyBytes caps how much of an untrusted peer's non-2xx response
// body is read into StatusError.
const maxErrorBodyBytes = 8 << 10

// maxResponseBodyBytes caps a 2xx response body. The largest legitimate
// payloads are evidence envelopes carrying quotes and certificate chains,
// well under this; anything bigger is a misbehaving peer, not data.
const maxResponseBodyBytes = 8 << 20

// defaultRequestTimeout bounds each request made by a NewClient-built client.
// Callers needing a different bound pass their own client via
// NewClientWithHTTP (or a per-call context deadline for a tighter one).
const defaultRequestTimeout = 60 * time.Second

// Client is a high-level client for the CDS attestation flow.
// It handles the full challenge-attest-certify flow in a single call.
type Client struct {
	baseURL    string
	httpClient *http.Client
	// attestHTTP reaches the attestation-api. It never shares httpClient's
	// TLS settings, which verify CDS, and never uses a proxy.
	attestHTTP *http.Client

	// MeasuredPolicies is the node's measured-policy journal that TDX
	// evidence lists, in the /attest request and in AttestationExtension;
	// nil lists none.
	MeasuredPolicies *armtls.Journal
}

// CertificateResult is the complete CDS challenge/attest/certify result.
// Certificate is the PEM chain issued by CDS. Challenge, Platform, Evidence
// and RuntimeExtensions are the attestation material that authorized issuance.
//
// Authenticity of Certificate on the network path is provided by the armTLS
// handshake the caller performed against CDS (see pkg/armtls.NewClientTLSConfig);
// callers MUST construct this client over an armTLS-verified transport.
type CertificateResult struct {
	Certificate string
	Challenge   string
	Platform    teetypes.PlatformType
	Evidence    json.RawMessage

	// RuntimeExtensions is the TDX RTMR[3] runtime extension list the
	// evidence vouches for: a node's measured policies sent with the request
	// (Client.MeasuredPolicies), or a pod's measured images carried inside
	// its claims; nil off TDX.
	RuntimeExtensions []string
}

// NewClient creates a new attestation flow client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
		attestHTTP: armtls.NewDirectHTTPClient(defaultRequestTimeout),
	}
}

// NewClientWithHTTP creates a new client that reaches CDS through httpClient.
// Evidence requests to the attestation-api keep only its timeout: they verify
// the system roots, never httpClient's CDS verification, and never use a
// proxy.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		attestHTTP: armtls.NewDirectHTTPClient(httpClient.Timeout),
	}
}

// GenerateEvidenceContext calls the local attestation-api to generate TEE
// evidence for the given report data. The request never goes through a proxy.
func (c Client) GenerateEvidenceContext(ctx context.Context, attestationApiURL string, reportData []byte) (remote.AttestResponse, error) {
	asClient := remote.NewClientWithHTTP(attestationApiURL, c.attestHTTP)
	return asClient.Attest(contextOrBackground(ctx), remote.AttestRequest{
		ReportData: reportData,
		Platform:   remote.PlatformAuto,
	})
}

// ObtainCertificateWithSandboxContext performs the full attestation flow and
// returns the issued chain with the evidence that authorized it, forwarding an
// inventory-signed sandbox token. challenge is the base64 CDS challenge the
// caller already fetched (POST /authenticate); the same nonce binds the
// evidence REPORTDATA and the sandbox token, so CDS checks both against one
// single-use value. sandboxToken, when non-empty, is the token JSON
// (workloadclaims.SignedSandboxToken) forwarded opaquely for CDS to verify and
// stamp as the leaf's pod-sandbox-ID extension (armtls.OIDSandboxID).
//
// The requester never reports its own container images: CDS resolves those
// from the inventory named by the token (docs/armtls.md, "Sandbox identity").
func (c Client) ObtainCertificateWithSandboxContext(ctx context.Context, attestationApiURL, csrPEM, challenge string, sandboxToken json.RawMessage) (CertificateResult, error) {
	return c.ObtainCertificateWithProfileContext(ctx, attestationApiURL, csrPEM, challenge, IssuanceProfile{
		ReportData: nodeReportData,
		Request: func(platform teetypes.PlatformType, req *types.AttestRequestBody) error {
			req.SandboxToken = sandboxToken
			if platform.IsTDX() {
				req.RuntimeExtensions = c.MeasuredPolicies.Policies()
			}
			return nil
		},
	})
}

// IssuanceProfile is one profile's share of a challenge-attest-certify round:
// how its quote binds the CSR key to the challenge, and what its /attest
// request carries beside the challenge, the evidence and the CSR. Each
// profile chooses its own report-data preimage, so a quote obtained for one
// never satisfies another.
type IssuanceProfile struct {
	// ReportData returns the 48 report-data bytes binding key, the
	// signature-checked CSR key, to challenge, the decoded nonce.
	ReportData func(key crypto.PublicKey, challenge []byte) ([]byte, error)
	// Request completes req once evidence from platform is in hand. An error
	// refuses issuance before anything reaches CDS.
	Request func(platform teetypes.PlatformType, req *types.AttestRequestBody) error
}

// ObtainCertificateWithProfileContext runs one issuance round for p: it quotes
// p.ReportData over the CSR key and the challenge, lets p complete the /attest
// request, and returns the chain CDS issued with the material that authorized
// it. challenge is the base64 CDS challenge the caller fetched, so one nonce
// can bind the evidence and whatever else the profile carries.
func (c Client) ObtainCertificateWithProfileContext(ctx context.Context, attestationApiURL string, csrPEM string, challenge string, p IssuanceProfile) (CertificateResult, error) {
	ctx = contextOrBackground(ctx)

	if p.ReportData == nil || p.Request == nil {
		return CertificateResult{}, fmt.Errorf("issuance profile must set ReportData and Request")
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("invalid base64 in challenge: %w", err)
	}
	csr, err := certutil.ParseCSRPEM([]byte(csrPEM))
	if err != nil {
		return CertificateResult{}, err
	}
	reportData, err := p.ReportData(csr.PublicKey, challengeBytes)
	if err != nil {
		return CertificateResult{}, err
	}

	asResp, err := c.GenerateEvidenceContext(ctx, attestationApiURL, reportData)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("attestation-api: %w", err)
	}

	// Submit evidence + CSR to CDS for verification and cert issuance.
	// asResp.Evidence is the platform-specific evidence object as emitted by
	// /attest; CDS's /attest expects it wrapped in an AttestationEvidence
	// envelope keyed by Platform.
	req := attestRequest{Challenge: challenge, Evidence: asResp.Envelope(), CSR: csrPEM}
	if err := p.Request(asResp.Platform, &req); err != nil {
		return CertificateResult{}, err
	}
	certPEM, err := c.AttestContext(ctx, req)
	if err != nil {
		return CertificateResult{}, err
	}

	return CertificateResult{
		Certificate:       certPEM,
		Challenge:         challenge,
		Platform:          asResp.Platform,
		Evidence:          asResp.Evidence,
		RuntimeExtensions: req.RuntimeExtensions,
	}, nil
}

// AuthenticateContext requests an attestation challenge nonce.
func (c Client) AuthenticateContext(ctx context.Context) (types.ChallengeResponse, error) {
	body, err := c.do(ctx, http.MethodPost, "/authenticate", nil)
	if err != nil {
		return types.ChallengeResponse{}, err
	}
	var result types.ChallengeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return types.ChallengeResponse{}, err
	}
	return result, nil
}

type attestRequest = types.AttestRequestBody

// AttestContext submits attestation evidence and receives a signed
// certificate chain PEM.
func (c Client) AttestContext(ctx context.Context, req attestRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	body, err := c.do(ctx, http.MethodPost, "/attest", data)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// MeshCA fetches the mesh CA bundle CDS currently serves at /ca.
// Authenticity comes from the armTLS transport the client was constructed
// over, the same channel that authenticates the CA trailing an issued chain.
func (c Client) MeshCA(ctx context.Context) ([]byte, error) {
	return c.do(ctx, http.MethodGet, "/ca", nil)
}

// do sends method path with an optional JSON body and returns the response
// body on 2xx. A non-2xx response becomes a *StatusError carrying a capped
// copy of the body.
func (c Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(contextOrBackground(ctx), method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, &StatusError{Status: resp.StatusCode, Body: string(respBody)}
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// nodeReportData is the node profile's binding, armtls.ReportDataForKey over
// the CSR key and the challenge, as the 48 bytes the attestation-api quotes.
func nodeReportData(key crypto.PublicKey, challenge []byte) ([]byte, error) {
	reportData, err := armtls.ReportDataForKey(key, challenge)
	if err != nil {
		return nil, err
	}
	out := make([]byte, sha512.Size384)
	copy(out, reportData[:sha512.Size384])
	return out, nil
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}
