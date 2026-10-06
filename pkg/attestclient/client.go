package attestclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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
}

// CertificateResult is the complete CDS challenge/attest/certify result.
// Certificate is the PEM chain issued by CDS. Challenge, Platform, and
// Evidence are the attestation material that authorized issuance.
//
// Authenticity of Certificate on the network path is provided by the ARmTLS
// handshake the caller performed against CDS (see pkg/armtls.NewClientTLSConfig);
// callers MUST construct this client over an ARmTLS-verified transport.
type CertificateResult struct {
	Certificate string
	Challenge   string
	Platform    teetypes.PlatformType
	Evidence    json.RawMessage
}

// NewClient creates a new attestation flow client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
	}
}

// NewClientWithHTTP creates a new client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// GenerateEvidence calls the local attestation-api to generate TEE evidence
// for the given report data. This is the same attestation-api call used
// internally by ObtainCertificate, exposed for callers that need evidence
// without the full CDS challenge-attest-certify flow.
func (c Client) GenerateEvidence(attestationApiURL string, reportData []byte) (remote.AttestResponse, error) {
	return c.GenerateEvidenceContext(context.Background(), attestationApiURL, reportData)
}

// GenerateEvidenceContext is GenerateEvidence with caller-controlled
// cancellation.
func (c Client) GenerateEvidenceContext(ctx context.Context, attestationApiURL string, reportData []byte) (remote.AttestResponse, error) {
	asClient := remote.NewClientWithHTTP(attestationApiURL, c.httpClient)
	return asClient.Attest(contextOrBackground(ctx), remote.AttestRequest{
		ReportData: reportData,
		Platform:   remote.PlatformAuto,
	})
}

// ObtainCertificate performs the full attestation flow and returns a signed
// certificate chain.
//
// It:
//  1. Requests a challenge nonce from CDS (POST /authenticate)
//  2. Passes SHA-384(CSR public key || challenge) as report_data to the
//     local attestation-api (POST /attest)
//  3. Submits the evidence and caller-provided CSR to CDS (POST /attest)
//     which verifies the evidence and returns a signed certificate chain
func (c Client) ObtainCertificate(attestationApiURL, csrPEM string) (string, error) {
	return c.ObtainCertificateWithContext(context.Background(), attestationApiURL, csrPEM)
}

// ObtainCertificateWithContext is ObtainCertificate with caller-controlled
// cancellation.
func (c Client) ObtainCertificateWithContext(ctx context.Context, attestationApiURL, csrPEM string) (string, error) {
	result, err := c.ObtainCertificateWithEvidenceContext(ctx, attestationApiURL, csrPEM)
	if err != nil {
		return "", err
	}
	return result.Certificate, nil
}

// ObtainCertificateWithEvidence performs the full attestation flow and returns
// both the issued certificate chain and the evidence used to obtain it.
func (c Client) ObtainCertificateWithEvidence(attestationApiURL, csrPEM string) (CertificateResult, error) {
	return c.ObtainCertificateWithEvidenceContext(context.Background(), attestationApiURL, csrPEM)
}

// ObtainCertificateWithEvidenceContext is ObtainCertificateWithEvidence with
// caller-controlled cancellation across authenticate, local attest, and CDS
// attest requests.
func (c Client) ObtainCertificateWithEvidenceContext(ctx context.Context, attestationApiURL, csrPEM string) (CertificateResult, error) {
	ctx = contextOrBackground(ctx)
	// The plain flow fetches its own challenge; the sandbox flow has get-cert
	// fetch it so one nonce binds both the token and the evidence.
	challengeResp, err := c.AuthenticateContext(ctx)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("authenticate: %w", err)
	}
	return c.ObtainCertificateWithSandboxContext(ctx, attestationApiURL, csrPEM, challengeResp.Challenge, nil)
}

// ObtainCertificateWithSandboxContext is ObtainCertificateWithEvidenceContext
// that additionally forwards an inventory-signed sandbox token. challenge is
// the base64 CDS challenge the caller already fetched (POST /authenticate); the
// same nonce binds the evidence REPORTDATA and the sandbox token, so CDS checks
// both against one single-use value. sandboxToken, when non-empty, is the
// token JSON (workloadclaims.SignedSandboxToken) forwarded opaquely for CDS to
// verify and stamp as the leaf's pod-sandbox-ID extension (armtls.OIDSandboxID).
//
// The requester never reports its own container images: CDS resolves those
// from the inventory named by the token (docs/armtls.md, "Sandbox identity").
func (c Client) ObtainCertificateWithSandboxContext(ctx context.Context, attestationApiURL, csrPEM, challenge string, sandboxToken json.RawMessage) (CertificateResult, error) {
	ctx = contextOrBackground(ctx)

	// The caller fetched the challenge so the same nonce binds both the sandbox
	// token and the evidence REPORTDATA below.
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("invalid base64 in challenge: %w", err)
	}

	reportData, err := reportDataForCSR(csrPEM, challengeBytes)
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
	attestReq := attestRequest{
		Challenge:    challenge,
		Evidence:     asResp.Envelope(),
		CSR:          csrPEM,
		SandboxToken: sandboxToken,
	}
	certPEM, err := c.AttestContext(ctx, attestReq)
	if err != nil {
		return CertificateResult{}, err
	}

	return CertificateResult{
		Certificate: certPEM,
		Challenge:   challenge,
		Platform:    asResp.Platform,
		Evidence:    asResp.Evidence,
	}, nil
}

// Authenticate requests an attestation challenge nonce.
func (c Client) Authenticate() (types.ChallengeResponse, error) {
	return c.AuthenticateContext(context.Background())
}

// AuthenticateContext requests an attestation challenge nonce with
// caller-controlled cancellation.
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

type attestRequest struct {
	Challenge    string                       `json:"challenge"`
	Evidence     teetypes.AttestationEvidence `json:"evidence"`
	CSR          string                       `json:"csr"`
	SandboxToken json.RawMessage              `json:"sandbox_token,omitempty"`
}

// Attest submits attestation evidence and receives a signed certificate chain
// PEM.
func (c Client) Attest(req attestRequest) (string, error) {
	return c.AttestContext(context.Background(), req)
}

// AttestContext submits attestation evidence with caller-controlled
// cancellation.
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
// Authenticity comes from the ARmTLS transport the client was constructed
// over, the same channel that authenticates the CA trailing an issued chain.
func (c Client) MeshCA(ctx context.Context) ([]byte, error) {
	return c.do(ctx, http.MethodGet, "/ca", nil)
}

// Healthz checks liveness of the CDS service.
func (c Client) Healthz() (bool, error) {
	return c.ok("/healthz")
}

// Readyz checks readiness of the CDS service.
func (c Client) Readyz() (bool, error) {
	return c.ok("/readyz")
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

// ok reports whether a GET of path returned 2xx.
func (c Client) ok(path string) (bool, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func reportDataForCSR(csrPEM string, challenge []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR must be a PEM-encoded certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	reportData, err := armtls.ReportDataForKey(csr.PublicKey, challenge)
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
