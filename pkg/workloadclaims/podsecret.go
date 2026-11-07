package workloadclaims

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Pod secret release (POC; workload attestation Q1). The broker asks for one
// store path with fresh evidence over its current snapshot, bound like Pod
// issuance (PI3) but under its own domain, to a single-use response key in
// place of a CSR key, and to the path. CDS seals the value to that key, so
// only the guest that produced the quote can open it.
const (
	PodSecretRoute          = "/pod-secrets"
	PodSecretChallengeRoute = "/secrets"
	podSecretDomain         = "c8s-pod-secret/v1\x00"
)

// PodSecretRequest is the body of POST /pod-secrets.
type PodSecretRequest struct {
	Challenge   string                       `json:"challenge"`
	Evidence    teetypes.AttestationEvidence `json:"evidence"`
	PodClaims   json.RawMessage              `json:"pod_claims"`
	Path        string                       `json:"path"`
	ResponseKey []byte                       `json:"response_key"`
}

// PodSecretResponse carries the sealed value and what the guest must enforce
// locally: the grant (allowlist entry) that released it and the image digests
// that entry names. Only containers running one of those images may mount the
// value.
type PodSecretResponse struct {
	Workload string   `json:"workload"`
	Readers  []string `json:"readers"`
	Sealed   []byte   `json:"sealed"`
}

// PodSecret is an opened release.
type PodSecret struct {
	Path     string
	Workload string
	Readers  []string
	Value    []byte
}

func podSecretKEM() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

// PodSecretReportData is the 48-byte binding the broker quotes:
//
//	SHA-384("c8s-pod-secret/v1" || 0x00 || SHA-384(response key) ||
//	        challenge || SHA-384(claims bytes) || SHA-384(path))
func PodSecretReportData(responseKey, nonce, canonical []byte, path string) ([]byte, error) {
	if len(nonce) != 32 {
		return nil, fmt.Errorf("pod secret request requires a 32-byte challenge")
	}
	if _, err := podSecretKEM().NewPublicKey(responseKey); err != nil {
		return nil, fmt.Errorf("invalid Pod secret response key")
	}
	if _, err := DecodePodClaims(canonical); err != nil {
		return nil, err
	}
	keyHash := sha512.Sum384(responseKey)
	claimsHash := sha512.Sum384(canonical)
	pathHash := sha512.Sum384([]byte(path))
	h := sha512.New384()
	_, _ = h.Write([]byte(podSecretDomain))
	_, _ = h.Write(keyHash[:])
	_, _ = h.Write(nonce)
	_, _ = h.Write(claimsHash[:])
	_, _ = h.Write(pathHash[:])
	return h.Sum(nil), nil
}

// SealPodSecret encrypts value to the request's response key. The info is
// the request's binding, so a sealed value opens only for the request it
// answers.
func SealPodSecret(responseKey, binding, value []byte) ([]byte, error) {
	pub, err := podSecretKEM().NewPublicKey(responseKey)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pub, hpke.HKDFSHA256(), hpke.AES256GCM(), binding, value)
}

func openPodSecret(priv hpke.PrivateKey, binding, sealed []byte) ([]byte, error) {
	return hpke.Open(priv, hpke.HKDFSHA256(), hpke.AES256GCM(), binding, sealed)
}

// PodSecretTransport is the slice of attestclient.Client the broker uses: an
// authenticated POST to CDS and the local quote service.
type PodSecretTransport interface {
	PostJSON(ctx context.Context, path string, body []byte) ([]byte, error)
	GenerateEvidenceContext(ctx context.Context, attestationAPIURL string, reportData []byte) (remote.AttestResponse, error)
}

// ObtainPodSecretContext runs one release round for path over claims. The
// caller owns the snapshot and exclusive quote access, as for issuance.
func ObtainPodSecretContext(ctx context.Context, c PodSecretTransport, attestationURL, path string, claims PodClaims) (PodSecret, error) {
	canonical, err := claims.Canonical()
	if err != nil {
		return PodSecret{}, err
	}
	priv, err := podSecretKEM().GenerateKey()
	if err != nil {
		return PodSecret{}, err
	}
	responseKey := priv.PublicKey().Bytes()
	raw, err := c.PostJSON(ctx, PodSecretChallengeRoute, nil)
	if err != nil {
		return PodSecret{}, fmt.Errorf("pod secret challenge: %w", err)
	}
	var challenge types.ChallengeResponse
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return PodSecret{}, fmt.Errorf("pod secret challenge: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return PodSecret{}, fmt.Errorf("pod secret challenge: %w", err)
	}
	binding, err := PodSecretReportData(responseKey, nonce, canonical, path)
	if err != nil {
		return PodSecret{}, err
	}
	evidence, err := c.GenerateEvidenceContext(ctx, attestationURL, binding)
	if err != nil {
		return PodSecret{}, fmt.Errorf("attestation-api: %w", err)
	}
	if !evidence.Platform.IsTDX() {
		return PodSecret{}, fmt.Errorf("pod secrets require TDX evidence")
	}
	body, err := json.Marshal(PodSecretRequest{
		Challenge: challenge.Challenge, Evidence: evidence.Envelope(),
		PodClaims: canonical, Path: path, ResponseKey: responseKey,
	})
	if err != nil {
		return PodSecret{}, err
	}
	raw, err = c.PostJSON(ctx, PodSecretRoute, body)
	if err != nil {
		return PodSecret{}, err
	}
	var resp PodSecretResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return PodSecret{}, fmt.Errorf("decode Pod secret response: %w", err)
	}
	value, err := openPodSecret(priv, binding, resp.Sealed)
	if err != nil {
		return PodSecret{}, fmt.Errorf("open Pod secret: %w", err)
	}
	for _, d := range resp.Readers {
		if !types.IsCanonicalDigest(d) {
			return PodSecret{}, fmt.Errorf("pod secret names an invalid reader digest")
		}
	}
	if len(resp.Readers) == 0 {
		return PodSecret{}, fmt.Errorf("pod secret names no reader")
	}
	return PodSecret{Path: path, Workload: resp.Workload, Readers: slices.Clone(resp.Readers), Value: value}, nil
}
