package getkubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
)

// Config is the get-kubeconfig client configuration.
type Config struct {
	// ReleaseBaseURL is the cred-release endpoint base (e.g. https://<node>:8443).
	ReleaseBaseURL string
	// APIServerURL is the guest apiserver the kubeconfig points at
	// (e.g. https://<node>:6443).
	APIServerURL string
	// OperatorKeyPath is the operator ECDSA PRIVATE key (PEM). Its public half
	// was bound into the node's RTMR[3] at launch.
	OperatorKeyPath string
	// ImageManifestPath is the build-artifact manifest carrying the expected
	// guest image's full TDX tuple (mrtd, rtmr1, rtmr2). Required: without it
	// the gate would rest on RTMR[3] alone, which the untrusted host can
	// reproduce under any image it likes by staging the same operator key.
	ImageManifestPath string
	// WorkloadImages are the digest-pinned image refs the node's measurer is
	// expected to have extended into RTMR[3], in first-extend order. Empty
	// means the register must equal the bare operator-key seed.
	WorkloadImages []string
	// Role selects the identity cred-release stamps on the cert:
	// credrelease.RoleOperator (the bounded operator role; "" means the same) or
	// credrelease.RoleLogReader (pods and their logs only).
	Role string
	// ContextName names the kubeconfig cluster/context/user.
	ContextName string
	// TLSServerName is emitted as the kubeconfig's tls-server-name, so cert
	// verification is pinned to a stable SAN the image bakes (c8s-cvm) rather
	// than the per-launch IP the operator dials (which the apiserver cert has
	// no SAN for). Empty omits it (verification then needs the dialed IP to be
	// a cert SAN, which it usually isn't).
	TLSServerName string
	// OutPath is where the kubeconfig is written.
	OutPath string
	// Timeout bounds each network step.
	Timeout time.Duration
	// ReleaseWait bounds refused-connection retries for each cred-release step.
	ReleaseWait time.Duration
}

// Run executes the client flow: attest + RTMR[3] gate, then CSR -> cred-release
// -> kubeconfig.
func Run(ctx context.Context, cfg Config) error {
	// Signed requests must always pass through the armTLS verifier. An HTTP
	// URL would bypass TLS entirely, even with VerifyConnection installed.
	if _, err := parseHTTPSURL("--release-url", cfg.ReleaseBaseURL); err != nil {
		return err
	}
	if _, err := parseHTTPSURL("--apiserver-url", cfg.APIServerURL); err != nil {
		return err
	}
	cfg.ReleaseBaseURL = strings.TrimRight(cfg.ReleaseBaseURL, "/")
	role, err := credrelease.ParseRole(cfg.Role)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(cfg.OperatorKeyPath)
	if err != nil {
		return fmt.Errorf("read operator key: %w", err)
	}
	pubPEM, err := publicKeyPEMFromPrivate(keyPEM)
	if err != nil {
		return fmt.Errorf("derive operator public key: %w", err)
	}
	exp, err := guestverify.PolicyFor(cfg.ImageManifestPath, pubPEM, cfg.WorkloadImages)
	if err != nil {
		return err
	}
	if exp.Family() == teetypes.FamilyTDX {
		exp = exp.WithMeasuredPolicies(nil)
	}

	// 1. Verify the channel and a fresh nonce-bound report before releasing
	// credentials. The certificate quote binds the TLS key, but may predate
	// later workload extends; it cannot replace the fresh report.
	httpClient := guestverify.NewClient(exp, cfg.Timeout)
	defer httpClient.CloseIdleConnections()
	err = retryRefused(ctx, cfg.Timeout, cfg.ReleaseWait, func(stepCtx context.Context) error {
		return attestCredentialRelease(stepCtx, httpClient, cfg.ReleaseBaseURL, keyPEM, exp)
	})
	if err != nil {
		return fmt.Errorf("attestation gate: %w", err)
	}

	// 2. Generate the kube-client identity + CSR.
	id, err := newClientIdentity()
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	csrPEM, err := id.csrPEM()
	if err != nil {
		return fmt.Errorf("build CSR: %w", err)
	}

	// 3. Exchange the CSR for a signed cert over cred-release. The :8443 dial
	//    is armTLS-verified in-process by the operator's own verifier
	//    (guestverify.NewClient): the serving cert's embedded quote must bind
	//    to the cert key AND satisfy the same full measured-identity policy as
	//    the attest gate, so the host can't MITM the channel.
	var resp *credrelease.ReleaseResponse
	err = retryRefused(ctx, cfg.Timeout, cfg.ReleaseWait, func(stepCtx context.Context) error {
		var requestErr error
		resp, requestErr = requestCredential(stepCtx, httpClient, cfg.ReleaseBaseURL, keyPEM, csrPEM, role)
		return requestErr
	})
	if err != nil {
		return fmt.Errorf("credential release: %w", err)
	}

	// 4. Assemble + write the kubeconfig.
	kc, err := buildKubeconfig(cfg.APIServerURL, cfg.ContextName, cfg.TLSServerName, []byte(resp.CertPEM), id.keyPEM, []byte(resp.CAPEM))
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}
	if err := os.WriteFile(cfg.OutPath, kc, 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (context %q, role %s) — attested: image tuple + operator-key chain verified\n", cfg.OutPath, cfg.ContextName, role)
	return nil
}

// parseHTTPSURL parses raw as an absolute HTTPS URL with a host and no
// userinfo, query or fragment. flag names the source in the error.
func parseHTTPSURL(flag, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTPS URL without userinfo, query or fragment", flag)
	}
	return u, nil
}

// publicKeyPEMFromPrivate derives the PKIX PEM public key from an ECDSA
// private key PEM. This MUST byte-match the pubkey the launcher put on the
// opkeydata disk (confai wrote `openssl ec -pubout`, which is PKIX PEM), or
// the RTMR[3] expected value won't match. Both use x509.MarshalPKIXPublicKey.
func publicKeyPEMFromPrivate(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("operator key is not PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("operator key is %T, want ECDSA", k)
		}
		key = ec
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// retryRefused retries each cred-release step; tests replace it.
var retryRefused = httputil.RetryConnectionRefused
