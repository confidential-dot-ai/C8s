package getkubeconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// newARMTLSClient builds an HTTP client whose :8443 dial is verified with the
// operator's OWN in-process verifier (attestation-go), with no trust in the
// guest's attestation-api and not TOFU. The cred-release serving cert embeds a
// fresh TDX quote bound to the cert's public key (armtls.ReportDataForKey);
// verifyServerCert extracts it, asserts the quote covers this exact cert key,
// and enforces the same full measured-identity policy as the attest gate. A
// host MITM can't forge that quote, so a successful handshake proves the
// channel terminates inside the measured, operator-key-bound guest.
//
// Go's own chain/hostname verification is disabled (InsecureSkipVerify): the
// serving cert is self-signed and carries no SAN for the per-launch IP. armTLS
// replaces it — the quote binding is strictly stronger than a CA chain here.
func newARMTLSClient(cfg Config, exp platformVerifier) *http.Client {
	return &http.Client{
		Timeout: cfg.Timeout,
		// Never move signed bootstrap requests onto another endpoint or HTTP.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // armTLS in VerifyConnection is the real check
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("armtls: server presented no certificate")
					}
					return verifyServerCert(cs.PeerCertificates[0], exp)
				},
			},
		},
	}
}

// verifyServerCert runs the armTLS check on the :8443 leaf cert: it
// authenticates the certificate body itself (validity within the shared skew
// bound; the self-signature under the cert's own key — the quote binds only
// the key, so without that check any other body field could be rewritten),
// then pulls the embedded TDX quote, binds it to the cert's own public key,
// verifies it in-process with attestation-go (HW chain + report_data
// binding), and enforces the full measured-identity policy — identical to the
// attest gate. Fails closed on any missing piece.
func verifyServerCert(leaf *x509.Certificate, exp platformVerifier) error {
	// This leaf is self-signed by construction (newARMTLSClient's doc comment:
	// there is no CA on this path at all), so the classification must come
	// back BodySelfSigned. Assert it rather than discard it: a CA-vouched
	// result here means the presented cert was issued by something, and
	// nothing in this flow would check that issuer — the body would ride in
	// unauthenticated under a genuine quote.
	body, err := certutil.AuthenticateLeafBody(leaf, time.Now())
	if err != nil {
		return fmt.Errorf("armtls: %w", err)
	}
	if body != certutil.BodySelfSigned {
		return fmt.Errorf("armtls: cred-release serving cert is not self-signed (issuer != subject), so its body is authenticated by nothing this flow checks; the armTLS leaf must carry its own signature under the attested key")
	}
	return exp.verifyCertificate(leaf)
}

// verifyCertificate routes to the arm the manifest's family names. An unknown
// family cannot reach here — policyFor refuses one — but the default fails
// closed rather than falling through to another family's rules.
func (exp measuredPolicy) verifyCertificate(leaf *x509.Certificate) error {
	switch exp.identity.Family() {
	case teetypes.FamilySNP:
		return exp.verifySNPCertificate(leaf)
	case teetypes.FamilyTDX:
		return exp.verifyTDXCertificate(leaf)
	default:
		return fmt.Errorf("armtls: --image-manifest pins TEE family %q, which this flow has no gate for", exp.identity.Family())
	}
}

func (exp measuredPolicy) verifyTDXCertificate(leaf *x509.Certificate) error {
	att, err := armtls.ExtractAttestation(leaf)
	if err != nil {
		return fmt.Errorf("armtls: %w", err)
	}
	evidence, ok := att.EmbeddedEvidence()
	if !ok {
		// TDX always carries a JSON envelope in the armTLS extension; its
		// absence means the cert isn't a genuine TDX armTLS cert.
		return fmt.Errorf("armtls: server cert carries no TDX attestation envelope")
	}

	// The quote's report_data must be SHA-384(cert pubkey) — this is what ties
	// the attested guest to THIS TLS channel. The 64-byte ReportDataForKey
	// output (48-byte hash + zero tail) matches the quote's report_data field
	// exactly.
	rd, err := armtls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("armtls: compute expected report_data: %w", err)
	}

	envJSON, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("armtls: marshal embedded evidence: %w", err)
	}

	// Reuse the exact verifier the attest gate uses — one funnel, one policy.
	if _, err := verifyEvidence(envJSON, rd[:], exp); err != nil {
		return fmt.Errorf("armtls: %w", err)
	}
	return nil
}

// verifySNPARMTLS is localverify.Verify; a package var so tests can stub the
// verdict without AMD KDS.
var verifySNPARMTLS localverify.VerifyFunc = localverify.Verify

// snpARMTLSTimeout bounds the dial-time verification, whose collateral fetch
// (VCEK from AMD KDS) crosses the network. VerifyConnection has no context.
const snpARMTLSTimeout = 30 * time.Second

// verifySNPCertificate verifies an SNP serving certificate: it enforces the SAME two
// pins as the attest gate — the launch digest must be one of the manifest's
// per-SMP variants, and HOSTDATA must equal the operator-key binding — over
// evidence extracted from a bare-metal SNP armTLS cert (a raw report, no
// inline VCEK; localverify fetches it from AMD KDS).
//
// The REPORTDATA anchor is the cert's own key hash, so a captured quote from
// another guest cannot be replayed onto this channel.
func (exp measuredPolicy) verifySNPCertificate(leaf *x509.Certificate) error {
	platform, evidence, expectedReportData, err := localverify.CertEnvelope(leaf)
	if err != nil {
		return fmt.Errorf("armtls: %w", err)
	}
	// Bare-metal snp only: on az-snp/gcp-snp the HOSTDATA field is owned by
	// the cloud stack, so it cannot carry the operator-key binding.
	if platform != string(teetypes.PlatformSNP) {
		return fmt.Errorf("armtls: serving cert platform is %q: the SNP trust gate pins launch-time HOSTDATA, which only bare-metal snp launches carry as the operator-key binding", platform)
	}

	ctx, cancel := context.WithTimeout(context.Background(), snpARMTLSTimeout)
	defer cancel()
	res, err := verifySNPARMTLS(ctx, platform, evidence, exp.verificationParams(expectedReportData))
	if err != nil {
		return fmt.Errorf("armtls: verify serving cert evidence: %w", err)
	}
	// Defense in depth: never accept a success the claims contradict. The
	// engine already enforced both pins, but re-check them over the returned
	// claims with the same helper the attest gate uses.
	if !res.SignatureValid {
		return fmt.Errorf("armtls: quote signature invalid")
	}
	if err := exp.checkIdentity(res); err != nil {
		return fmt.Errorf("armtls: %w", err)
	}
	return nil
}
