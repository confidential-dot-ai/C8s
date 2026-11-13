package podstatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// AttestConfig configures the client.
type AttestConfig struct {
	Node              string
	LaunchKeyPubPath  string
	ImageManifestPath string
	ExpectDigests     []string
	Timeout           time.Duration
}

// Report is what Attest proves about the pod CVM.
type Report struct {
	Image           string   `json:"image"`
	LaunchKeySHA256 string   `json:"launch_key_sha256"`
	MeasuredDigests []string `json:"measured_digests"`
	RTMR3           string   `json:"rtmr3,omitempty"`
}

// Seams for tests.
var (
	newClient   = guestverify.NewClient
	verifyFresh = guestverify.VerifyEvidence
)

// Attest verifies fresh evidence from the pod CVM and its measured digest
// list, returning the report and the verified channel for further reads.
func Attest(ctx context.Context, cfg AttestConfig) (*Report, *http.Client, error) {
	a, err := newAttestation(cfg)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	client, firstDigests, err := a.openPinnedChannel(ctx, cfg.Timeout)
	if err != nil {
		return nil, nil, err
	}
	report, err := a.attestPinned(ctx, client, firstDigests)
	if err != nil {
		// The transport has no idle timeout, so a failed attestation must not
		// leave its sockets to the retry.
		client.CloseIdleConnections()
		return nil, nil, err
	}
	return report, client, nil
}

// attestation is what one Attest call checks the pod CVM against.
type attestation struct {
	base         string
	launchKeyPEM []byte
	// policy is the base policy; each check derives its own measured list
	// from it with WithMeasuredPolicies.
	policy guestverify.Policy
	// expectsDigests is set when the caller names the exact digest set,
	// which may be empty: no containers.
	expectsDigests bool
	expect         []string
}

func newAttestation(cfg AttestConfig) (attestation, error) {
	if err := cfg.validate(); err != nil {
		return attestation{}, err
	}
	expect, err := canonicalDigests(cfg.ExpectDigests)
	if err != nil {
		return attestation{}, fmt.Errorf("cfg.ExpectDigests: %w", err)
	}
	launchKeyPEM, err := os.ReadFile(cfg.LaunchKeyPubPath)
	if err != nil {
		return attestation{}, fmt.Errorf("launch key: %w", err)
	}
	// One gate for the channel and the evidence: the image the manifest pins
	// and the launch key, bound as every c8s verifier binds a node's. The
	// channel replays the list the serving certificate carries as a prefix
	// of the register; the fresh evidence replays the list read from the
	// guest.
	policy, err := guestverify.PolicyFor(cfg.ImageManifestPath, launchKeyPEM, nil)
	if err != nil {
		return attestation{}, err
	}
	return attestation{
		base:           "https://" + hostPort(cfg.Node),
		launchKeyPEM:   launchKeyPEM,
		policy:         policy.WithMeasuredPolicies(nil),
		expectsDigests: cfg.ExpectDigests != nil,
		expect:         expect,
	}, nil
}

func (cfg AttestConfig) validate() error {
	if cfg.Node == "" || cfg.LaunchKeyPubPath == "" || cfg.ImageManifestPath == "" {
		return errors.New("cfg.Node, cfg.LaunchKeyPubPath and cfg.ImageManifestPath are required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("cfg.Timeout must be positive")
	}
	if strings.ContainsAny(cfg.Node, "/?#@") {
		return fmt.Errorf("cfg.Node must be a host or IP, got %q", cfg.Node)
	}
	return nil
}

func canonicalDigests(refs []string) ([]string, error) {
	digests := make([]string, 0, len(refs))
	for _, ref := range refs {
		d, err := runtimemeasure.CanonicalDigest(ref)
		if err != nil {
			return nil, err
		}
		digests = append(digests, d)
	}
	return digests, nil
}

// openPinnedChannel reads the measured digests once and returns a client
// pinned to the key that served them.
//
// The first answer fixes the serving key: every connection after it, here
// and over the returned client, must present that key. Otherwise a host
// could answer the later reads from another pod CVM launched with the same
// launch key, whose certificate passes the same checks.
func (a attestation) openPinnedChannel(
	ctx context.Context,
	requestTimeout time.Duration,
) (*http.Client, []string, error) {
	unpinned := newClient(a.policy, requestTimeout)
	defer unpinned.CloseIdleConnections()
	digests, peer, err := fetchDigests(ctx, unpinned, a.base)
	if err != nil {
		return nil, nil, err
	}
	pinned, err := pinServingKey(unpinned, peer)
	if err != nil {
		return nil, nil, err
	}
	return pinned, digests, nil
}

func (a attestation) attestPinned(
	ctx context.Context,
	client *http.Client,
	firstDigests []string,
) (*Report, error) {
	quoted, err := a.quoteWithStableDigests(ctx, client, firstDigests)
	if err != nil {
		return nil, err
	}
	res, err := a.verify(quoted)
	if err != nil {
		return nil, err
	}
	if err := a.checkExpected(quoted.digests); err != nil {
		return nil, err
	}
	return a.report(res, quoted.digests)
}

// quotedEvidence is a fresh quote and the measured digest list read on both
// sides of it.
type quotedEvidence struct {
	envelope []byte
	// wantReportData binds the channel's certificate key and the nonce.
	wantReportData [64]byte
	digests        []string
}

const maxQuoteAttempts = 3

// quoteWithStableDigests quotes until the digest list reads the same before
// and after the quote: a container may start in between.
func (a attestation) quoteWithStableDigests(
	ctx context.Context,
	client *http.Client,
	digestsBeforeQuote []string,
) (quotedEvidence, error) {
	for range maxQuoteAttempts {
		envelope, wantReportData, err := a.quote(ctx, client)
		if err != nil {
			return quotedEvidence{}, err
		}
		digestsAfterQuote, _, err := fetchDigests(ctx, client, a.base)
		if err != nil {
			return quotedEvidence{}, err
		}
		if slices.Equal(digestsBeforeQuote, digestsAfterQuote) {
			return quotedEvidence{
				envelope:       envelope,
				wantReportData: wantReportData,
				digests:        digestsAfterQuote,
			}, nil
		}
		// The next quote is taken after this read.
		digestsBeforeQuote = digestsAfterQuote
	}
	return quotedEvidence{}, errors.New("measured digests kept changing during attestation; retry")
}

// quote asks for evidence over a fresh nonce, and returns it with the report
// data it must carry: this channel's certificate key and the nonce.
func (a attestation) quote(
	ctx context.Context,
	client *http.Client,
) (envelope []byte, wantReportData [64]byte, err error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, [64]byte{}, err
	}
	reqBody, _ := json.Marshal(types.NonceRequest{Nonce: nonce})
	envelope, peer, err := postEvidence(ctx, client, a.base, reqBody)
	if err != nil {
		return nil, [64]byte{}, fmt.Errorf("fresh evidence: %w", err)
	}
	wantReportData, err = EvidenceReportData(peer, nonce)
	if err != nil {
		return nil, [64]byte{}, err
	}
	return envelope, wantReportData, nil
}

func (a attestation) verify(quoted quotedEvidence) (*teetypes.VerificationResult, error) {
	res, err := verifyFresh(quoted.envelope, quoted.wantReportData[:], a.policy.WithMeasuredPolicies(quoted.digests))
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	// The gate accepts any replaying prefix; here the list was read on both
	// sides of the quote and agreed, so the whole of it must replay. A list
	// that ran ahead of the register fails here and only here: that is a
	// recorded extend the guest has not made yet.
	if err := runtimemeasure.VerifyBinding(res, a.launchKeyPEM, quoted.digests); err != nil {
		return nil, fmt.Errorf("measured digests do not explain the attested register: %w", err)
	}
	return res, nil
}

func (a attestation) checkExpected(digests []string) error {
	if a.expectsDigests && !sameSet(a.expect, digests) {
		return fmt.Errorf("measured digests %v, expected %v", digests, a.expect)
	}
	return nil
}

func (a attestation) report(res *teetypes.VerificationResult, digests []string) (*Report, error) {
	sum := sha256.Sum256(a.launchKeyPEM)
	report := &Report{
		Image:           res.Claims.LaunchDigest,
		LaunchKeySHA256: hex.EncodeToString(sum[:]),
		MeasuredDigests: digests,
	}
	if res.Platform.HasRegisters() {
		reg, err := runtimemeasure.Binding(res)
		if err != nil {
			return nil, err
		}
		report.RTMR3 = hex.EncodeToString(reg)
	}
	return report, nil
}

// pinServingKey returns a client, on a clone of client's transport, that
// accepts only connections served with peer, before the checks client
// already makes. Every pod CVM launched with
// one launch key presents a certificate that passes those checks; the pin
// tells the attested one apart.
func pinServingKey(client *http.Client, peer crypto.PublicKey) (*http.Client, error) {
	want, err := x509.MarshalPKIXPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("pin serving key: %w", err)
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("pin serving key: the attested client has no TLS transport")
	}
	tr := base.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	verify := tr.TLSClientConfig.VerifyConnection
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server presented no certificate")
		}
		got, err := x509.MarshalPKIXPublicKey(cs.PeerCertificates[0].PublicKey)
		if err != nil || !bytes.Equal(got, want) {
			return errors.New("serving key differs from the attested one: another guest answered")
		}
		if verify != nil {
			return verify(cs)
		}
		return nil
	}
	return &http.Client{Timeout: client.Timeout, CheckRedirect: client.CheckRedirect, Transport: tr}, nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// fetchDigests also returns the key of the certificate that served the list.
func fetchDigests(ctx context.Context, client *http.Client, base string) ([]string, crypto.PublicKey, error) {
	body, peer, _, err := doPeer(ctx, client, http.MethodGet, base+MeasurementsPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("measurements: %w", err)
	}
	var m Measurements
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, fmt.Errorf("measurements: %w", err)
	}
	return m.Digests, peer, nil
}

func postEvidence(ctx context.Context, client *http.Client, base string, reqBody []byte) ([]byte, crypto.PublicKey, error) {
	body, peer, binding, err := doPeer(ctx, client, http.MethodPost, base+EvidencePath, reqBody)
	if err != nil {
		return nil, nil, err
	}
	if binding != BindingVersion {
		return nil, nil, fmt.Errorf("guest evidence binding is %q, this client needs %q: guest and client c8s are different builds", binding, BindingVersion)
	}
	return body, peer, nil
}

// doPeer also returns the public key of the certificate the server
// presented on the connection that carried this request.
func doPeer(ctx context.Context, client *http.Client, method, url string, body []byte) ([]byte, crypto.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("attested request (image or channel not verified): %w", err)
	}
	defer resp.Body.Close()
	data, err := readutil.ReadAll(resp.Body, maxBody)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is peer-controlled; keep only its head in the error.
		const maxErrBody = 512
		msg := strings.TrimSpace(string(data))
		if len(msg) > maxErrBody {
			msg = msg[:maxErrBody] + "..."
		}
		return nil, nil, "", fmt.Errorf("%s: %s", resp.Status, msg)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, nil, "", errors.New("response did not arrive over TLS")
	}
	return data, resp.TLS.PeerCertificates[0].PublicKey, resp.Header.Get(BindingHeader), nil
}

func hostPort(node string) string {
	if _, _, err := net.SplitHostPort(node); err == nil {
		return node
	}
	return net.JoinHostPort(strings.Trim(node, "[]"), "8443")
}
