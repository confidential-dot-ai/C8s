package join

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// maxTokenRespBytes caps the /join response read. The token is a few
// hundred bytes; anything near the cap is malformed.
const maxTokenRespBytes = 64 << 10

// JoinConfig is the join client configuration.
type JoinConfig struct {
	// ServerAddr is the join-release endpoint as host:port (e.g. "10.0.0.5:8444").
	ServerAddr string
	// AttestationAPIURL is the local attestation-api base URL, used both for
	// this node's client-cert quote and for verifying the server's quote.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx" or "sev-snp").
	Platform string
	// MeasurementsConfig pins exactly one designated server image and operator key.
	MeasurementsConfig string
	// TokenOut is where the received token is written. Must be on a RAM-backed
	// filesystem, held open from verification through the atomic token write.
	TokenOut string
	// DocumentPath and SignaturePath are this agent's verified launch document
	// and signature as launched; the server reads the node name from them.
	DocumentPath  string
	SignaturePath string
	// NodePasswordOut is where RKE2 reads this node's password.
	NodePasswordOut string
	// MeasuredPoliciesFile is the node's measured-policy journal its client
	// certificate lists, so the server can replay RTMR[3]. Empty lists none.
	MeasuredPoliciesFile string
	// Timeout bounds each network step separately (cert
	// provisioning, handshake incl. peer verification, token fetch), so a slow
	// verifier cannot eat a later step's budget. Must be positive. One attempt
	// per invocation; retries belong to the systemd unit.
	Timeout time.Duration
}

// RunJoin verifies the designated server, presents this node's quote-bound
// client certificate, and stages the received agent token for rke2-agent.
func RunJoin(ctx context.Context, cfg JoinConfig) error {
	if cfg.Platform == "" {
		return fmt.Errorf("--platform is required (armTLS is mandatory for join)")
	}
	// A non-positive timeout expires every step's context before it starts.
	if cfg.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive (got %s)", cfg.Timeout)
	}
	if _, _, err := net.SplitHostPort(cfg.ServerAddr); err != nil {
		return fmt.Errorf("--server must be host:port: %w", err)
	}

	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.AttestationAPIURL); err != nil {
		return err
	}
	policy, err := loadPeerPolicy(cfg.MeasurementsConfig, cfg.Platform, cfg.AttestationAPIURL, cfg.Timeout, true)
	if err != nil {
		return err
	}
	if cfg.NodePasswordOut == "" {
		return fmt.Errorf("--node-password-out is required")
	}
	request, err := loadJoinRequest(cfg)
	if err != nil {
		return err
	}
	// Keep the checked RAM directory open through enrollment and the rename.
	// Replacing its pathname while the network call runs cannot redirect secrets.
	tokenRoot, err := prepareTokenDir(cfg.TokenOut)
	if err != nil {
		return err
	}
	defer tokenRoot.Close()

	// Client cert with an embedded quote bound to its own key: the server's
	// side of the mutual attestation.
	attestFunc := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		// Both connections below replace the in-handshake verifier this
		// policy installs: the probe captures the leaf for verifyPeer, and the
		// fetch accepts only that verified leaf.
		Policy:     policy.verify,
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		// The cert only has to survive this one exchange; the validity window
		// is the replay bound for a stolen leaf key, so keep it
		// as tight as clock skew allows.
		CertTTL: joinClientCertTTL,
		Logger:  slog.Default(),

		MeasuredPoliciesFile: cfg.MeasuredPoliciesFile,
	})
	if err != nil {
		return fmt.Errorf("build armTLS client config: %w", err)
	}
	warmCtx, cancelWarm := context.WithTimeout(ctx, cfg.Timeout)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("provision client cert: %w", err)
	}

	// Verify the server's quote with no connection open, then accept only that
	// exact certificate. Keeping the slow attestation-api call out of the
	// handshake lets join-release drop stalled handshakes after a short bound.
	leaf, err := probeServerCert(ctx, cfg, tlsCfg.Clone())
	if err != nil {
		return err
	}
	vctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	err = verifyPeer(vctx, leaf, policy)
	cancel()
	if err != nil {
		return err
	}
	fetchCfg := tlsCfg.Clone()
	fetchCfg.VerifyPeerCertificate = pinnedServerCert(leaf.Raw)
	resp, err := fetchToken(ctx, cfg, fetchCfg, request)
	if err != nil {
		return err
	}

	if err := writeStaged(cfg, tokenRoot, resp); err != nil {
		return err
	}
	slog.Info("joined: token staged", "server", cfg.ServerAddr, "token_file", cfg.TokenOut)
	return nil
}

// probeServerCert reads the server's leaf certificate and aborts the handshake
// before this node sends its own certificate. Nothing it returns is trusted
// until verifyPeer accepts it.
func probeServerCert(ctx context.Context, cfg JoinConfig, tlsCfg *tls.Config) (*x509.Certificate, error) {
	var raw []byte
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) > 0 {
			raw = rawCerts[0]
		}
		return errProbeDone
	}
	dctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: tlsCfg}).DialContext(dctx, "tcp", cfg.ServerAddr)
	if err == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("join: server certificate probe completed a handshake")
	}
	if !errors.Is(err, errProbeDone) {
		return nil, fmt.Errorf("fetch server certificate: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("join: server presented no certificate")
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("join: parse server cert: %w", err)
	}
	return leaf, nil
}

var errProbeDone = errors.New("server certificate captured")

// pinnedServerCert accepts only the leaf verifyPeer already accepted. The TLS
// handshake still proves the server holds that leaf's key; a certificate that
// rotated in between fails this attempt and the unit retries.
func pinnedServerCert(verified []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 || !bytes.Equal(rawCerts[0], verified) {
			return fmt.Errorf("join: server certificate changed after verification")
		}
		return nil
	}
}

// loadJoinRequest encodes this agent's signed launch document for the server.
func loadJoinRequest(cfg JoinConfig) ([]byte, error) {
	document, err := readBoundedFile(cfg.DocumentPath, launchconfig.MaxDocumentSize)
	if err != nil {
		return nil, fmt.Errorf("launch document: %w", err)
	}
	signature, err := readBoundedFile(cfg.SignaturePath, launchconfig.MaxSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("launch signature: %w", err)
	}
	return json.Marshal(joinRequest{Document: document, Signature: string(signature)})
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := readutil.ReadAll(f, limit)
	if errors.Is(err, readutil.ErrTooLarge) {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, err
}

// fetchToken performs the POST /join exchange over the mutually attested
// channel. The server certificate was verified beforehand, so the handshake
// does no attestation work and gets a single step's budget.
func fetchToken(ctx context.Context, cfg JoinConfig, tlsCfg *tls.Config, request []byte) (tokenResponse, error) {
	transport := &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: cfg.Timeout}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Timeout:   2 * cfg.Timeout, // handshake + request
		Transport: transport,
		// join-release never redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("join-release must not redirect")
		},
	}
	url := "https://" + cfg.ServerAddr + "/join"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("fetch join token: %w", err)
	}
	defer resp.Body.Close()

	body, err := readutil.ReadAll(resp.Body, maxTokenRespBytes)
	if err != nil {
		if errors.Is(err, readutil.ErrTooLarge) {
			return tokenResponse{}, fmt.Errorf("join-release response exceeds size limit")
		}
		return tokenResponse{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is server-controlled but the server is attested by now;
		// still, don't echo more than the status line needs.
		return tokenResponse{}, fmt.Errorf("join-release returned %s", resp.Status)
	}
	return decodeTokenResponse(body)
}

// Decode exactly the token and node password, in that order, in exactly one
// object; duplicate keys, unknown fields, trailing documents and malformed or
// privileged tokens are refused.
func decodeTokenResponse(body []byte) (tokenResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return tokenResponse{}, fmt.Errorf("join-release response must be a JSON object")
	}
	var out tokenResponse
	for _, field := range []struct {
		name string
		dst  *string
	}{{"token", &out.Token}, {"nodePassword", &out.NodePassword}} {
		if key, err := dec.Token(); err != nil || key != field.name {
			return tokenResponse{}, fmt.Errorf("join-release response requires %s", field.name)
		}
		if err := dec.Decode(field.dst); err != nil {
			return tokenResponse{}, fmt.Errorf("decode %s: %w", field.name, err)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return tokenResponse{}, fmt.Errorf("join-release response must contain only token and nodePassword")
	}
	if _, err := dec.Token(); err != io.EOF {
		return tokenResponse{}, fmt.Errorf("trailing data after join-release response")
	}
	if !isSecureAgentToken(out.Token) {
		return tokenResponse{}, fmt.Errorf("join-release returned an invalid agent token")
	}
	if !nodePasswordRE.MatchString(out.NodePassword) {
		return tokenResponse{}, fmt.Errorf("join-release returned an invalid node password")
	}
	return out, nil
}

var nodePasswordRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// prepareTokenDir creates TokenOut's directory and enforces that it is
// RAM-backed: the join token is a bearer secret and must never reach
// persistent storage, which the host reads at will.
func prepareTokenDir(path string) (*os.Root, error) {
	if path == "" || path != filepath.Clean(path) || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return nil, fmt.Errorf("--token-out must name a file")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	return cmdsutil.OpenRAMBackedDir("--token-out", dir)
}

// writeStaged replaces the token within the already verified RAM directory,
// then the node password where RKE2 reads it. Repeated enrollment replaces
// files atomically; partition/fetch failures write nothing. The rke2 config
// drop-in has a single owner in launch-config staging, so join writes only
// the credentials.
func writeStaged(cfg JoinConfig, tokenRoot *os.Root, resp tokenResponse) error {
	if err := fileutil.WriteAtomicRoot(tokenRoot, filepath.Base(cfg.TokenOut), []byte(resp.Token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.NodePasswordOut), 0o700); err != nil {
		return fmt.Errorf("create node password directory: %w", err)
	}
	if err := fileutil.WriteAtomic(cfg.NodePasswordOut, []byte(resp.NodePassword+"\n"), 0o600); err != nil {
		return fmt.Errorf("write node password: %w", err)
	}
	return nil
}
