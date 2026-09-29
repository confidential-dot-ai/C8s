package join

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	// maxConcurrentConns caps accepted sockets and protects the HTTP server
	// from connection-level resource exhaustion.
	maxConcurrentConns = 64
	// maxConcurrentVerifications independently caps expensive attestation-api
	// calls. A single HTTP/2 connection can carry many concurrent requests, so
	// the listener limit alone is not an admission bound.
	maxConcurrentVerifications = 64
)

// ReleaseConfig is the join-release service configuration.
type ReleaseConfig struct {
	// ListenAddr is the HTTPS bind address (e.g. ":8444").
	ListenAddr string
	// AttestationAPIURL is the local attestation-api base URL, used both for
	// the RA-TLS serving cert's quote and for verifying callers' quotes.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx" or "sev-snp").
	Platform string
	// MeasurementsConfig pins the authorized agent images and operator keys.
	MeasurementsConfig string
	// TokenPath is the agent-only rke2 join token file (the full-format
	// K10<ca-hash>::node:... token rke2-server writes once initialised).
	TokenPath string
	// VerifyTimeout bounds the per-request peer verification round trip to
	// the attestation-api.
	VerifyTimeout time.Duration
}

// RunRelease serves the RA-TLS-protected /join-token endpoint. It blocks
// until ctx is done.
//
// The authorization policy is loaded before binding the listener. Every request
// verifies a client certificate before reading either RKE2 credential file.
func RunRelease(ctx context.Context, cfg ReleaseConfig) error {
	return runRelease(ctx, cfg, nil)
}

// runRelease serves on ln when non-nil (test injection); nil binds
// cfg.ListenAddr after the attestation ladder, never before policy is pinned.
func runRelease(ctx context.Context, cfg ReleaseConfig, ln net.Listener) error {
	// RA-TLS is mandatory: joining agents verify this endpoint's serving
	// quote before presenting their own evidence, so a plain-TLS listener
	// (empty platform in the ratls package) must never come up.
	if cfg.Platform == "" {
		return fmt.Errorf("--platform is required (RA-TLS is mandatory for join release)")
	}
	// Non-positive: every request's verification context is already expired,
	// so the service comes up healthy and denies the entire cluster.
	if cfg.VerifyTimeout <= 0 {
		return fmt.Errorf("--verify-timeout must be positive (got %s)", cfg.VerifyTimeout)
	}

	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.AttestationAPIURL); err != nil {
		return err
	}

	policy, err := loadPeerPolicy(cfg.MeasurementsConfig, cfg.Platform, cfg.AttestationAPIURL, cfg.VerifyTimeout, false)
	if err != nil {
		return err
	}

	handler := &releaseHandler{
		policy:        policy,
		tokenPath:     cfg.TokenPath,
		verifyTimeout: cfg.VerifyTimeout,
		verifySlots:   make(chan struct{}, maxConcurrentVerifications),
		logger:        slog.Default(),
	}

	attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		// Short-lived serving cert: the validity window is the replay bound
		// for a stolen leaf key. Rotation is automatic.
		CertTTL: releaseServerCertTTL,
		Logger:  slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("build RA-TLS config: %w", err)
	}
	// Demand a client cert at the TLS layer; verification lives in the
	// handler (verifyPeer) so the whole policy is one auditable path rather
	// than split between a TLS callback and the handler.
	tlsCfg.ClientAuth = tls.RequireAnyClientCert

	warmCtx, cancelWarm := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up RA-TLS serving cert: %w", err)
	}

	if ln == nil {
		var lnErr error
		ln, lnErr = net.Listen("tcp", cfg.ListenAddr)
		if lnErr != nil {
			return fmt.Errorf("listen %s: %w", cfg.ListenAddr, lnErr)
		}
	}

	srv := newReleaseServer(handler, tlsCfg, cfg.VerifyTimeout)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeTLS(netutil.LimitListener(ln, maxConcurrentConns), "", "")
	}()

	select {
	case <-ctx.Done():
		cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)
		return nil
	case err := <-errCh:
		return err
	}
}

// handshakeTimeout bounds how long an unauthenticated connection may hold one
// of the listener's slots before sending its request. Agents verify this
// server's quote before connecting, so their handshake does no slow work.
const handshakeTimeout = 10 * time.Second

// newReleaseServer bounds every phase by what the exchange legitimately needs.
// net/http cuts the TLS handshake at the smaller of ReadHeaderTimeout and
// WriteTimeout, and restarts WriteTimeout once the request headers are read,
// so that deadline must also cover the handler's own peer verification.
func newReleaseServer(handler http.Handler, tlsCfg *tls.Config, verifyTimeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: handshakeTimeout,
		// A slow reader or parked keep-alive must not hold a goroutine open.
		WriteTimeout:   handshakeTimeout + verifyTimeout,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}

// tokenResponse is the /join-token response body.
type tokenResponse struct {
	Token string `json:"token"`
}

type releaseHandler struct {
	policy        peerPolicy
	tokenPath     string
	verifyTimeout time.Duration
	verifySlots   chan struct{}
	logger        *slog.Logger
}

func (h *releaseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/join-token" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// RequireAnyClientCert makes this unreachable over TLS; kept so a
		// misconfigured server can never release without evidence.
		h.logger.Warn("join denied: no client certificate", "remote", r.RemoteAddr)
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}

	select {
	case h.verifySlots <- struct{}{}:
		defer func() { <-h.verifySlots }()
	default:
		h.logger.Warn("join delayed: verification capacity exhausted", "remote", r.RemoteAddr)
		http.Error(w, "join verification busy", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.verifyTimeout)
	defer cancel()
	if err := verifyPeer(ctx, r.TLS.PeerCertificates[0], h.policy); err != nil {
		h.logger.Warn("join denied", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "join denied", http.StatusForbidden)
		return
	}

	// Read per request, no caching: the file appears only once rke2-server
	// has initialised, and agents retry on 503 until then.
	token, err := readAgentToken(h.tokenPath)
	if err != nil {
		h.logger.Warn("join token not ready", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "join token not ready", http.StatusServiceUnavailable)
		return
	}

	h.logger.Info("join token released", "remote", r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse{Token: token}); err != nil {
		h.logger.Warn("write response", "remote", r.RemoteAddr, "err", err)
	}
}

// readAgentToken also reads the conventional companion privileged token. RKE2
// defaults agent-token to an alias of token unless a separate agent secret was
// configured. Comparing secrets catches that alias even if its role is rewritten.
func readAgentToken(path string) (string, error) {
	token, err := readTokenFile(path)
	if err != nil {
		return "", err
	}
	ca, user, secret, ok := secureTokenParts(token)
	if !ok || user != "node" {
		return "", fmt.Errorf("agent token has invalid format or role")
	}
	server, err := readTokenFile(filepath.Join(filepath.Dir(path), "token"))
	if err != nil {
		return "", fmt.Errorf("privileged token unavailable: %w", err)
	}
	serverCA, serverUser, serverSecret, ok := secureTokenParts(server)
	if !ok || serverUser != "server" || serverCA != ca {
		return "", fmt.Errorf("privileged token has invalid format or CA pin")
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(serverSecret)) == 1 {
		return "", fmt.Errorf("agent token aliases privileged server credential")
	}
	return token, nil
}

func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := readutil.ReadAll(f, maxTokenRespBytes)
	if err != nil {
		if errors.Is(err, readutil.ErrTooLarge) {
			return "", fmt.Errorf("token file exceeds size limit")
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func isSecureAgentToken(token string) bool {
	_, user, _, ok := secureTokenParts(token)
	return ok && user == "node"
}

func secureTokenParts(token string) (ca, user, secret string, ok bool) {
	ca, credentials, found := strings.Cut(token, "::")
	if !found || !strings.HasPrefix(ca, "K10") || len(ca) != 3+2*sha256.Size {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(ca[3:]); err != nil {
		return "", "", "", false
	}
	user, secret, found = strings.Cut(credentials, ":")
	if !found || secret == "" || strings.ContainsRune(secret, ':') {
		return "", "", "", false
	}
	for _, c := range secret {
		if c < '!' || c > '~' {
			return "", "", "", false
		}
	}
	return ca, user, secret, true
}
