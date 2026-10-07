// Package getcert implements the get-cert subcommand: it requests a TLS
// certificate from CDS by proving the caller runs inside a TEE.
package getcert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// config holds all CLI configuration for get-cert.
type config struct {
	CDSURL                 string
	CDSMeasurements        string
	CDSRTMRs               string
	MeasurementsConfig     string
	MeasurementsConfigJSON string
	AttestationApiURL      string
	CertPath               string
	CAPath                 string
	KeyPath                string
	SAN                    string
	SANFile                string
	NoSAN                  bool
	Verbose                bool
	RenewInterval          time.Duration
	RenewJitterPercent     int
	InitialRetryTimeout    time.Duration
	InitialRetryInterval   time.Duration
	ReloadNginx            bool
	ContinueOnInitialError bool
	ReloadWatchPaths       []string
	ReloadWatchInterval    time.Duration
	CAWatchInterval        time.Duration
	DiscoveryOutPath       string
	DiscoveryCDSCertURL    string
	DiscoveryMeshCAURL     string
	DiscoveryPublicTLSMode string
	WorkloadClaimsTimeout  time.Duration
	NoWorkloadClaims       bool
	UnnamedRenewInterval   time.Duration
}

// nodeInventory is the local inventory get-cert redeems its workload identity
// assertion at: the compiled socket endpoint and the mount that carries it. It
// is a package variable only so tests can point it at a temporary socket; the
// production endpoint is a baked path the control plane cannot redirect.
var nodeInventory = inventory{
	endpoint:     workloadclaims.InventoryEndpoint,
	requireMount: workloadclaims.RequireSidecarSocketDir,
}

type inventory struct {
	endpoint     func() string
	requireMount func() error
}

// procRoot is the procfs mount used to find nginx; tests substitute a fake tree.
var procRoot = "/proc"

var (
	errInvalidDiscoveryPublicTLSMode             = errors.New("invalid discovery public TLS mode")
	errInvalidCAWatchInterval                    = errors.New("invalid CA watch interval")
	errInvalidReloadWatchInterval                = errors.New("invalid reload watch interval")
	errInvalidUnnamedRenewInterval               = errors.New("invalid unnamed renew interval")
	errInvalidRenewJitterPercent                 = errors.New("invalid renew jitter percent")
	errReloadWatchRequiresRenewInterval          = errors.New("reload watch requires renew interval")
	errContinueOnInitialErrorRequiresRenewalLoop = errors.New("continue on initial error requires renewal loop")
)

// NewCmd returns the cobra subcommand. It is registered as a child of
// `c8s` and as the root command of the standalone binary.
func NewCmd() *cobra.Command {
	var cfg config

	cmd := &cobra.Command{
		Use:   "get-cert",
		Short: "Obtain a signed certificate via the CDS attestation flow",
		Long: `get-cert requests a TLS certificate from the Certificate Distribution Service (CDS)
by proving it is running in a Trusted Execution Environment (TEE).

It generates an ECDSA P-256 key pair in memory for every certificate it
requests, creates a CSR with the selected SAN (Subject Alternative Name), and
uses the CDS attestation flow to obtain a signed certificate. The P-384 keypair used elsewhere in c8s is limited
to mesh CA rotation; get-cert leaf keys stay P-256.

The leaf, key and CA are published as one generation on the pod's private
credential volume and validated before publication; the paths named by
--cert-path, --key-path and --ca-path always resolve to one complete generation,
or to nothing while none is published.

This tool is designed to run as a native sidecar alongside the credential
consumers that read that volume.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging(cfg.Verbose)
			return run(cfg)
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	cmdsutil.BindImagePolicyFlags(flags, &cfg.MeasurementsConfig, &cfg.MeasurementsConfigJSON, "", "pins the CDS endpoint; excludes --cds-measurements and --cds-rtmrs")
	flags.StringVar(&cfg.CDSURL, "cds-url", "", "URL of the CDS service (e.g. https://cds:8443)")
	flags.StringVar(&cfg.CDSMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch measurements for CDS armTLS verification (empty = accept any attested CDS)")
	flags.StringVar(&cfg.CDSRTMRs, "cds-rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex> CDS's armTLS cert must additionally satisfy; ignored when CDS presents SNP evidence (empty = launch-digest pinning only)")
	flags.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "URL of the node-local attestation-api (http://localhost:8400, or unix:// plus the on-node socket path the chart wires)")
	flags.StringVar(&cfg.CertPath, "cert-path", "", "Path where the certificate chain PEM of the published generation is read")
	flags.StringVar(&cfg.CAPath, "ca-path", "", "Path where the mesh CA PEM of the published generation is read; must be in the --cert-path directory")
	flags.StringVar(&cfg.KeyPath, "key-path", "", "Path where the private key PEM of the published generation is read, mode 0600 (0640 in shared setgid directories); must be in the --cert-path directory, on a memory-backed filesystem")
	flags.StringVar(&cfg.SAN, "san", "", "Subject Alternative Name for the certificate (IP address or hostname)")
	flags.StringVar(&cfg.SANFile, "san-file", "", "Path to a file containing the certificate SAN")
	flags.BoolVar(&cfg.NoSAN, "no-san", false, "Request a certificate with no SAN, for a pod without confidential.ai/cw; CDS takes the subject from the verified workload identity instead")
	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable debug logging")
	flags.DurationVar(&cfg.RenewInterval, "renew-interval", 0, "Re-obtain the certificate at this interval (0 = run once and exit)")
	flags.IntVar(&cfg.RenewJitterPercent, "renew-jitter-percent", defaultRenewJitterPercent, "Shorten each renewal delay by a random fraction of itself, up to this percent, so certificates issued together do not refresh in lockstep (0 = no jitter)")
	flags.DurationVar(&cfg.InitialRetryTimeout, "initial-retry-timeout", 2*time.Minute, "Retry the first certificate request in-process for up to this long before failing, so a transient CDS/mesh outage during a roll does not crash the init container into kubelet backoff (0 = try once)")
	flags.DurationVar(&cfg.InitialRetryInterval, "initial-retry-interval", 2*time.Second, "Delay between in-process retries of the first certificate request")
	flags.BoolVar(&cfg.ReloadNginx, "reload-nginx", true, "SIGHUP nginx after certificate renewal or watched file changes")
	flags.BoolVar(&cfg.ContinueOnInitialError, "continue-on-initial-error", false, "In renewal mode, keep running when the first certificate request fails, retrying on a capped backoff until a certificate is issued")
	flags.StringArrayVar(&cfg.ReloadWatchPaths, "reload-watch", nil, "File path to poll for changes and reload nginx when it changes (repeatable)")
	flags.DurationVar(&cfg.ReloadWatchInterval, "reload-watch-interval", time.Minute, "Poll interval for --reload-watch paths")
	flags.DurationVar(&cfg.CAWatchInterval, "ca-watch-interval", 0, "Poll CDS's /ca at this interval and renew immediately when the published CA is not the CA CDS currently holds. A CDS restart regenerates the mesh CA in-memory, so without this the pod serves the dead CA until the next scheduled renewal (0 = disabled; requires --renew-interval)")
	flags.StringVar(&cfg.DiscoveryOutPath, "discovery-out", "", "Path to write JSON discovery metadata for the issued certificate and attestation evidence")
	flags.StringVar(&cfg.DiscoveryCDSCertURL, "discovery-cds-cert-url", "", "Public URL path where the CDS certificate PEM is served")
	flags.StringVar(&cfg.DiscoveryMeshCAURL, "discovery-mesh-ca-url", "", "Public URL path where the mesh CA PEM is served")
	flags.StringVar(&cfg.DiscoveryPublicTLSMode, "discovery-public-tls-mode", "cds", "Public TLS mode to report in discovery metadata (cds, webpki, or acme)")
	flags.DurationVar(&cfg.WorkloadClaimsTimeout, "workload-claims-timeout", 5*time.Second, "Timeout for the admission inventory request")
	flags.BoolVar(&cfg.NoWorkloadClaims, "no-workload-claims", false, "Request certificates without a workload identity assertion, for a pod whose node runs no admission inventory. The leaf then carries no workload instance, so nothing binds it to this pod's sandbox; injected workloads never set it")
	flags.DurationVar(&cfg.UnnamedRenewInterval, "unnamed-renew-interval", 30*time.Second, "With --renew-interval, renew while the installed leaf carries no matched-workload stamp at most this far apart (plus jitter), starting at 2s and doubling, so a pod picks up its name at the first post-completion renewal instead of waiting a full interval; settles to --renew-interval once named, and backs off toward it for a pod that stays unnamed. Poll timing never changes the match decision. 0 disables the fast poll")

	for _, name := range []string{"cds-url", "attestation-api-url", "cert-path", "key-path", "ca-path"} {
		_ = cmd.MarkFlagRequired(name)
	}
	cmd.MarkFlagsOneRequired("san", "san-file", "no-san")
	cmd.MarkFlagsMutuallyExclusive("san", "san-file", "no-san")

	return cmd
}

func setupLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func newCDSClient(cfg config) (attestclient.Client, error) {
	httpClient, err := cdsHTTPClient(cfg)
	if err != nil {
		var zero attestclient.Client
		return zero, err
	}
	return attestclient.NewClientWithHTTP(cfg.CDSURL, httpClient), nil
}

func cdsHTTPClient(cfg config) (*http.Client, error) {
	parsed, err := url.Parse(cfg.CDSURL)
	if err != nil {
		return nil, fmt.Errorf("--cds-url: %w", err)
	}
	// CDS is reached over armTLS: the scheme MUST be https so the client
	// verifies CDS's TEE attestation. A plaintext http:// URL would fall back
	// to a client that skips attestation entirely and impersonation by any
	// on-path peer becomes trivial. The chart only ever renders https URLs, so
	// a non-https value is a misconfiguration, not a supported mode.
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("--cds-url must use https (armTLS); got scheme %q", parsed.Scheme)
	}

	pins, err := cdsPins(cfg)
	if err != nil {
		return nil, err
	}
	client, err := armtls.NewVerifyingHTTPClient(pins, cfg.AttestationApiURL)
	if err != nil {
		return nil, fmt.Errorf("cds armTLS client: %w", err)
	}
	return client, nil
}

func cdsPins(cfg config) (armtls.Pins, error) {
	policy, err := (cmdsutil.ImagePolicySource{File: cfg.MeasurementsConfig, JSON: cfg.MeasurementsConfigJSON}).Load(
		cmdsutil.MeasurementPinsFromStrings(cfg.CDSMeasurements, cfg.CDSRTMRs, "cds-"))
	if err != nil {
		return armtls.Pins{}, err
	}
	cmdsutil.WarnIfCDSUnpinned(len(policy.Measurements)+len(policy.Images), "--cds-measurements not set; get-cert accepts any armTLS-attested CDS measurement")
	return armtls.Pins(policy), nil
}

// obtainCertFn is a var so renewal-loop tests can observe attempts.
var obtainCertFn = obtainCert

func run(cfg config) error {
	san, err := resolveSAN(cfg)
	if err != nil {
		return err
	}
	cfg.SAN = san
	slog.Info("starting get-cert", "san", cfg.SAN)

	if err := validateConfig(cfg); err != nil {
		return err
	}
	volume, err := credentialVolumeFor(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
	if err != nil {
		return err
	}
	// One directory holds the whole generation, so one writability check and
	// one memory-backing check cover it.
	if err := validateOutputPaths(cfg.CertPath, cfg.DiscoveryOutPath); err != nil {
		return err
	}
	// The key is published in this directory, so it must never reach
	// persistent storage.
	if err := cmdsutil.RequireRAMBackedDir("--key-path", volume.dir); err != nil {
		return err
	}
	slog.Debug("credential volume validated")

	client, err := newCDSClient(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	creds, err := resumeCredentials(ctx, cfg, volume)
	if err != nil {
		return err
	}

	if err := obtainCertWithRetry(ctx, cfg, client, creds); err != nil {
		if cfg.RenewInterval <= 0 || !cfg.ContinueOnInitialError {
			return err
		}
		slog.Error("initial certificate request failed, will keep retrying", "error", err)
	} else if cfg.RenewInterval <= 0 {
		return nil
	}
	return renewLoop(ctx, cfg, client, creds)
}

// resumeCredentials is the pod's state before anything is requested: the
// workload instance its node inventory asserts, and the generation and issuer
// its volume already holds. Both must hold for a request to be made at all.
func resumeCredentials(ctx context.Context, cfg config, volume credentialVolume) (*credentials, error) {
	instanceID, err := workloadInstance(ctx, cfg)
	if err != nil {
		return nil, err
	}
	creds, err := loadCredentials(volume, instanceID)
	if err != nil {
		return nil, err
	}
	if err := creds.adoptStoredGeneration(time.Now()); err != nil {
		return nil, err
	}
	return creds, nil
}

// workloadInstance is the instance this pod's credentials are bound to: the one
// its node inventory asserts, or none under --no-workload-claims, where the
// leaf must carry none either (requireInstanceID holds either way).
func workloadInstance(ctx context.Context, cfg config) (string, error) {
	if cfg.NoWorkloadClaims {
		slog.Warn("requesting certificates with no workload identity assertion (--no-workload-claims)")
		return "", nil
	}
	// Fail fast, never retry: a missing socket directory means the mount was
	// not injected at container creation and no in-process wait can produce
	// it, while the retry loop would idle forever behind
	// --continue-on-initial-error (see workloadclaims.RequireSidecarSocketDir).
	if err := nodeInventory.requireMount(); err != nil {
		return "", err
	}
	instanceID, err := assertedInstanceID(ctx, cfg)
	if err != nil {
		return "", err
	}
	slog.Info("workload instance asserted", "instance_id", instanceID)
	return instanceID, nil
}

// assertedInstanceID is the workload instance the node inventory names for this
// pod, which every leaf get-cert publishes must carry. Without an assertion
// get-cert has no identity to check a certificate against, so it requests
// nothing.
func assertedInstanceID(ctx context.Context, cfg config) (string, error) {
	// This token is read locally and never submitted, so it carries a nonce
	// and a key of its own: bound to a key nobody keeps, it cannot be spent as
	// an issuance token by anything that sees it.
	probe, _, err := generateKey()
	if err != nil {
		return "", err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate inventory nonce: %w", err)
	}
	token, err := workloadclaims.FetchSandboxToken(ctx, nodeInventory.endpoint(), cfg.WorkloadClaimsTimeout, &probe.PublicKey, nonce[:])
	if err != nil {
		return "", fmt.Errorf("assert workload instance: %w", err)
	}
	instanceID, err := workloadclaims.UnverifiedSandboxIDFromToken(token.Token)
	if err != nil {
		return "", err
	}
	if err := armtls.ValidateSandboxID(instanceID); err != nil {
		return "", err
	}
	return instanceID, nil
}

// renewLoop is get-cert's daemon mode: renew with graceful shutdown, on a
// resettable timer paced off the published generation's own expiry as well as
// --renew-interval, and — while the published leaf is unnamed — off the fast
// unnamed interval, so the pod's first post-completion renewal picks up its
// matched-workload stamp promptly.
// With --ca-watch-interval it also polls CDS's /ca and renews immediately when
// the published CA is not the CA CDS holds, so a CDS restart
// (which regenerates the mesh CA in-memory) does not leave the pod on a dead
// CA until the next scheduled renewal.
//
// Until the first generation is published the cadence is the initial-retry
// backoff instead: the credential-wait gate holds the workload on that
// generation (docs/getcert-workload-binding.md), so waiting out a renewal
// interval to re-ask would strand it for that long.
func renewLoop(ctx context.Context, cfg config, client attestclient.Client, creds *credentials) error {
	initialBackoff := backoff.NewExponentialBackOff()
	initialBackoff.MaxInterval = maxInitialRetryInterval
	if cfg.InitialRetryInterval > 0 {
		initialBackoff.InitialInterval = cfg.InitialRetryInterval
	}
	// unnamedRuns counts consecutive renewals that came back without a
	// matched-workload stamp; failures counts consecutive renewal errors. Both
	// only pace the timer.
	var unnamedRuns, failures int
	next := renewalInterval(cfg, creds.current, unnamedRuns)
	if creds.current == nil {
		next = initialBackoff.NextBackOff()
	}
	slog.Info("entering renewal loop", "interval", cfg.RenewInterval, "next", next, "published", creds.current != nil)
	renewTimer := time.NewTimer(next)
	defer renewTimer.Stop()

	var watchC <-chan time.Time
	var watchTicker *time.Ticker
	var watchState map[string]fileSnapshot
	if cfg.ReloadNginx && len(cfg.ReloadWatchPaths) > 0 {
		var err error
		watchState, err = snapshotReloadWatchPaths(cfg.ReloadWatchPaths)
		if err != nil {
			return err
		}
		watchTicker = time.NewTicker(cfg.ReloadWatchInterval)
		defer watchTicker.Stop()
		watchC = watchTicker.C
		slog.Info("watching files for nginx reload", "paths", cfg.ReloadWatchPaths, "interval", cfg.ReloadWatchInterval)
	}

	var caWatchC <-chan time.Time
	if cfg.CAWatchInterval > 0 {
		caTicker := time.NewTicker(cfg.CAWatchInterval)
		defer caTicker.Stop()
		caWatchC = caTicker.C
		slog.Info("watching cds mesh CA for changes", "interval", cfg.CAWatchInterval, "ca_path", cfg.CAPath)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down cert renewer")
			return nil
		case <-caWatchC:
			// While nothing is published the initial-retry backoff is already
			// re-asking as fast as allowed.
			if creds.current == nil {
				continue
			}
			stale, err := servedCAStale(ctx, client, cfg.CAPath)
			if err != nil {
				slog.Warn("mesh CA check failed", "error", err)
				continue
			}
			if !stale {
				continue
			}
			slog.Info("cds holds a mesh CA other than the published one, renewing now")
			renewTimer.Reset(0)
		case <-renewTimer.C:
			published := creds.current != nil
			err := obtainCertFn(ctx, cfg, client, creds)
			if err != nil && !published {
				retry := initialBackoff.NextBackOff()
				slog.Error("certificate request failed, still nothing published", "error", err, "retry_in", retry)
				renewTimer.Reset(retry)
				continue
			}
			if err != nil {
				// A short backoff, not a full interval: the timer is paced so
				// it fires around half the published generation's remaining
				// lifetime, so by the time a renewal fails the generation is
				// already close to expiry.
				failures++
				retry := renewalRetryInterval(cfg, creds.current, failures)
				slog.Error("certificate renewal failed, retrying", "error", err, "retry_in", retry, "failures", failures, "published", creds.current != nil)
				renewTimer.Reset(retry)
				continue
			}
			failures = 0
			if isNamedLeaf(creds.current) {
				unnamedRuns = 0
			} else {
				unnamedRuns++
			}
			if cfg.ReloadNginx {
				if err := cmdsutil.ReloadNginx(procRoot, slog.Default()); err != nil {
					slog.Warn("certificate renewed but nginx reload failed", "error", err)
				}
			}
			renewTimer.Reset(renewalInterval(cfg, creds.current, unnamedRuns))
		case <-watchC:
			changed, nextState, err := reloadWatchChanged(watchState, cfg.ReloadWatchPaths)
			if err != nil {
				slog.Warn("reload watch check failed", "error", err)
				continue
			}
			watchState = nextState
			if !changed {
				continue
			}
			slog.Info("watched file changed, reloading nginx")
			if err := cmdsutil.ReloadNginx(procRoot, slog.Default()); err != nil {
				slog.Warn("watched file changed but nginx reload failed", "error", err)
			}
		}
	}
}

const (
	// minRenewalDelay floors every computed delay so an already-expired leaf
	// cannot turn the renewal loop into a hot attestation spin against CDS. It
	// never raises a delay above --renew-interval, which the operator chose.
	minRenewalDelay = 5 * time.Second

	// maxInitialRetryInterval caps the backoff between attempts at the first
	// certificate.
	maxInitialRetryInterval = time.Minute

	// unnamedBackoffAfter is how many consecutive unnamed renewals run at the
	// fast poll before it doubles toward --renew-interval. A pod can be
	// permanently unnamed — a foreign admission, an inventory with no
	// containers view, an ambiguous match, a main container that never comes
	// up — and must not run a full attestation every --unnamed-renew-interval
	// for its whole lifetime.
	unnamedBackoffAfter = 10

	// unnamedFirstPoll is the first delay while the installed leaf is
	// unnamed; it doubles per unnamed renewal up to --unnamed-renew-interval.
	unnamedFirstPoll = 2 * time.Second

	defaultRenewJitterPercent = 20
)

// renewalRetryBase is the first delay after a failed renewal; consecutive
// failures double it up to the ordinary pacing. It is a var the renewal-loop
// test shrinks and TestRenewalRetryInterval reads; keep the package non-parallel.
var renewalRetryBase = 15 * time.Second

// renewalInterval picks the next renewal delay.
//
// The ceiling is whichever comes first: --renew-interval, or half the published
// generation's remaining lifetime — its leaf's or its CA's, whichever
// expires first, so a CA renewed under the pod's bound key is picked up before
// the previous CA certificate expires. That second bound is also what
// keeps a leaf from expiring exactly as its renewal fires: CDS caps a named
// leaf at issuer.MaxNamedLeafTTL and nothing backdates NotBefore, so pacing on
// the flag alone — which the chart sets to the same value — would reset the
// timer after issuance, drift later every cycle, and leave a single failed
// renewal on a dead generation for a full interval.
//
// Under that ceiling a leaf carrying no matched-workload stamp fast-polls from
// unnamedFirstPoll up to --unnamed-renew-interval, so a pod picks up its name at
// the first post-completion renewal. unnamedRuns is the number of consecutive
// renewals that came back unnamed; see unnamedBackoffAfter.
//
// An unparseable or unknown leaf counts as unnamed — polling fast on damage is
// harmless, serving stale identity is not.
func renewalInterval(cfg config, g *generation, unnamedRuns int) time.Duration {
	delay := cfg.RenewInterval
	if expiry := generationExpiry(g); !expiry.IsZero() {
		if half := time.Until(expiry) / 2; half < delay {
			delay = half
		}
	}
	// Renew early by up to --renew-jitter-percent so certificates issued
	// together do not refresh in lockstep. Keep the already-jittered unnamed
	// fast poll and delay floor.
	if spread := int64(delay) * int64(cfg.RenewJitterPercent) / 100; spread > 0 {
		delay -= time.Duration(mrand.Int64N(spread + 1))
	}
	if delay < minRenewalDelay {
		delay = min(minRenewalDelay, cfg.RenewInterval)
	}
	// The unnamed poll is under the floor at first; its own backoff bounds it.
	if fast := unnamedPollInterval(cfg, g, unnamedRuns); fast > 0 && fast < delay {
		delay = fast
	}
	return delay
}

// unnamedPollInterval returns the fast-poll delay for an unnamed leaf, or 0
// when the fast poll does not apply. Jitter is added here and clamped by the
// caller, so it can never push a delay past --renew-interval or past the
// published generation's remaining lifetime.
func unnamedPollInterval(cfg config, g *generation, unnamedRuns int) time.Duration {
	if cfg.UnnamedRenewInterval <= 0 || isNamedLeaf(g) {
		return 0
	}
	// Start at unnamedFirstPoll and double per unnamed renewal up to the flag:
	// a new pod is named as soon as its main container runs, which is often
	// seconds after the cert container, and the router cannot reach it until
	// then.
	iv := min(unnamedFirstPoll, cfg.UnnamedRenewInterval)
	for i := 0; i < unnamedRuns && iv < cfg.UnnamedRenewInterval; i++ {
		iv *= 2
	}
	iv = min(iv, cfg.UnnamedRenewInterval)
	// Doubling past unnamedBackoffAfter bounds a permanently-unnamed pod to a
	// handful of fast polls; the caller's clamp lands it on --renew-interval.
	// The loop cannot run away: it stops at the clamp, so at most log2 steps.
	for i := 0; i < unnamedRuns-unnamedBackoffAfter && iv < cfg.RenewInterval; i++ {
		iv *= 2
	}
	// Jitter up to +25% so a fleet of unnamed pods does not renew in lockstep.
	// Integer division makes the divisor zero for a sub-4ns interval, which
	// mrand.Int64N panics on.
	if quarter := int64(iv) / 4; quarter > 0 {
		iv += time.Duration(mrand.Int64N(quarter))
	}
	return iv
}

// renewalRetryInterval is the delay after a failed renewal: exponential from
// renewalRetryBase so a CDS outage is not hammered, but never slower than the
// ordinary pacing, which is itself bounded by the published generation's
// remaining lifetime.
func renewalRetryInterval(cfg config, g *generation, failures int) time.Duration {
	ceiling := renewalInterval(cfg, g, 0)
	delay := renewalRetryBase
	for i := 1; i < failures && delay < ceiling; i++ {
		delay *= 2
	}
	return min(delay, ceiling)
}

// isNamedLeaf reports whether the published leaf carries a valid
// matched-workload stamp. An absent, unparseable or unstamped leaf is not named.
func isNamedLeaf(g *generation) bool {
	if g == nil {
		return false
	}
	matched, err := armtls.MatchedWorkloadFromCert(g.Leaf)
	return err == nil && matched != nil
}

// obtainCertWithRetry runs the first certificate request, retrying in-process
// on a fixed cadence until it succeeds, InitialRetryTimeout elapses, or the
// context is cancelled. During a full-stack roll CDS and the mesh are briefly
// unavailable; retrying here keeps a transient failure from exiting the init
// container into kubelet's minutes-long CrashLoopBackOff. It still fails closed:
// once the deadline passes the last error is returned and the pod publishes
// nothing.
func obtainCertWithRetry(ctx context.Context, cfg config, client attestclient.Client, creds *credentials) error {
	if cfg.InitialRetryTimeout <= 0 {
		return obtainCertFn(ctx, cfg, client, creds)
	}
	bo := backoff.NewConstantBackOff(cfg.InitialRetryInterval)
	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		return struct{}{}, obtainCertFn(ctx, cfg, client, creds)
	},
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(cfg.InitialRetryTimeout),
		backoff.WithNotify(func(err error, d time.Duration) {
			slog.Warn("certificate request failed, retrying", "retry_in", d, "error", err)
		}),
	)
	return err
}

// obtainCert requests one certificate on a key of its own and publishes both as
// one generation. The response is validated first, so a response that does not
// match that key, the pod's instance or its bound CA key leaves the previous
// generation in place.
func obtainCert(ctx context.Context, cfg config, client attestclient.Client, creds *credentials) error {
	// One request, one key: the sandbox token, the evidence and the CSR below
	// all bind to this key, and it is published only with the certificate
	// issued for it.
	key, keyPEM, err := generateKey()
	if err != nil {
		return err
	}

	// Fetch the CDS challenge up front so one single-use nonce binds both the
	// sandbox token and the evidence REPORTDATA — freshness without a clock
	// (docs/armtls.md, "Sandbox identity").
	challenge, err := client.AuthenticateContext(ctx)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return fmt.Errorf("invalid challenge from cds: %w", err)
	}

	var sandboxToken json.RawMessage
	if !cfg.NoWorkloadClaims {
		asserted := ""
		sandboxToken, asserted, err = fetchSandboxToken(ctx, cfg, &key.PublicKey, nonce)
		if err != nil {
			return err
		}
		// The assertion this request carries must name the instance the pod was
		// resumed under: one issuance, one workload instance, start to finish.
		if asserted != creds.instanceID {
			return fmt.Errorf("the inventory now asserts workload instance %q, not %q", asserted, creds.instanceID)
		}
	}

	// Always embed a nonce-free armTLS .1.1 extension so a downstream armtls-mode
	// verifier (secret-inventory --peer-verify=armtls) can re-verify the leaf —
	// the same nonce-free embed the mesh client uses (docs/armtls.md).
	ext, err := client.AttestationExtension(ctx, cfg.AttestationApiURL, &key.PublicKey)
	if err != nil {
		return fmt.Errorf("build armTLS attestation extension: %w", err)
	}

	csrPEM, err := createCSR(key, cfg.SAN, ext)
	if err != nil {
		return err
	}

	slog.Info("requesting certificate from cds", "cds_url", cfg.CDSURL, "san", cfg.SAN, "instance_id", creds.instanceID)
	result, err := client.ObtainCertificateWithSandboxContext(ctx, cfg.AttestationApiURL, string(csrPEM), challenge.Challenge, sandboxToken)
	if err != nil {
		return fmt.Errorf("attestation failed: %w", err)
	}
	slog.Info("certificate obtained")

	generation, err := issuedGeneration(result.Certificate, key, keyPEM)
	if err != nil {
		return err
	}
	if err := creds.publish(generation, time.Now()); err != nil {
		return err
	}
	return writeDiscoveryDocument(cfg, result)
}

// fetchSandboxToken redeems this pod's kernel peer credentials at the
// inventory for a signed token naming its sandbox (docs/armtls.md, "Sandbox
// identity"). pub is the CSR key the token is bound to; nonce is the CDS
// challenge it must carry for CDS to accept it as fresh.
//
// get-cert never reports its pod's images: the token names the sandbox and the
// inventory that admitted it, and CDS asks that inventory directly. So this
// resolves at first issuance — the sidecar's own container is already tracked
// — where a self-reported image set would still be empty.
//
// Every failure is fail-closed, an inventory that does not serve the route
// included: a certificate issued without the assertion would carry no instance
// for the pod to check it against.
func fetchSandboxToken(ctx context.Context, cfg config, pub crypto.PublicKey, nonce []byte) (json.RawMessage, string, error) {
	token, err := workloadclaims.FetchSandboxToken(ctx, nodeInventory.endpoint(), cfg.WorkloadClaimsTimeout, pub, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("fetch sandbox token: %w", err)
	}
	asserted, err := workloadclaims.UnverifiedSandboxIDFromToken(token.Token)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return nil, "", fmt.Errorf("marshal sandbox token: %w", err)
	}
	return raw, asserted, nil
}

// validateConfig checks that all required configuration is valid.
func validateConfig(cfg config) error {
	if err := cmdsutil.ValidateHTTPURL("--cds-url", cfg.CDSURL); err != nil {
		return err
	}
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.AttestationApiURL); err != nil {
		return err
	}
	if cfg.SAN != "" {
		if err := validateSAN(cfg.SAN); err != nil {
			return fmt.Errorf("--san: %w", err)
		}
	}
	if cfg.DiscoveryOutPath != "" {
		switch discoveryPublicTLSMode(cfg.DiscoveryPublicTLSMode) {
		case "cds", "webpki", "acme":
		default:
			return fmt.Errorf("%w: --discovery-public-tls-mode must be 'cds', 'webpki', or 'acme', got %q", errInvalidDiscoveryPublicTLSMode, cfg.DiscoveryPublicTLSMode)
		}
	}
	if len(cfg.ReloadWatchPaths) > 0 {
		if cfg.ReloadWatchInterval <= 0 {
			return fmt.Errorf("%w: --reload-watch-interval must be greater than 0 when --reload-watch is set", errInvalidReloadWatchInterval)
		}
		if cfg.RenewInterval <= 0 {
			return fmt.Errorf("%w: --renew-interval must be greater than 0 when --reload-watch is set", errReloadWatchRequiresRenewInterval)
		}
	}
	if cfg.CAWatchInterval < 0 {
		return fmt.Errorf("%w: --ca-watch-interval must be 0 (disabled) or positive, got %v", errInvalidCAWatchInterval, cfg.CAWatchInterval)
	}
	if cfg.CAWatchInterval > 0 {
		if cfg.RenewInterval <= 0 {
			return fmt.Errorf("%w: --ca-watch-interval requires --renew-interval, the loop that re-issues on a CA change", errInvalidCAWatchInterval)
		}
	}
	// A fast poll is a full attestation round-trip, so a sub-second value is
	// never what an operator means; 0 is the documented "disabled".
	if cfg.UnnamedRenewInterval != 0 && cfg.UnnamedRenewInterval < time.Second {
		return fmt.Errorf("%w: --unnamed-renew-interval must be 0 (disabled) or at least 1s, got %v", errInvalidUnnamedRenewInterval, cfg.UnnamedRenewInterval)
	}
	if cfg.RenewJitterPercent < 0 || cfg.RenewJitterPercent >= 100 {
		return fmt.Errorf("%w: --renew-jitter-percent must be between 0 (disabled) and 99, got %d", errInvalidRenewJitterPercent, cfg.RenewJitterPercent)
	}
	if cfg.ContinueOnInitialError && cfg.RenewInterval <= 0 {
		return fmt.Errorf("%w: --continue-on-initial-error requires --renew-interval", errContinueOnInitialErrorRequiresRenewalLoop)
	}
	return nil
}

// resolveSAN loads the configured identity once, before network or output work.
// --no-san is the pod that asks for none, and CDS then takes the subject from
// the verified workload identity assertion instead.
func resolveSAN(cfg config) (string, error) {
	switch {
	case cfg.NoSAN && (cfg.SAN != "" || cfg.SANFile != ""):
		return "", fmt.Errorf("--no-san cannot be combined with --san or --san-file")
	case cfg.NoSAN:
		return "", nil
	case cfg.SAN != "" && cfg.SANFile != "":
		return "", fmt.Errorf("--san and --san-file are mutually exclusive")
	case cfg.SAN == "" && cfg.SANFile == "":
		return "", fmt.Errorf("one of --san, --san-file or --no-san is required")
	}
	san := cfg.SAN
	if cfg.SANFile != "" {
		var err error
		if san, err = cmdsutil.ReadSANFile("--san-file", cfg.SANFile); err != nil {
			return "", err
		}
	}
	if err := validateSAN(san); err != nil {
		return "", fmt.Errorf("certificate SAN: %w", err)
	}
	return san, nil
}

// validateSAN checks that a SAN is a valid IP address or RFC 1123 hostname.
func validateSAN(san string) error {
	if san == "" {
		return fmt.Errorf("SAN must not be empty")
	}
	// If it parses as an IP, it's valid.
	if isIPSAN(san) {
		return nil
	}
	if strings.HasPrefix(san, "http://") || strings.HasPrefix(san, "https://") {
		return fmt.Errorf("'%s' looks like a URL, not a hostname - provide just the hostname", san)
	}
	if strings.Contains(san, "*") {
		return fmt.Errorf("'%s' contains a wildcard - wildcards are not supported", san)
	}
	return cmdsutil.ValidateDNSName(san)
}

// isIPSAN returns true if the SAN is an IP address.
func isIPSAN(san string) bool {
	return net.ParseIP(san) != nil
}

// validateOutputPaths checks that output file locations are writable before
// doing any expensive work (key generation, attestation). This prevents
// requesting certificates that can't be saved.
func validateOutputPaths(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		dir := filepath.Dir(p)
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("output directory %q does not exist: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("output path parent %q is not a directory", dir)
		}
		// Try creating a temp file to verify write access.
		f, err := os.CreateTemp(dir, ".get-cert-probe-*")
		if err != nil {
			return fmt.Errorf("output directory %q is not writable: %w", dir, err)
		}
		name := f.Name()
		f.Close()
		os.Remove(name)
	}
	return nil
}

// generateKey mints the key of one certificate request: every renewal asks for
// a certificate on a key of its own, so a disclosed key is useless past the
// generation it was published in.
func generateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	slog.Debug("P-256 key generated")
	return key, keyPEM, nil
}

// createCSR builds a PEM-encoded certificate signing request with the given
// SAN. extraExts are carried as CSR extensions (e.g. the armTLS attestation
// extension CDS copies onto the leaf); nil for the plain flow.
func createCSR(key *ecdsa.PrivateKey, san string, extraExts ...pkix.Extension) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:         pkix.Name{},
		ExtraExtensions: extraExts,
	}

	switch {
	case san == "":
		slog.Debug("CSR will carry no SAN")
	case isIPSAN(san):
		template.IPAddresses = []net.IP{net.ParseIP(san)}
		slog.Debug("CSR will include IP SAN", "ip", san)
	default:
		template.DNSNames = []string{san}
		slog.Debug("CSR will include DNS SAN", "hostname", san)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	slog.Debug("CSR created", "san", san, "pem_bytes", len(csrPEM))
	return csrPEM, nil
}

// caBundleFromChain returns the issuer (CA) portion of a CDS-issued PEM chain:
// every CERTIFICATE block after the first. CDS serves leaf-first, CA-last
// (see the /attest handler), so the leaf is dropped and the remaining blocks
// — the mesh CA bundle — are re-emitted. Errors if no issuer block is present.
func caBundleFromChain(chainPEM []byte) ([]byte, error) {
	var out []byte
	rest := chainPEM
	seenLeaf := false
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		if !seenLeaf {
			seenLeaf = true // skip the leaf
			continue
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CA certificate found after the leaf in the issued chain")
	}
	return out, nil
}

// servedCAStale reports whether the CA published at caPath is not the one CDS
// serves at /ca. The fetch rides the same armTLS-verified client the issuance
// flow uses, so the refresh trusts CDS for exactly the reason the initial fetch
// did. A stale CA means every client following the documented recovery recipe —
// re-fetch the mesh CA from the discovery endpoint — pins a CA nothing signs
// with anymore.
func servedCAStale(ctx context.Context, client attestclient.Client, caPath string) (bool, error) {
	currentPEM, err := client.MeshCA(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch current mesh CA from cds: %w", err)
	}
	current, err := soleCA(currentPEM)
	if err != nil {
		return false, fmt.Errorf("mesh CA from cds: %w", err)
	}
	servedPEM, err := os.ReadFile(caPath)
	if err != nil {
		return false, fmt.Errorf("read served mesh CA: %w", err)
	}
	served, err := soleCA(servedPEM)
	if err != nil {
		return false, fmt.Errorf("published mesh CA: %w", err)
	}
	return !served.Equal(current), nil
}

// privateKeyMode returns 0640 for setgid directories, 0600 otherwise.
func privateKeyMode(path string) (os.FileMode, error) {
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSetgid != 0 {
		return 0640, nil
	}
	return 0600, nil
}

// writeDiscoveryDocument writes the public metadata that names the published
// certificate. It is not part of the generation: no consumer authenticates
// anything with it.
func writeDiscoveryDocument(cfg config, result attestclient.CertificateResult) error {
	if cfg.DiscoveryOutPath == "" {
		return nil
	}
	doc, err := buildDiscoveryDocument(cfg, result)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal discovery metadata: %w", err)
	}
	data = append(data, '\n')
	if err := fileutil.WriteAtomic(cfg.DiscoveryOutPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write discovery metadata to %s: %w", cfg.DiscoveryOutPath, err)
	}
	slog.Info("discovery metadata written", "path", cfg.DiscoveryOutPath)
	return nil
}

func buildDiscoveryDocument(cfg config, result attestclient.CertificateResult) (types.DiscoveryDocument, error) {
	cert, err := certutil.ParseCertificatePEM([]byte(result.Certificate))
	if err != nil {
		return types.DiscoveryDocument{}, fmt.Errorf("parse issued certificate for discovery: %w", err)
	}
	fingerprint := sha256.Sum256(cert.Raw)

	return types.DiscoveryDocument{
		Version:     "v1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		PublicTLS: types.PublicTLSDiscovery{
			Hostname: cfg.SAN,
			Mode:     discoveryPublicTLSMode(cfg.DiscoveryPublicTLSMode),
		},
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM:    result.Certificate,
			CertificateSHA256: hex.EncodeToString(fingerprint[:]),
			CertificateURL:    cfg.DiscoveryCDSCertURL,
			MeshCAURL:         cfg.DiscoveryMeshCAURL,
		},
		Attestation: types.AttestationDiscovery{
			Challenge: result.Challenge,
			Platform:  string(result.Platform),
			Evidence:  result.Evidence,
		},
	}, nil
}

func discoveryPublicTLSMode(mode string) string {
	if mode == "" {
		return "cds"
	}
	return mode
}

type fileSnapshot struct {
	size    int64
	modTime time.Time
	sha256  [sha256.Size]byte
}

func snapshotReloadWatchPaths(paths []string) (map[string]fileSnapshot, error) {
	snapshots := make(map[string]fileSnapshot, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat reload watch path %s: %w", path, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("reload watch path %s is a directory", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read reload watch path %s: %w", path, err)
		}
		snapshots[path] = fileSnapshot{
			size:    info.Size(),
			modTime: info.ModTime(),
			sha256:  sha256.Sum256(data),
		}
	}
	return snapshots, nil
}

func reloadWatchChanged(previous map[string]fileSnapshot, paths []string) (bool, map[string]fileSnapshot, error) {
	next, err := snapshotReloadWatchPaths(paths)
	if err != nil {
		return false, nil, err
	}
	for _, path := range paths {
		if previous[path] != next[path] {
			return true, next, nil
		}
	}
	return false, next, nil
}
