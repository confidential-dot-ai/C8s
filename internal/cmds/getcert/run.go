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
	"slices"
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

const cdsPinFlags = "--cds-measurements or --image-policy-file"

// config holds all CLI configuration for get-cert.
type config struct {
	CDSURL                 string
	CDSMeasurements        string
	CDSRTMRs               string
	MeasurementsConfig     string
	MeasurementsConfigJSON string
	AttestationApiURL      string
	OutPath                string
	CAOutPath              string
	KeyPath                string
	KeyOutPath             string
	SAN                    string
	SANFile                string
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
	WorkloadClaims         bool
	WorkloadClaimsTimeout  time.Duration
	UnnamedRenewInterval   time.Duration
}

// inventoryEndpoint returns the compiled admission-inventory endpoint. It is a
// package variable only so tests can point it at a temporary Unix socket; the
// production value is always workloadclaims.InventoryEndpoint (a baked path
// the control plane cannot redirect).
var inventoryEndpoint = workloadclaims.InventoryEndpoint

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

It generates an ECDSA P-256 key pair (or loads the key passed with --key),
creates a CSR with the specified SAN (Subject Alternative Name), and uses
the CDS attestation flow to obtain a signed certificate. The P-384 keypair
used elsewhere in c8s is limited to mesh CA rotation; get-cert leaf keys stay
P-256 by default.

This tool is designed to run as a Kubernetes init container or renewal sidecar
alongside a workload that uses the obtained certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging(cfg.Verbose)
			return run(cfg)
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	cmdsutil.BindImagePolicyFlags(flags, &cfg.MeasurementsConfig, &cfg.MeasurementsConfigJSON, "", "pins the CDS endpoint; excludes --cds-measurements and --cds-rtmrs")
	flags.StringVar(&cfg.CDSURL, "cds-url", "", "URL of the CDS service (e.g. https://cds:8443)")
	flags.StringVar(&cfg.CDSMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch measurements for CDS armTLS verification; required, unless --image-policy-file names the images")
	flags.StringVar(&cfg.CDSRTMRs, "cds-rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex> CDS's armTLS cert must additionally satisfy; ignored when CDS presents SNP evidence (empty = launch-digest pinning only)")
	flags.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "URL of the node-local attestation-api (http://localhost:8400, or unix:// plus the on-node socket path the chart wires)")
	flags.StringVarP(&cfg.OutPath, "out", "o", "", "Path to write the signed certificate chain PEM (prints to stdout if omitted)")
	flags.StringVar(&cfg.CAOutPath, "ca-out", "", "Path to write just the mesh CA bundle PEM (the issuer certs trailing the leaf in the CDS chain), e.g. for nginx to serve at a discovery endpoint without a separate ConfigMap")
	flags.StringVar(&cfg.KeyPath, "key", "", "Path to a PEM private key to use for the CSR (generates an ephemeral key if omitted)")
	flags.StringVar(&cfg.KeyOutPath, "key-out", "", "Path to write the private key PEM with mode 0600 (0640 in shared setgid directories; key reused on restart); must be on a memory-backed filesystem")
	flags.StringVar(&cfg.SAN, "san", "", "Subject Alternative Name for the certificate (IP address or hostname)")
	flags.StringVar(&cfg.SANFile, "san-file", "", "Path to a file containing the certificate SAN; mutually exclusive with --san")
	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable debug logging")
	flags.DurationVar(&cfg.RenewInterval, "renew-interval", 0, "Re-obtain the certificate at this interval (0 = run once and exit)")
	flags.IntVar(&cfg.RenewJitterPercent, "renew-jitter-percent", defaultRenewJitterPercent, "Shorten each renewal delay by a random fraction of itself, up to this percent, so certificates issued together do not refresh in lockstep (0 = no jitter)")
	flags.DurationVar(&cfg.InitialRetryTimeout, "initial-retry-timeout", 2*time.Minute, "Retry the first certificate request in-process for up to this long before failing, so a transient CDS/mesh outage during a roll does not crash the init container into kubelet backoff (0 = try once)")
	flags.DurationVar(&cfg.InitialRetryInterval, "initial-retry-interval", 2*time.Second, "Delay between in-process retries of the first certificate request")
	flags.BoolVar(&cfg.ReloadNginx, "reload-nginx", true, "SIGHUP nginx after certificate renewal or watched file changes")
	flags.BoolVar(&cfg.ContinueOnInitialError, "continue-on-initial-error", false, "In renewal mode, keep running when the first certificate request fails, retrying on a capped backoff until a certificate is issued")
	flags.StringArrayVar(&cfg.ReloadWatchPaths, "reload-watch", nil, "File path to poll for changes and reload nginx when it changes (repeatable)")
	flags.DurationVar(&cfg.ReloadWatchInterval, "reload-watch-interval", time.Minute, "Poll interval for --reload-watch paths")
	flags.DurationVar(&cfg.CAWatchInterval, "ca-watch-interval", 0, "Poll CDS's /ca at this interval and renew immediately when the bundle at --ca-out no longer contains the CA CDS currently holds. A CDS restart regenerates the mesh CA in-memory, so without this the pod serves the dead CA until the next scheduled renewal (0 = disabled; requires --ca-out and --renew-interval)")
	flags.StringVar(&cfg.DiscoveryOutPath, "discovery-out", "", "Path to write JSON discovery metadata for the issued certificate and attestation evidence")
	flags.StringVar(&cfg.DiscoveryCDSCertURL, "discovery-cds-cert-url", "", "Public URL path where the CDS certificate PEM is served")
	flags.StringVar(&cfg.DiscoveryMeshCAURL, "discovery-mesh-ca-url", "", "Public URL path where the mesh CA PEM is served")
	flags.StringVar(&cfg.DiscoveryPublicTLSMode, "discovery-public-tls-mode", "cds", "Public TLS mode to report in discovery metadata (cds, webpki, or acme)")
	flags.BoolVar(&cfg.WorkloadClaims, "workload-claims", false, "Request an inventory-signed sandbox token, which CDS verifies and stamps into the issued leaf, from the local inventory at get-cert's compiled Unix socket path — nri-image-policy on node-CVM (docs/armtls.md). The path is baked in, not supplied, so the control plane cannot redirect the request; fail-closed if the inventory is unreachable")
	flags.DurationVar(&cfg.WorkloadClaimsTimeout, "workload-claims-timeout", 5*time.Second, "Timeout for the admission inventory request")
	flags.DurationVar(&cfg.UnnamedRenewInterval, "unnamed-renew-interval", 30*time.Second, "With --workload-claims and --renew-interval, renew while the installed leaf carries no matched-workload stamp at most this far apart (plus jitter), starting at 2s and doubling, so a pod picks up its name at the first post-completion renewal instead of waiting a full interval; settles to --renew-interval once named, and backs off toward it for a pod that stays unnamed. Poll timing never changes the match decision. 0 disables the fast poll")

	_ = cmd.MarkFlagRequired("cds-url")
	_ = cmd.MarkFlagRequired("attestation-api-url")
	cmd.MarkFlagsOneRequired("san", "san-file")
	cmd.MarkFlagsMutuallyExclusive("san", "san-file")

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
	return cmdsutil.ResolveCDSPins(
		cmdsutil.ImagePolicySource{
			File: cfg.MeasurementsConfig,
			JSON: cfg.MeasurementsConfigJSON,
		},
		cmdsutil.MeasurementPinsFromStrings(cfg.CDSMeasurements, cfg.CDSRTMRs, "cds-"),
		cdsPinFlags)
}

// obtainCertFn is a var so renewal-loop tests can observe attempts.
var obtainCertFn = obtainCert

func run(cfg config) error {
	san, err := resolveSAN(cfg.SAN, cfg.SANFile)
	if err != nil {
		return err
	}
	cfg.SAN = san
	slog.Info("starting get-cert", "san", cfg.SAN)

	if err := validateConfig(cfg); err != nil {
		return err
	}
	// Fail fast, never retry: a missing socket directory means the mount was
	// not injected at container creation and no in-process wait can produce
	// it, while the retry loop below would idle forever behind
	// --continue-on-initial-error (see workloadclaims.RequireSidecarSocketDir).
	if cfg.WorkloadClaims {
		if err := workloadclaims.RequireSidecarSocketDir(); err != nil {
			return err
		}
	}

	if err := validateOutputPaths(cfg.OutPath, cfg.KeyOutPath, cfg.DiscoveryOutPath); err != nil {
		return err
	}
	if err := requireKeyOutRAMBacked(cfg.KeyOutPath); err != nil {
		return err
	}
	slog.Debug("output paths validated")

	client, err := newCDSClient(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	haveCert := true
	leaf, err := obtainCertWithRetry(ctx, cfg, client)
	if err != nil {
		if cfg.RenewInterval <= 0 || !cfg.ContinueOnInitialError {
			return err
		}
		haveCert = false
		slog.Error("initial certificate request failed, will keep retrying", "error", err)
	} else if cfg.RenewInterval <= 0 {
		return nil
	}
	return renewLoop(ctx, cfg, client, leaf, haveCert)
}

// renewLoop is get-cert's daemon mode: renew with graceful shutdown, on a
// resettable timer paced off the installed leaf's own expiry as well as
// --renew-interval, and — while the installed leaf is unnamed and
// --workload-claims is on — off the fast unnamed interval, so the pod's first
// post-completion renewal picks up its matched-workload stamp promptly.
// With --ca-watch-interval it also polls CDS's /ca and renews immediately when
// the served CA bundle no longer contains the CA CDS holds, so a CDS restart
// (which regenerates the mesh CA in-memory) does not leave the discovery
// endpoints serving a dead CA until the next scheduled renewal.
//
// Until the first certificate lands the cadence is the initial-retry backoff
// instead: c8s-cert-wait holds the workload on that certificate
// (docs/getcert-workload-binding.md), so waiting out a renewal interval to
// re-ask would strand it for that long.
func renewLoop(ctx context.Context, cfg config, client attestclient.Client, leaf *x509.Certificate, haveCert bool) error {
	initialBackoff := backoff.NewExponentialBackOff()
	initialBackoff.MaxInterval = maxInitialRetryInterval
	if cfg.InitialRetryInterval > 0 {
		initialBackoff.InitialInterval = cfg.InitialRetryInterval
	}
	// unnamedRuns counts consecutive renewals that came back without a
	// matched-workload stamp; failures counts consecutive renewal errors. Both
	// only pace the timer.
	var unnamedRuns, failures int
	next := renewalInterval(cfg, leaf, unnamedRuns)
	if !haveCert {
		next = initialBackoff.NextBackOff()
	}
	slog.Info("entering renewal loop", "interval", cfg.RenewInterval, "next", next, "have_cert", haveCert)
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
		slog.Info("watching cds mesh CA for changes", "interval", cfg.CAWatchInterval, "ca_path", cfg.CAOutPath)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down cert renewer")
			return nil
		case <-caWatchC:
			// While no certificate is installed the initial-retry backoff is
			// already re-asking as fast as allowed.
			if !haveCert {
				continue
			}
			stale, err := servedCAStale(ctx, client, cfg.CAOutPath)
			if err != nil {
				slog.Warn("mesh CA check failed", "error", err)
				continue
			}
			if !stale {
				continue
			}
			slog.Info("cds holds a mesh CA the served bundle is missing, renewing now")
			renewTimer.Reset(0)
		case <-renewTimer.C:
			renewed, err := obtainCertFn(ctx, cfg, client)
			if err != nil && !haveCert {
				retry := initialBackoff.NextBackOff()
				slog.Error("certificate request failed, still no certificate", "error", err, "retry_in", retry)
				renewTimer.Reset(retry)
				continue
			}
			if err != nil {
				// A short backoff, not a full interval: the timer is paced so
				// it fires around half the installed leaf's remaining
				// lifetime, so by the time a renewal fails the leaf is already
				// close to expiry. Sleeping out --renew-interval here would
				// leave the workload serving a dead certificate.
				failures++
				if shouldRestartAfterRenewalFailures(leaf, failures) {
					// The installed leaf is dead and renewal from this process
					// keeps failing, so retrying in-process serves an expired
					// certificate indefinitely. Exit instead: as a native
					// sidecar (restartPolicy: Always) the container restarts
					// with fresh client state and re-runs the full issuance.
					return fmt.Errorf("installed certificate expired at %s and %d consecutive renewals failed (last: %w); exiting for a clean restart", leaf.NotAfter.Format(time.RFC3339), failures, err)
				}
				retry := renewalRetryInterval(cfg, leaf, failures)
				slog.Error("certificate renewal failed, retrying", "error", err, "retry_in", retry, "failures", failures)
				renewTimer.Reset(retry)
				continue
			}
			haveCert = true
			failures = 0
			leaf = renewed
			if isNamedLeaf(leaf) {
				unnamedRuns = 0
			} else {
				unnamedRuns++
			}
			if cfg.ReloadNginx {
				if err := cmdsutil.ReloadNginx(procRoot, slog.Default()); err != nil {
					slog.Warn("certificate renewed but nginx reload failed", "error", err)
				}
			}
			renewTimer.Reset(renewalInterval(cfg, leaf, unnamedRuns))
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

	// expiredExitFailures is how many consecutive renewal failures the loop
	// tolerates once the installed leaf has expired before exiting for a clean
	// sidecar restart. Small, because every request in a renewal attempt is
	// individually timed out — a failing attempt resolves in seconds — and an
	// expired leaf means clients are already failing closed against this pod.
	expiredExitFailures = 3

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
// The ceiling is whichever comes first: --renew-interval, or half the installed
// leaf's remaining lifetime. That second bound is what keeps a leaf from
// expiring exactly as its renewal fires: CDS caps a named leaf at
// issuer.MaxNamedLeafTTL and nothing backdates NotBefore, so pacing on the flag
// alone — which the chart sets to the same value — would reset the timer after
// issuance, drift later every cycle, and leave a single failed renewal serving a
// dead leaf for a full interval.
//
// Under that ceiling a workload-claims leaf carrying no matched-workload stamp
// fast-polls from unnamedFirstPoll up to --unnamed-renew-interval, so a pod picks up its name at the
// first post-completion renewal. unnamedRuns is the number of consecutive
// renewals that came back unnamed; see unnamedBackoffAfter.
//
// An unparseable or unknown leaf counts as unnamed — polling fast on damage is
// harmless, serving stale identity is not.
func renewalInterval(cfg config, leaf *x509.Certificate, unnamedRuns int) time.Duration {
	delay := cfg.RenewInterval
	if leaf != nil && !leaf.NotAfter.IsZero() {
		if half := time.Until(leaf.NotAfter) / 2; half < delay {
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
	if fast := unnamedPollInterval(cfg, leaf, unnamedRuns); fast > 0 && fast < delay {
		delay = fast
	}
	return delay
}

// unnamedPollInterval returns the fast-poll delay for an unnamed
// workload-claims leaf, or 0 when the fast poll does not apply. Jitter is added
// here and clamped by the caller, so it can never push a delay past
// --renew-interval or past the installed leaf's remaining lifetime.
func unnamedPollInterval(cfg config, leaf *x509.Certificate, unnamedRuns int) time.Duration {
	if !cfg.WorkloadClaims || cfg.UnnamedRenewInterval <= 0 || isNamedLeaf(leaf) {
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
// ordinary pacing, which is itself bounded by the installed leaf's remaining
// lifetime.
func renewalRetryInterval(cfg config, leaf *x509.Certificate, failures int) time.Duration {
	ceiling := renewalInterval(cfg, leaf, 0)
	delay := renewalRetryBase
	for i := 1; i < failures && delay < ceiling; i++ {
		delay *= 2
	}
	return min(delay, ceiling)
}

func shouldRestartAfterRenewalFailures(leaf *x509.Certificate, failures int) bool {
	return leaf != nil && failures >= expiredExitFailures && time.Now().After(leaf.NotAfter)
}

// isNamedLeaf reports whether the installed leaf carries a valid
// matched-workload stamp. A nil, unparseable, or unstamped leaf is not named.
func isNamedLeaf(leaf *x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	matched, err := armtls.MatchedWorkloadFromCert(leaf)
	return err == nil && matched != nil
}

// obtainCertWithRetry runs the first certificate request, retrying in-process
// on a fixed cadence until it succeeds, InitialRetryTimeout elapses, or the
// context is cancelled. During a full-stack roll CDS and the mesh are briefly
// unavailable; retrying here keeps a transient failure from exiting the init
// container into kubelet's minutes-long CrashLoopBackOff. It still fails closed:
// once the deadline passes the last error is returned and the pod does not
// start without a real mesh cert.
func obtainCertWithRetry(ctx context.Context, cfg config, client attestclient.Client) (*x509.Certificate, error) {
	if cfg.InitialRetryTimeout <= 0 {
		return obtainCertFn(ctx, cfg, client)
	}
	bo := backoff.NewConstantBackOff(cfg.InitialRetryInterval)
	return backoff.Retry(ctx, func() (*x509.Certificate, error) {
		return obtainCertFn(ctx, cfg, client)
	},
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(cfg.InitialRetryTimeout),
		backoff.WithNotify(func(err error, d time.Duration) {
			slog.Warn("certificate request failed, retrying", "retry_in", d, "error", err)
		}),
	)
}

// obtainCert requests, writes, and returns the issued leaf. A leaf that cannot
// be parsed back is returned as nil without failing the renewal — the outputs
// are already written, and the caller only reads the leaf for poll pacing.
func obtainCert(ctx context.Context, cfg config, client attestclient.Client) (*x509.Certificate, error) {
	privateKey, keyPEM, err := loadOrGenerateKey(cfg)
	if err != nil {
		return nil, err
	}

	// Fetch the CDS challenge up front so one single-use nonce binds both the
	// sandbox token and the evidence REPORTDATA — freshness without a clock
	// (docs/armtls.md, "Sandbox identity").
	challenge, err := client.AuthenticateContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge from cds: %w", err)
	}

	sandboxToken, err := fetchSandboxToken(ctx, cfg, &privateKey.PublicKey, nonce)
	if err != nil {
		return nil, err
	}

	// Always embed a nonce-free armTLS .1.1 extension so a downstream armtls-mode
	// verifier (secret-inventory --peer-verify=armtls) can re-verify the leaf —
	// the same nonce-free embed the mesh client uses (docs/armtls.md).
	ext, err := client.AttestationExtension(ctx, cfg.AttestationApiURL, &privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("build armTLS attestation extension: %w", err)
	}

	csrPEM, err := createCSR(privateKey, cfg.SAN, ext)
	if err != nil {
		return nil, err
	}

	slog.Info("requesting certificate from cds", "cds_url", cfg.CDSURL, "san", cfg.SAN, "sandbox_token", len(sandboxToken) > 0)
	result, err := client.ObtainCertificateWithSandboxContext(ctx, cfg.AttestationApiURL, string(csrPEM), challenge.Challenge, sandboxToken)
	if err != nil {
		return nil, fmt.Errorf("attestation failed: %w", err)
	}
	slog.Info("certificate obtained")

	if err := writeOutputs(cfg, keyPEM, result); err != nil {
		return nil, err
	}
	leaf, err := certutil.ParseCertificatePEM([]byte(result.Certificate))
	if err != nil {
		slog.Warn("issued certificate could not be parsed back; treating it as unnamed", "error", err)
		return nil, nil
	}
	return leaf, nil
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
// Without --workload-claims it returns nil. With it, an inventory that does not
// serve the route issues without a sandbox ID; any other failure is
// fail-closed, so issuance aborts rather than silently dropping the binding.
func fetchSandboxToken(ctx context.Context, cfg config, pub crypto.PublicKey, nonce []byte) (json.RawMessage, error) {
	if !cfg.WorkloadClaims {
		return nil, nil
	}
	endpoint := inventoryEndpoint()
	token, err := workloadclaims.FetchSandboxToken(ctx, endpoint, cfg.WorkloadClaimsTimeout, pub, nonce)
	switch {
	case errors.Is(err, workloadclaims.ErrSandboxUnsupported):
		slog.Info("inventory does not serve the sandbox route; issuing without a sandbox ID")
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("fetch sandbox token: %w", err)
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal sandbox token: %w", err)
	}
	return raw, nil
}

// validateConfig checks that all required configuration is valid.
func validateConfig(cfg config) error {
	if err := cmdsutil.ValidateHTTPURL("--cds-url", cfg.CDSURL); err != nil {
		return err
	}
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.AttestationApiURL); err != nil {
		return err
	}
	if err := validateSAN(cfg.SAN); err != nil {
		return fmt.Errorf("--san: %w", err)
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
		if cfg.CAOutPath == "" {
			return fmt.Errorf("%w: --ca-watch-interval requires --ca-out, the served bundle it compares against", errInvalidCAWatchInterval)
		}
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
func resolveSAN(san, path string) (string, error) {
	if path != "" {
		if san != "" {
			return "", fmt.Errorf("--san and --san-file are mutually exclusive")
		}
		var err error
		san, err = cmdsutil.ReadSANFile("--san-file", path)
		if err != nil {
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

// requireKeyOutRAMBacked enforces that --key-out sits on tmpfs/ramfs: the
// private key must never reach persistent storage, which the host reads at
// will. The cert and CA outputs are public and stay unconstrained.
func requireKeyOutRAMBacked(keyOutPath string) error {
	if keyOutPath == "" {
		return nil
	}
	return cmdsutil.RequireRAMBackedDir("--key-out", filepath.Dir(keyOutPath))
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

// loadOrGenerateKey resolves the workload's private key.
//
//   - --key <path>  : load (path must exist).
//   - --key-out <path> : reuse if a key already exists at <path>, else
//     generate one. The reuse case keeps the same keypair across container
//     restarts inside a pod — a fresh key would invalidate every cert CDS
//     has previously issued for it.
//   - neither      : generate an ephemeral key (lost on exit).
func loadOrGenerateKey(cfg config) (*ecdsa.PrivateKey, []byte, error) {
	if cfg.KeyPath != "" {
		slog.Debug("loading existing private key", "path", cfg.KeyPath)
		return loadKey(cfg.KeyPath)
	}
	if cfg.KeyOutPath != "" {
		switch info, err := os.Stat(cfg.KeyOutPath); {
		case err == nil && !info.IsDir() && info.Size() > 0:
			slog.Debug("reusing existing private key from --key-out path", "path", cfg.KeyOutPath)
			return loadKey(cfg.KeyOutPath)
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return nil, nil, fmt.Errorf("stat %s: %w", cfg.KeyOutPath, err)
		}
		// Fall through: generate and let writeOutputs persist it.
	}
	slog.Debug("generating ephemeral P-256 key pair")
	return generateKey()
}

func loadKey(path string) (*ecdsa.PrivateKey, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key at %s: %w", path, err)
	}
	key, err := certutil.ParseECPrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid key at %s: %w", path, err)
	}
	slog.Debug("private key loaded", "curve", key.Curve.Params().Name)
	return key, data, nil
}

func generateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	slog.Debug("ephemeral P-256 key generated")
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

	if isIPSAN(san) {
		template.IPAddresses = []net.IP{net.ParseIP(san)}
		slog.Debug("CSR will include IP SAN", "ip", san)
	} else {
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

// servedCAStale reports whether the bundle written at caOutPath is missing a
// certificate CDS currently serves at /ca. The fetch rides the same
// armTLS-verified client the issuance flow uses, so the refresh trusts CDS for
// exactly the reason the initial fetch did. A stale bundle means every client
// following the documented recovery recipe — re-fetch the mesh CA from the
// discovery endpoint — pins a CA nothing signs with anymore.
func servedCAStale(ctx context.Context, client attestclient.Client, caOutPath string) (bool, error) {
	currentPEM, err := client.MeshCA(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch current mesh CA from cds: %w", err)
	}
	current, err := certutil.ParsePEMCertificates(currentPEM)
	if err != nil {
		return false, fmt.Errorf("parse mesh CA from cds: %w", err)
	}
	servedPEM, err := os.ReadFile(caOutPath)
	if err != nil {
		return false, fmt.Errorf("read served mesh CA: %w", err)
	}
	served, err := certutil.ParsePEMCertificates(servedPEM)
	if err != nil {
		return false, fmt.Errorf("parse served mesh CA: %w", err)
	}
	for _, cur := range current {
		if !slices.ContainsFunc(served, cur.Equal) {
			return true, nil
		}
	}
	return false, nil
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

// writeOutputs writes the certificate, key, and optional discovery metadata.
func writeOutputs(cfg config, keyPEM []byte, result attestclient.CertificateResult) error {
	if cfg.KeyOutPath != "" {
		mode, err := privateKeyMode(cfg.KeyOutPath)
		if err != nil {
			return fmt.Errorf("determine key permissions for %s: %w", cfg.KeyOutPath, err)
		}
		if err := fileutil.WriteAtomic(cfg.KeyOutPath, keyPEM, mode); err != nil {
			return fmt.Errorf("failed to write key to %s: %w", cfg.KeyOutPath, err)
		}
		slog.Info("private key written", "path", cfg.KeyOutPath)
	} else if cfg.KeyPath == "" {
		slog.Warn("ephemeral key used but --key-out not set, private key will be lost")
	}

	// The CA bundle lands before the cert: the cert file is the readiness
	// sentinel c8s-cert-wait probes, so consumers gated on it (the injected
	// secrets agent) must find the CA already on disk.
	if cfg.CAOutPath != "" {
		caPEM, err := caBundleFromChain([]byte(result.Certificate))
		if err != nil {
			return fmt.Errorf("extract mesh CA bundle: %w", err)
		}
		if err := fileutil.WriteAtomic(cfg.CAOutPath, caPEM, 0644); err != nil {
			return fmt.Errorf("failed to write mesh CA to %s: %w", cfg.CAOutPath, err)
		}
		slog.Info("mesh CA bundle written", "path", cfg.CAOutPath)
	}

	if cfg.OutPath != "" {
		if err := fileutil.WriteAtomic(cfg.OutPath, []byte(result.Certificate), 0644); err != nil {
			return fmt.Errorf("failed to write cert to %s: %w", cfg.OutPath, err)
		}
		slog.Info("certificate written", "path", cfg.OutPath)
	} else {
		fmt.Print(result.Certificate)
	}

	if cfg.DiscoveryOutPath != "" {
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
	}

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
