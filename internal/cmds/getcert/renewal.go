package getcert

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v5"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// renewLoop is get-cert's daemon mode. Until ctx ends it keeps a valid
// generation published:
//   - a timer requests the next generation, paced by renewalInterval once one
//     is published and by the initial-retry backoff until then;
//   - a failed request is retried with backoff;
//   - each --ca-watch-interval tick renews early when CDS serves a renewed CA
//     certificate under the pod's bound key, or an allowlist policy other than
//     the one the leaf is stamped with;
//   - in a guest, a changed pod snapshot renews at once;
//   - a generation that stops validating is withdrawn, even mid-request.
func renewLoop(
	ctx context.Context,
	cfg config,
	client attestclient.Client,
	policyClient allowlistclient.Client,
	creds *credentials,
) error {
	r := newRenewer(cfg, client, policyClient, creds)
	defer r.stop()
	return r.run(ctx)
}

// renewer is the renewal loop's state between events.
type renewer struct {
	cfg          config
	client       attestclient.Client
	policyClient allowlistclient.Client
	creds        *credentials

	// podChanges is nil outside a guest.
	podChanges <-chan struct{}
	// cdsWatch and cdsTicker are nil when --ca-watch-interval is 0.
	cdsWatch   <-chan time.Time
	cdsTicker  *time.Ticker
	renewTimer *time.Timer
	renewDue   time.Time

	// initialRetry paces requests while nothing is published: the
	// credential-wait gate holds the workload until the first generation
	// (docs/getcert-workload-binding.md).
	initialRetry *backoff.ExponentialBackOff
	// unnamedRuns counts consecutive renewals that came back without a
	// matched-workload stamp.
	unnamedRuns int
	// renewalFailures counts consecutive failed renewals of a published
	// generation.
	renewalFailures int
	// refusals counts consecutive requests CDS or the inventory refused.
	refusals int
	// retryPending is set while the last request failed; a pod change does
	// not shorten its backoff.
	retryPending bool
	// policyRenewalPending debounces the policy watch until the timer fires.
	policyRenewalPending bool
	warnedWorkloads      map[string]bool
}

func newRenewer(
	cfg config,
	client attestclient.Client,
	policyClient allowlistclient.Client,
	creds *credentials,
) *renewer {
	r := &renewer{
		cfg:             cfg,
		client:          client,
		policyClient:    policyClient,
		creds:           creds,
		initialRetry:    newInitialRetryBackoff(cfg),
		warnedWorkloads: map[string]bool{},
	}
	if cfg.guest != nil {
		r.podChanges = cfg.guest.Changes
	}
	warnUnexpectedWorkload(cfg, publishedLeaf(creds.current), r.warnedWorkloads)

	first := r.takeFirstRequestDelay()
	slog.Info("entering renewal loop", "interval", cfg.RenewInterval, "next", first, "published", r.hasPublished())
	r.renewTimer = time.NewTimer(first)
	r.renewDue = time.Now().Add(first)

	if cfg.CAWatchInterval > 0 {
		r.cdsTicker = time.NewTicker(cfg.CAWatchInterval)
		r.cdsWatch = r.cdsTicker.C
		slog.Info("watching cds for changes", "interval", cfg.CAWatchInterval, "ca_path", cfg.CAPath, "policy", !cfg.NoWorkloadClaims)
	}
	return r
}

func newInitialRetryBackoff(cfg config) *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxInterval = maxInitialRetryInterval
	if cfg.InitialRetryInterval > 0 {
		b.InitialInterval = cfg.InitialRetryInterval
	}
	return b
}

// takeFirstRequestDelay advances the initial-retry backoff while nothing is
// published.
func (r *renewer) takeFirstRequestDelay() time.Duration {
	if !r.hasPublished() {
		return r.initialRetry.NextBackOff()
	}
	return renewalInterval(r.cfg, r.creds.current, r.unnamedRuns)
}

func (r *renewer) stop() {
	r.renewTimer.Stop()
	if r.cdsTicker != nil {
		r.cdsTicker.Stop()
	}
}

func (r *renewer) run(ctx context.Context) error {
	for {
		if err := r.creds.withdrawUnusable(time.Now()); err != nil {
			return err
		}
		if ctx.Err() != nil {
			slog.Info("shutting down cert renewer")
			return nil
		}
		if err := r.handleNextEvent(ctx); err != nil {
			return err
		}
	}
}

// handleNextEvent waits for one event and handles it. Its requests end at the
// published generation's expiry, so run withdraws that generation on time
// even while a request blocks.
func (r *renewer) handleNextEvent(ctx context.Context) error {
	requestCtx, cancel := generationValidityContext(ctx, r.creds.current)
	defer cancel()
	select {
	case <-requestCtx.Done():
		return nil
	case _, open := <-r.podChanges:
		if !open {
			// A closed channel is always ready; a nil one never is.
			r.podChanges = nil
			return nil
		}
		r.renewOnPodChange()
		return nil
	case <-r.cdsWatch:
		r.renewIfCDSChanged(requestCtx)
		return nil
	case <-r.renewTimer.C:
		return r.renew(requestCtx)
	}
}

// renewOnPodChange renews at once unless a failed request is backing off: its
// retry asks with the current snapshot anyway.
func (r *renewer) renewOnPodChange() {
	if !r.retryPending {
		r.scheduleRenewal(0)
	}
}

// renewIfCDSChanged renews when CDS serves a renewed CA certificate under the
// pod's bound key or an allowlist policy other than the leaf's stamp.
func (r *renewer) renewIfCDSChanged(ctx context.Context) {
	// Until a generation is published the initial-retry backoff is already
	// asking as fast as allowed.
	if !r.hasPublished() {
		return
	}
	if r.publishedCAStale(ctx) {
		slog.Info("cds renewed the bound mesh CA certificate, renewing now")
		r.scheduleRenewal(0)
		return
	}
	if r.policyCheckDue() {
		r.renewIfPolicyStale(ctx)
	}
}

// publishedCAStale treats a failed check as not stale: the failure may be
// local (an unreadable --ca-path) and must not mute the policy check.
func (r *renewer) publishedCAStale(ctx context.Context) bool {
	stale, err := servedCAStale(ctx, r.client, r.creds.issuer, r.creds.volume)
	if err != nil {
		slog.Warn("mesh CA check failed", "error", err)
		return false
	}
	return stale
}

// policyCheckDue is false while renewals are failing or a policy renewal is
// already scheduled: either one re-issues anyway.
func (r *renewer) policyCheckDue() bool {
	return !r.cfg.NoWorkloadClaims && r.renewalFailures == 0 && !r.policyRenewalPending
}

// renewIfPolicyStale schedules a renewal when CDS serves allowlist bytes
// other than the ones the leaf is stamped with. An unstamped leaf is left to
// the unnamed fast poll; a leaf naming another workload than
// --expected-workload is still checked, since that poll may be off.
func (r *renewer) renewIfPolicyStale(ctx context.Context) {
	stamp, err := armtls.MatchedWorkloadFromCert(r.creds.current.Leaf)
	if err != nil || stamp == nil {
		return
	}
	servedVersion, stale, err := stampedPolicyStale(ctx, r.policyClient, stamp.AllowlistDigest)
	if err != nil {
		slog.Warn("allowlist policy check failed", "error", err)
		return
	}
	if !stale {
		return
	}
	delay := policyRenewDelayFn(r.cfg.CAWatchInterval, time.Until(r.renewDue))
	logPolicyChange(stamp, servedVersion, delay)
	r.policyRenewalPending = true
	r.scheduleRenewal(delay)
}

func logPolicyChange(
	stamp *armtls.MatchedWorkload,
	servedVersion string,
	delay time.Duration,
) {
	if servedVersion == stamp.AllowlistVersion {
		slog.Warn("cds serves different allowlist bytes at the version the stamp names, renewing", "stamped_version", stamp.AllowlistVersion, "delay", delay)
		return
	}
	slog.Info("cds serves a newer allowlist policy than the leaf names, renewing", "stamped_version", stamp.AllowlistVersion, "served_version", servedVersion, "delay", delay)
}

// renew requests the next generation and schedules the request after it.
func (r *renewer) renew(ctx context.Context) error {
	r.policyRenewalPending = false
	wasPublished := r.hasPublished()
	err := obtainCertFn(ctx, r.cfg, r.client, r.creds)
	if errors.Is(err, errFailClosed) {
		return err
	}
	r.refusals = consecutiveRefusals(r.refusals, err)
	switch {
	case err == nil:
		r.scheduleAfterSuccess()
	case !wasPublished:
		r.retryFirstIssuance(err)
	default:
		return r.retryRenewal(err)
	}
	return nil
}

func (r *renewer) scheduleAfterSuccess() {
	r.renewalFailures = 0
	r.retryPending = false
	warnUnexpectedWorkload(r.cfg, publishedLeaf(r.creds.current), r.warnedWorkloads)
	if isNamedLeaf(r.cfg, r.creds.current) {
		r.unnamedRuns = 0
	} else {
		r.unnamedRuns++
	}
	r.scheduleRenewal(renewalInterval(r.cfg, r.creds.current, r.unnamedRuns))
}

// retryFirstIssuance backs off on the initial-retry backoff, which advances on
// every failed attempt, refusals included.
func (r *renewer) retryFirstIssuance(requestErr error) {
	retry := r.initialRetry.NextBackOff()
	if r.refusals > 0 {
		retry = refusedRetryInterval(r.cfg, r.refusals)
	}
	slog.Error("certificate request failed, still nothing published", "error", requestErr, "retry_in", retry)
	r.retryPending = true
	r.scheduleRenewal(retry)
}

// retryRenewal keeps the published generation only while it still validates,
// then retries on a short backoff, not a full interval: the timer fires around
// half the generation's remaining lifetime, so it is already close to expiry.
func (r *renewer) retryRenewal(requestErr error) error {
	// Withdraw first: the retry is paced off what remains published.
	if err := r.creds.withdrawUnusable(time.Now()); err != nil {
		return err
	}
	r.renewalFailures++
	retry := renewalRetryInterval(r.cfg, r.creds.current, r.renewalFailures, r.refusals)
	slog.Error("certificate renewal failed, retrying", "error", requestErr, "retry_in", retry, "failures", r.renewalFailures, "published", r.hasPublished())
	r.retryPending = true
	r.scheduleRenewal(retry)
	return nil
}

func (r *renewer) scheduleRenewal(in time.Duration) {
	r.renewTimer.Reset(in)
	r.renewDue = time.Now().Add(in)
}

func (r *renewer) hasPublished() bool {
	return r.creds.current != nil
}

const (
	// minRenewalDelay floors every computed delay so an already-expired leaf
	// cannot turn the renewal loop into a hot attestation spin against CDS. It
	// never raises a delay above --renew-interval, which the operator chose.
	minRenewalDelay = 5 * time.Second

	// maxInitialRetryInterval caps the backoff between attempts at the first
	// certificate.
	maxInitialRetryInterval = time.Minute

	defaultInitialRetryInterval = 2 * time.Second

	// maxRefusedRetryInterval caps the backoff after refusals (refused).
	maxRefusedRetryInterval = 5 * time.Minute

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

	defaultCDSWatchInterval = time.Minute
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
// the flag alone — which the chart sets below that cap — would reset the
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
	if cfg.UnnamedRenewInterval <= 0 || isNamedLeaf(cfg, g) {
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
// renewalRetryBase so a CDS outage is not hammered, or refusedRetryInterval
// after a refusal, but never slower than the ordinary pacing, which is itself
// bounded by the published generation's remaining lifetime.
func renewalRetryInterval(cfg config, g *generation, failures, refusals int) time.Duration {
	// An unnamed or wrong-name generation still serves; back off like a named
	// one, not at the fast poll, so a failure is not retried every few seconds
	// (#1068).
	cfg.ExpectedWorkload = ""
	cfg.UnnamedRenewInterval = 0
	ceiling := renewalInterval(cfg, g, 0)
	if refusals > 0 {
		return min(refusedRetryInterval(cfg, refusals), ceiling)
	}
	delay := renewalRetryBase
	for i := 1; i < failures && delay < ceiling; i++ {
		delay *= 2
	}
	return min(delay, ceiling)
}

// refused reports whether CDS or the node inventory refused this pod (403, as
// for a sandbox the allowlist does not admit) or CDS rate-limited its source
// (429). Asking again soon gets the same answer, and every attempt spends the
// per-source CDS limit that all pods of the node share, the router's renewal
// included.
func refused(err error) bool {
	var status *attestclient.StatusError
	if errors.As(err, &status) {
		return status.Status == http.StatusForbidden || status.Status == http.StatusTooManyRequests
	}
	return errors.Is(err, workloadclaims.ErrSandboxRefused)
}

// consecutiveRefusals is the consecutive refusal count after a request that
// ended in err.
func consecutiveRefusals(refusals int, err error) int {
	if refused(err) {
		return refusals + 1
	}
	return 0
}

// refusedRetryInterval is the delay after the refusals-th refusal in a row:
// --initial-retry-interval doubled per refusal up to maxRefusedRetryInterval,
// less up to half of it at random so the refused pods of a node spread out.
func refusedRetryInterval(cfg config, refusals int) time.Duration {
	delay := cfg.InitialRetryInterval
	if delay <= 0 {
		delay = defaultInitialRetryInterval
	}
	for i := 1; i < refusals && delay < maxRefusedRetryInterval; i++ {
		delay *= 2
	}
	delay = min(delay, maxRefusedRetryInterval)
	return delay - time.Duration(mrand.Int64N(int64(delay)/2+1))
}

// publishedLeaf is the certificate of the published generation, or nil when
// nothing is published.
func publishedLeaf(g *generation) *x509.Certificate {
	if g == nil {
		return nil
	}
	return g.Leaf
}

// isNamedLeaf reports whether the published leaf carries a valid
// matched-workload stamp naming --expected-workload, or any name when that is
// unset. An absent, unparseable or unstamped leaf is not named. A pod stamped
// while its sandbox is still starting can match a subset entry, so a wrong
// name keeps polling rather than settling on it.
func isNamedLeaf(cfg config, g *generation) bool {
	name := stampedWorkload(publishedLeaf(g))
	return name != "" && (cfg.ExpectedWorkload == "" || name == cfg.ExpectedWorkload)
}

// stampedWorkload returns the leaf's matched-workload name, or "" for a nil,
// unparseable, or unstamped leaf.
func stampedWorkload(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	matched, err := armtls.MatchedWorkloadFromCert(leaf)
	if err != nil || matched == nil {
		return ""
	}
	return matched.Name
}

// warnUnexpectedWorkload logs a leaf stamped with a name other than
// --expected-workload, once per name recorded in warned until a leaf names
// the expected workload.
func warnUnexpectedWorkload(cfg config, leaf *x509.Certificate, warned map[string]bool) {
	name := stampedWorkload(leaf)
	if cfg.NoWorkloadClaims || cfg.ExpectedWorkload == "" || name == "" {
		return
	}
	if name == cfg.ExpectedWorkload {
		// A later regression to a wrong name logs again.
		clear(warned)
		return
	}
	if warned[name] {
		return
	}
	warned[name] = true
	slog.Warn("certificate stamped with an unexpected workload; renewing until it names the expected one", "stamped_workload", name, "expected_workload", cfg.ExpectedWorkload)
}

// servedCAStale detects a renewed CA certificate under the pod's bound issuer
// key, comparing what CDS serves now with the CA the volume publishes.
func servedCAStale(ctx context.Context, client attestclient.Client, bound issuerKeyID, volume credentialVolume) (bool, error) {
	currentPEM, err := client.MeshCA(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch current mesh CA from cds: %w", err)
	}
	current, err := soleCA(currentPEM)
	if err != nil {
		return false, fmt.Errorf("mesh CA from cds: %w", err)
	}
	issuer, err := issuerKeyIDOf(current)
	if err != nil {
		return false, err
	}
	if issuer != bound {
		return false, nil
	}
	servedPEM, err := volume.readPublished(volume.caName)
	if err != nil {
		return false, fmt.Errorf("read served mesh CA: %w", err)
	}
	served, err := soleCA(servedPEM)
	if err != nil {
		return false, fmt.Errorf("published mesh CA: %w", err)
	}
	return !served.Equal(current), nil
}

// stampedPolicyStale reports whether the allowlist CDS serves differs from the
// stamped bytes, and the version it serves them at. It sends the stamped
// digest's tag as If-None-Match, so an allowlist whose bytes are unchanged
// costs a 304 however its version moves. The fetch rides the armTLS-verified
// client, like servedCAStale's.
func stampedPolicyStale(ctx context.Context, client allowlistclient.Client, digest []byte) (servedVersion string, stale bool, err error) {
	stamped := "sha256:" + hex.EncodeToString(digest)
	served, notModified, err := client.FetchServed(ctx, pkgallowlist.EntityTag(stamped))
	if err != nil {
		return "", false, fmt.Errorf("fetch allowlist from cds: %w", err)
	}
	stale = !notModified && served.Digest != stamped
	return served.Version, stale, nil
}

// policyRenewDelayFn is a var so the debounce test can hold a renewal pending.
var policyRenewDelayFn = policyRenewDelay

// policyRenewDelay spreads a fleet's policy-change renewals over half a watch
// interval so one allowlist write does not land every pod on CDS at once. It
// never postpones a renewal already due sooner.
func policyRenewDelay(interval, remaining time.Duration) time.Duration {
	delay := time.Duration(mrand.Int64N(int64(interval/2) + 1))
	return max(0, min(delay, remaining))
}
