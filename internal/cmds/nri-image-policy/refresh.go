package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

type pullArgs struct {
	client      allowlistclient.Client
	target      policyTarget
	measure     func(digest string) error // nil measures nothing
	pull        *allowlistPull
	timeout     time.Duration
	pluginErrCh <-chan error
	logger      *slog.Logger
}

// pullInitial fetches the startup allowlist with bounded retries and
// returns the response ETag for the steady-state poll loop.
//
// INVARIANT: a nil error return means args.target holds the pulled document.
// Context cancellation surfaces as ctx.Err(); callers must not mark the
// plugin ready on that path.
func pullInitial(ctx context.Context, args pullArgs) (string, error) {
	delay := allowlistApiInitialDelay
	var lastErr error
	for attempt := 1; attempt <= allowlistApiMaxRetries; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				args.logger.Info("shutdown requested during allowlist init")
				return "", ctx.Err()
			}
			delay *= 2
		}
		if err := initialPullInterrupted(ctx, args); err != nil {
			return "", err
		}
		etag, err := pullInitialOnce(ctx, args, attempt)
		if err == nil {
			return etag, nil
		}
		args.pull.failed(err)
		args.logger.Error("allowlist fetch failed", "attempt", attempt, "error", err)
		if errors.Is(err, errPolicyRefused) {
			return "", err // retrying cannot succeed
		}
		lastErr = err
	}
	return "", fmt.Errorf("allowlist fetch failed after %d attempts: %w", allowlistApiMaxRetries, lastErr)
}

// initialPullInterrupted reports, without waiting, a plugin that died or a
// shutdown that began before the next attempt.
func initialPullInterrupted(ctx context.Context, args pullArgs) error {
	select {
	case err := <-args.pluginErrCh:
		return fmt.Errorf("%w: %w", errPluginDied, err)
	case <-ctx.Done():
		args.logger.Info("shutdown requested during allowlist init")
		return ctx.Err()
	default:
		return nil
	}
}

func pullInitialOnce(
	ctx context.Context,
	args pullArgs,
	attempt int,
) (string, error) {
	args.logger.Info("fetching initial allowlist from CDS", "attempt", attempt)
	served, notModified, err := fetchServed(ctx, args.client, args.timeout, "")
	switch {
	case err != nil:
		return "", err
	case notModified:
		return "", errInitialAllowlistNotModified
	case served.Allowlist == nil:
		return "", errInitialAllowlistNil
	}
	if err := measureWith(args.measure, served.Digest); err != nil {
		return "", err
	}
	version := parseVersion(served.Version)
	if err := args.target.install(ctx, served.Allowlist, version); err != nil {
		return "", err
	}
	args.pull.reached()
	args.logger.Info("initial allowlist pulled from CDS",
		"workloads", len(served.Allowlist.Workloads),
		"version", version,
		"etag", served.ETag,
		"digest", served.Digest,
	)
	return served.ETag, nil
}

type pullLoopArgs struct {
	client   allowlistclient.Client
	target   policyTarget
	measure  func(digest string) error // nil measures nothing
	pull     *allowlistPull
	interval time.Duration
	timeout  time.Duration
	etag     string
	logger   *slog.Logger
}

// runPullLoop polls CDS with If-None-Match. 200 rebuilds the index from the
// pulled document, advances the ETag and kills the running containers it no
// longer admits — unless the pulled version is below the applied
// one (epoch rollback), which is ignored so the ETag keeps re-fetching until a
// forward version arrives. 304 raises the applied version to the one CDS
// serves the document at; it and errors leave the index untouched. A
// version the measurer refuses for good also advances the ETag and is logged
// once per digest.
func runPullLoop(ctx context.Context, args pullLoopArgs) {
	ticker := time.NewTicker(args.interval)
	defer ticker.Stop()
	loop := &pullLoop{
		client:  args.client,
		target:  args.target,
		measure: args.measure,
		pull:    args.pull,
		timeout: args.timeout,
		logger:  args.logger,
		etag:    args.etag,
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			loop.poll(ctx)
		}
	}
}

// pullLoop is the pull loop's state between polls.
type pullLoop struct {
	client  allowlistclient.Client
	target  policyTarget
	measure func(digest string) error
	pull    *allowlistPull
	timeout time.Duration
	logger  *slog.Logger

	// etag names the document CDS answers 304 for.
	etag string
	// refusedDigest and unmeasuredDigest are the documents last logged at
	// Error as refused for good and as not yet measured.
	refusedDigest    string
	unmeasuredDigest string
}

func (l *pullLoop) poll(ctx context.Context) {
	served, notModified, err := fetchServed(ctx, l.client, l.timeout, l.etag)
	switch {
	case err != nil:
		l.pull.failed(err)
		l.logger.Warn("pull loop fetch failed", "error", err)
	case notModified:
		l.keepUnchanged(served)
	case served.Allowlist == nil:
		l.logger.Warn("pull loop fetch returned nil allowlist")
	case l.rolledBack(served):
		l.ignoreRollback(served)
	case l.settle(ctx, served):
		l.etag, l.unmeasuredDigest = served.ETag, ""
	}
}

func (l *pullLoop) keepUnchanged(served allowlistclient.Served) {
	l.target.policy().raiseAppliedVersion(parseVersion(served.Version))
	l.pull.reached()
	l.logger.Debug("pull loop: not modified", "etag", l.etag, "version", served.Version)
}

func (l *pullLoop) rolledBack(served allowlistclient.Served) bool {
	return l.target.policy().rolledBack(parseVersion(served.Version))
}

// ignoreRollback keeps the ETag, so later polls fetch until a forward version
// arrives. A rolled-back document is never enforced, so it is not measured.
func (l *pullLoop) ignoreRollback(served allowlistclient.Served) {
	l.logger.Warn("pull loop: ignoring rolled-back allowlist; keeping current index",
		"pulled_version", parseVersion(served.Version), "etag", served.ETag)
}

// settle measures and installs a pulled document, and reports whether polling
// can move past it: it is installed, or refused for good.
func (l *pullLoop) settle(
	ctx context.Context,
	served allowlistclient.Served,
) bool {
	err := measureWith(l.measure, served.Digest)
	switch {
	case err == nil:
		return l.replace(ctx, served)
	case errors.Is(err, errPolicyRefused):
		l.skipRefused(served, err)
		return true
	default:
		l.retryUnmeasured(ctx, served, err)
		return false
	}
}

func (l *pullLoop) replace(
	ctx context.Context,
	served allowlistclient.Served,
) bool {
	version := parseVersion(served.Version)
	if err := l.target.replace(ctx, served.Allowlist, version); err != nil {
		l.pull.failed(err)
		l.logger.Warn("pull loop: retained Pod policy refused update", "error", err)
		return false
	}
	l.pull.reached()
	l.logger.Info("pull loop: allowlist refreshed",
		"workloads", len(served.Allowlist.Workloads),
		"version", version,
		"etag", served.ETag,
		"digest", served.Digest,
	)
	return true
}

// skipRefused logs a refused document once; polling moves past it so later
// polls get 304 instead of downloading it again.
func (l *pullLoop) skipRefused(served allowlistclient.Served, err error) {
	l.pull.failed(err)
	if served.Digest == l.refusedDigest {
		return
	}
	l.refusedDigest = served.Digest
	l.logger.Error("pull loop: allowlist refused; keeping current policy",
		"digest", served.Digest, "etag", served.ETag, "error", err)
}

// retryUnmeasured keeps the ETag, so the next poll measures the document
// again.
func (l *pullLoop) retryUnmeasured(
	ctx context.Context,
	served allowlistclient.Served,
	err error,
) {
	level := slog.LevelError
	if served.Digest == l.unmeasuredDigest {
		level = slog.LevelDebug
	}
	l.unmeasuredDigest = served.Digest
	l.pull.failed(err)
	l.logger.Log(ctx, level, "pull loop: not applying an allowlist this node could not measure",
		"digest", served.Digest, "error", err)
}

// fetchServed asks CDS for its allowlist under a timeout of its own.
func fetchServed(
	ctx context.Context,
	client allowlistclient.Client,
	timeout time.Duration,
	etag string,
) (served allowlistclient.Served, notModified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return client.FetchServed(ctx, etag)
}

// parseVersion reads the CDS mutation counter a pull was served at, used for
// epoch anti-rollback. An unparseable version yields 0, which can only be
// rejected as a rollback once a real version has been applied.
func parseVersion(version string) uint64 {
	n, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
